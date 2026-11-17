package designate

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
	"github.com/libdns/libdns"
)

// Provider implements the libdns 1.x interfaces for OpenStack Designate.
// All operations are serialized on this provider instance to avoid losing
// values during concurrent TXT challenge updates.
type Provider struct {
	AuthOpenStack AuthOpenStack `json:"auth_open_stack"`

	mu        sync.Mutex
	dnsClient *gophercloud.ServiceClient
}

// AuthOpenStack contains credentials for the Designate service.
type AuthOpenStack struct {
	RegionName         string `json:"region_name"`
	TenantID           string `json:"tenant_id"`
	IdentityApiVersion string `json:"identity_api_version"`
	Password           string `json:"password"`
	AuthURL            string `json:"auth_url"`
	Username           string `json:"username"`
	TenantName         string `json:"tenant_name"`
	EndpointType       string `json:"endpoint_type"`
}

// prepare, called with p.mu held, resolves the zone without storing it in
// shared state. A trailing dot is required by the Designate API.
func (p *Provider) prepare(ctx context.Context, zone string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if strings.Trim(zone, ".") == "" {
		return "", "", fmt.Errorf("empty DNS zone")
	}
	zone = strings.TrimSuffix(zone, ".") + "."
	if err := p.authenticate(); err != nil {
		return "", "", err
	}
	zoneID, err := p.findZoneID(zone)
	return zone, zoneID, err
}

// GetRecords lists individual DNS records, not Designate recordsets.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zone, zoneID, err := p.prepare(ctx, zone)
	if err != nil {
		return nil, err
	}
	sets, err := p.listRecordSets(zoneID)
	if err != nil {
		return nil, err
	}

	var result []libdns.Record
	for _, rs := range sets {
		for _, value := range rs.Records {
			rec, err := recordFromDesignate(rs, value, zone)
			if err != nil {
				return result, fmt.Errorf("parse Designate %s %s: %w", rs.Type, rs.Name, err)
			}
			result = append(result, rec)
		}
	}
	return result, nil
}

// inputRR describes a group of libdns records that shares one Designate recordset.
type inputRR struct {
	name, kind string
	ttl        time.Duration
	values     []string
	originals  []libdns.Record
}

func groupInput(records []libdns.Record, zone string) (map[string]*inputRR, []string, error) {
	groups := make(map[string]*inputRR)
	var order []string
	for _, rec := range records {
		if rec == nil {
			return nil, nil, fmt.Errorf("nil libdns record")
		}
		rr := rec.RR()
		if rr.Name == "" || rr.Type == "" {
			return nil, nil, fmt.Errorf("record name and type are required: %+v", rr)
		}
		name := libdns.AbsoluteName(rr.Name, zone)
		kind := strings.ToUpper(rr.Type)
		key := recordsetKey(name, kind)
		group, ok := groups[key]
		if !ok {
			group = &inputRR{name: name, kind: kind, ttl: rr.TTL}
			groups[key] = group
			order = append(order, key)
		}
		if rr.TTL > 0 && group.ttl > 0 && rr.TTL != group.ttl {
			return nil, nil, fmt.Errorf("conflicting TTL values for %s %s", kind, name)
		}
		if group.ttl == 0 && rr.TTL > 0 {
			group.ttl = rr.TTL
		}
		group.values = append(group.values, toDesignateData(kind, rr.Data))
		group.originals = append(group.originals, rec)
	}
	return groups, order, nil
}

func recordsetsByKey(sets []recordsets.RecordSet) map[string]recordsets.RecordSet {
	result := make(map[string]recordsets.RecordSet, len(sets))
	for _, rs := range sets {
		result[recordsetKey(rs.Name, rs.Type)] = rs
	}
	return result
}

// AppendRecords adds new values without removing values in existing recordsets.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zone, zoneID, err := p.prepare(ctx, zone)
	if err != nil {
		return nil, err
	}
	groups, order, err := groupInput(records, zone)
	if err != nil {
		return nil, err
	}
	sets, err := p.listRecordSets(zoneID)
	if err != nil {
		return nil, err
	}
	current := recordsetsByKey(sets)

	var appended []libdns.Record
	for _, key := range order {
		if err := ctx.Err(); err != nil {
			return appended, err
		}
		group := groups[key]
		existing, found := current[key]
		values := make([]string, 0, len(group.values))
		if found {
			values = append(values, existing.Records...)
		}
		var added []string
		for _, value := range group.values {
			if containsData(group.kind, values, value) {
				continue
			}
			values = append(values, value)
			added = append(added, value)
		}
		if len(added) == 0 {
			continue
		}
		var updated recordsets.RecordSet
		if found {
			updated, err = updateRecordset(p.dnsClient, zoneID, existing, 0, values)
		} else {
			updated, err = createRecordset(p.dnsClient, zoneID, group.name, group.kind, group.ttl, values)
		}
		if err != nil {
			return appended, err
		}
		if updated.Name == "" {
			updated.Name = group.name
		}
		if updated.Type == "" {
			updated.Type = group.kind
		}
		if updated.TTL == 0 && found {
			updated.TTL = existing.TTL
		}
		if updated.TTL == 0 {
			updated.TTL = int(group.ttl / time.Second)
		}
		current[key] = updated
		for _, value := range added {
			rec, err := recordFromDesignate(updated, value, zone)
			if err != nil {
				return appended, err
			}
			appended = append(appended, rec)
		}
	}
	return appended, nil
}

func containsData(kind string, values []string, wanted string) bool {
	for _, value := range values {
		if fromDesignateData(kind, value) == fromDesignateData(kind, wanted) {
			return true
		}
	}
	return false
}

// SetRecords replaces the contents of each supplied (name, type) recordset.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zone, zoneID, err := p.prepare(ctx, zone)
	if err != nil {
		return nil, err
	}
	groups, order, err := groupInput(records, zone)
	if err != nil {
		return nil, err
	}
	sets, err := p.listRecordSets(zoneID)
	if err != nil {
		return nil, err
	}
	current := recordsetsByKey(sets)

	var set []libdns.Record
	for _, key := range order {
		if err := ctx.Err(); err != nil {
			return set, err
		}
		group := groups[key]
		values := make([]string, 0, len(group.values))
		for _, value := range group.values {
			if !containsData(group.kind, values, value) {
				values = append(values, value)
			}
		}
		existing, found := current[key]
		var updated recordsets.RecordSet
		if found {
			updated, err = updateRecordset(p.dnsClient, zoneID, existing, group.ttl, values)
		} else {
			updated, err = createRecordset(p.dnsClient, zoneID, group.name, group.kind, group.ttl, values)
		}
		if err != nil {
			return set, err
		}
		if updated.Name == "" {
			updated.Name = group.name
		}
		if updated.Type == "" {
			updated.Type = group.kind
		}
		if updated.TTL == 0 && found {
			updated.TTL = existing.TTL
		}
		if updated.TTL == 0 {
			updated.TTL = int(group.ttl / time.Second)
		}
		current[key] = updated
		for _, value := range values {
			rec, err := recordFromDesignate(updated, value, zone)
			if err != nil {
				return set, err
			}
			set = append(set, rec)
		}
	}
	return set, nil
}

// DeleteRecords removes only matching values, not entire shared TXT recordsets.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zone, zoneID, err := p.prepare(ctx, zone)
	if err != nil {
		return nil, err
	}
	sets, err := p.listRecordSets(zoneID)
	if err != nil {
		return nil, err
	}

	var requested []libdns.RR
	for _, rec := range records {
		if rec == nil {
			return nil, fmt.Errorf("nil libdns record")
		}
		rr := rec.RR()
		if rr.Name == "" {
			return nil, fmt.Errorf("record name is required for deletion")
		}
		rr.Name = libdns.AbsoluteName(rr.Name, zone)
		requested = append(requested, rr)
	}

	var deleted []libdns.Record
	for _, rs := range sets {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		var remaining, toDelete []string
		for _, value := range rs.Records {
			matching := false
			for _, rr := range requested {
				if !strings.EqualFold(rr.Name, rs.Name) {
					continue
				}
				if rr.Type != "" && !strings.EqualFold(rr.Type, rs.Type) {
					continue
				}
				if rr.TTL != 0 && rr.TTL != time.Duration(rs.TTL)*time.Second {
					continue
				}
				if rr.Data != "" && rr.Data != fromDesignateData(rs.Type, value) {
					continue
				}
				matching = true
				break
			}
			if matching {
				toDelete = append(toDelete, value)
			} else {
				remaining = append(remaining, value)
			}
		}
		if len(toDelete) == 0 {
			continue
		}
		if len(remaining) == 0 {
			err = recordsets.Delete(p.dnsClient, zoneID, rs.ID).ExtractErr()
		} else {
			_, err = updateRecordset(p.dnsClient, zoneID, rs, 0, remaining)
		}
		if err != nil {
			return deleted, fmt.Errorf("delete values from %s %s: %w", rs.Type, rs.Name, err)
		}
		for _, value := range toDelete {
			rec, parseErr := recordFromDesignate(rs, value, zone)
			if parseErr != nil {
				return deleted, parseErr
			}
			deleted = append(deleted, rec)
		}
	}
	return deleted, nil
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
