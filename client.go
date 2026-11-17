package designate

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/zones"
	"github.com/libdns/libdns"
)

// authenticate is called with p.mu held.
func (p *Provider) authenticate() error {
	if p.dnsClient != nil {
		return nil
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: p.AuthOpenStack.AuthURL,
		ApplicationCredentialID:         p.AuthOpenStack.ApplicationCredentialID,
		ApplicationCredentialSecret:         p.AuthOpenStack.ApplicationCredentialSecret,
		TenantID:         p.AuthOpenStack.TenantID,
		TenantName:       p.AuthOpenStack.TenantName,
		AllowReauth:      true,
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return fmt.Errorf("authenticate to OpenStack: %w", err)
	}
	client, err := openstack.NewDNSV2(provider, gophercloud.EndpointOpts{
		Region: p.AuthOpenStack.RegionName,
	})
	if err != nil {
		return fmt.Errorf("create OpenStack Designate client: %w", err)
	}
	p.dnsClient = client
	return nil
}

// findZoneID does not mutate shared provider state.
func (p *Provider) findZoneID(zone string) (string, error) {
	pages, err := zones.List(p.dnsClient, zones.ListOpts{}).AllPages()
	if err != nil {
		return "", fmt.Errorf("list Designate zones: %w", err)
	}
	all, err := zones.ExtractZones(pages)
	if err != nil {
		return "", fmt.Errorf("extract Designate zones: %w", err)
	}
	for _, z := range all {
		if strings.EqualFold(z.Name, zone) {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("Designate zone %q not found", zone)
}

func (p *Provider) listRecordSets(zoneID string) ([]recordsets.RecordSet, error) {
	pages, err := recordsets.ListByZone(p.dnsClient, zoneID, recordsets.ListOpts{}).AllPages()
	if err != nil {
		return nil, fmt.Errorf("list Designate recordsets: %w", err)
	}
	sets, err := recordsets.ExtractRecordSets(pages)
	if err != nil {
		return nil, fmt.Errorf("extract Designate recordsets: %w", err)
	}
	return sets, nil
}

func recordsetKey(name, kind string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "\x00" + strings.ToUpper(kind)
}

func recordFromDesignate(rs recordsets.RecordSet, value, zone string) (libdns.Record, error) {
	rr := libdns.RR{
		Name: libdns.RelativeName(rs.Name, zone),
		Type: rs.Type,
		TTL:  time.Duration(rs.TTL) * time.Second,
		Data: fromDesignateData(rs.Type, value),
	}
	return rr.Parse()
}

func fromDesignateData(kind, data string) string {
	if strings.ToUpper(kind) != "TXT" || len(data) < 2 || data[0] != '"' {
		return data
	}
	// Designate uses zone-file quoted strings for TXT records. Join multiple
	// quoted chunks into one logical TXT value (RFC 1035 character strings).
	var out strings.Builder
	rest := strings.TrimSpace(data)
	for rest != "" {
		if !strings.HasPrefix(rest, "\"") {
			return data // Unexpected representation: preserve without corruption.
		}
		escaped := false
		end := -1
		for i := 1; i < len(rest); i++ {
			switch {
			case escaped:
				escaped = false
			case rest[i] == '\\':
				escaped = true
			case rest[i] == '"':
				end = i
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return data
		}
		part, err := strconv.Unquote(rest[:end+1])
		if err != nil {
			return data
		}
		out.WriteString(part)
		rest = strings.TrimSpace(rest[end+1:])
	}
	return out.String()
}

func toDesignateData(kind, data string) string {
	if strings.ToUpper(kind) == "TXT" {
		return strconv.Quote(data)
	}
	return data
}

func createRecordset(client *gophercloud.ServiceClient, zoneID, name, kind string, ttl time.Duration, values []string) (recordsets.RecordSet, error) {
	opts := recordsets.CreateOpts{
		Name: name, Type: kind, Records: values,
	}
	if ttl > 0 {
		opts.TTL = int(ttl / time.Second)
	}
	created, err := recordsets.Create(client, zoneID, opts).Extract()
	if err != nil {
		return recordsets.RecordSet{}, fmt.Errorf("create %s %s recordset: %w", kind, name, err)
	}
	return *created, nil
}

func updateRecordset(client *gophercloud.ServiceClient, zoneID string, rs recordsets.RecordSet, ttl time.Duration, values []string) (recordsets.RecordSet, error) {
	opts := recordsets.UpdateOpts{Records: values}
	if ttl > 0 {
		seconds := int(ttl / time.Second)
		opts.TTL = &seconds
	}
	updated, err := recordsets.Update(client, zoneID, rs.ID, opts).Extract()
	if err != nil {
		return recordsets.RecordSet{}, fmt.Errorf("update %s %s recordset: %w", rs.Type, rs.Name, err)
	}
	return *updated, nil
}
