package designate

import (
	"errors"
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/recordsets"
	"github.com/gophercloud/gophercloud/openstack/dns/v2/zones"
	"github.com/libdns/libdns"
	"time"
)

func (p *Provider) getRecords(
    recordSets []recordsets.RecordSet,
    zone string,
) ([]libdns.Record, error) {
    var records []libdns.Record

    for _, rs := range recordSets {
        for _, value := range rs.Records {
            // Designate may return quoted TXT data.
            // This handles a single quoted string.
            // Multi-string TXT values need separate handling.
            if rs.Type == "TXT" {
                if text, err := strconv.Unquote(value); err == nil {
                    value = text
                }
            }

            rr := libdns.RR{
                Name: libdns.RelativeName(rs.Name, zone),
                Type: rs.Type,
                TTL:  time.Duration(rs.TTL) * time.Second,
                Data: value,
            }

            parsed, err := rr.Parse()
            if err != nil {
                return nil, fmt.Errorf(
                    "parsing record %s: %w",
                    rs.Name, err,
                )
            }

            records = append(records, parsed)
        }
    }

    return records, nil
}

func (p *Provider) getRecordID(recordName string, zone string) (string, error) {
	recordName = recordName + "."

	listOpts := recordsets.ListOpts{
		Type: "TXT",
	}

	allPages, err := recordsets.ListByZone(p.dnsClient, p.zoneID, listOpts).AllPages()
	if err != nil {
		return "", err
	}

	allRecordSets, err := recordsets.ExtractRecordSets(allPages)
	if err != nil {
		return "", err
	}

	for _, rr := range allRecordSets {
		if recordName == rr.Name {
			return rr.ID, nil
		}
	}

	return "", nil
}

func (p *Provider) createRecord(record libdns.Record, zone string) error {
	rr := record.RR()

	createOpts := recordsets.CreateOpts{
		Name:    libdns.AbsoluteName(rr.Name, zone),
		Type:    rr.Type,
		TTL:     int(rr.TTL / time.Second),
		Records: []string{rr.Data},
	}

	exist, err := p.getRecordID(record.Name, zone)
	if err != nil {
		return fmt.Errorf("cannot get recordID: %v", err)
	}

	if exist != "" {
		return errors.New("DNS record already exist")
	}

	_, err = recordsets.Create(p.dnsClient, p.zoneID, createOpts).Extract()
	if err != nil {
		return fmt.Errorf("cannot create DNS record: %v", err)
	}

	return nil
}

func (p *Provider) updateRecord(record libdns.Record, recordID string) error {
	rr := record.RR()

	updateOpts := recordsets.UpdateOpts{
		TTL:     intToPointer(int(rr.TTL / time.Second)),
		Records: []string{rr.Data},
	}

	// Update updates a recordset in a given zone
	_, err := recordsets.Update(p.dnsClient, p.zoneID, recordID, updateOpts).Extract()
	if err != nil {
		return err
	}
	return nil
}

func (p *Provider) deleteRecord(recordID string) error {
	err := recordsets.Delete(p.dnsClient, p.zoneID, recordID).ExtractErr()
	if err != nil {
		return err
	}

	return nil
}

func (p *Provider) isAuth() (bool, error) {
	if p.dnsClient != nil {
		_, err := p.dnsClient.GetAuthResult().ExtractTokenID()
		if err != nil {
			return true, err
		}
	}

	return false, nil
}

func (p *Provider) auth() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	authStatus, err := p.isAuth()
	if err != nil {
		return err
	}

	if authStatus {
		return nil
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: p.AuthOpenStack.AuthURL,
		Username:         p.AuthOpenStack.Username,
		Password:         p.AuthOpenStack.Password,
		TenantID:         p.AuthOpenStack.TenantID,
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return err
	}

	dnsClient, err := openstack.NewDNSV2(provider, gophercloud.EndpointOpts{
		Region: p.AuthOpenStack.RegionName,
	})
	if err != nil {
		return err
	}
	p.dnsClient = dnsClient

	return nil
}

func (p *Provider) setZone(zone string) error {
	dot := zone[len(zone)-1:]
	if dot != "." {
		zone = zone + "."
	}

	zoneID, err := p.setZoneID(zone)
	if err != nil {
		return err
	}
	p.zoneID = zoneID

	if p.zoneID == "" {
		return errors.New("zoneID does not exist")
	}
	return nil
}

func (p *Provider) setZoneID(zoneName string) (string, error) {
	listOpts := zones.ListOpts{}

	allPages, err := zones.List(p.dnsClient, listOpts).AllPages()
	if err != nil {
		return "", fmt.Errorf("trying to get zones list: %v", err)
	}

	allZones, err := zones.ExtractZones(allPages)
	if err != nil {
		return "", fmt.Errorf("trying to extract zones: %v", err)
	}

	for _, zone := range allZones {
		if zoneName == zone.Name {
			return zone.ID, nil
		}
	}

	return "", nil
}

func intToPointer(x int) *int {
	return &x
}
