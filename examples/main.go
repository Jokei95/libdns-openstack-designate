package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/libdns/libdns"
	designate "github.com/libdns/openstack-designate"
)

func main() {
	zone := os.Getenv("ZONE")
	if zone == "" {
		log.Fatal("ZONE not set")
	}

	provider := designate.Provider{
		AuthOpenStack: designate.AuthOpenStack{
			RegionName:         "foo",
			TenantID:           "123123123",
			IdentityApiVersion: "2",
			Password:           "foo-bar-password",
			AuthURL:            "https://keystone.example.com/v2.0",
			Username:           "foo-username",
			TenantName:         "foo-tenant-name",
			EndpointType:       "publicURL",
		},
	}

	ctx := context.Background()

	// GET records
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Records:", records)

	// Record names are relative to the zone in libdns v1.
	testName := "foo-libdns"
	ttl := 600 * time.Second

	// CREATE records
	add, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{
			Name: testName,
			Text: fmt.Sprintf(
				"Replacement test entry created by libdns %s",
				time.Now(),
			),
			TTL: ttl,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ADDED:", add)

	// UPDATE records
	edit, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.TXT{
			Name: testName,
			Text: fmt.Sprintf(
				"SET1 test entry created by libdns %s",
				time.Now(),
			),
			TTL: ttl,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("UPDATED:", edit)

	// DELETE records
	// Delete the actual records returned by SetRecords.
	del, err := provider.DeleteRecords(ctx, zone, edit)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("DELETED:", del)
}
