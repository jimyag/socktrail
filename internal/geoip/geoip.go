// Package geoip reads optional, locally stored DB-IP Lite country and ASN databases.
package geoip

import (
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	geoip2 "github.com/oschwald/geoip2-golang/v2"
)

const (
	CountryFile = "dbip-country-lite.mmdb"
	ASNFile     = "dbip-asn-lite.mmdb"
	Attribution = "DB-IP Lite (CC BY 4.0, https://db-ip.com)"
)

type Location struct {
	CountryCode  string `json:"country_code,omitempty"`
	Country      string `json:"country,omitempty"`
	ASN          uint   `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
}

type DB struct {
	country, asn *geoip2.Reader
	status       string
}

// DefaultDir keeps sudo captures pointed at the invoking user's databases.
func DefaultDir() (string, error) {
	if os.Geteuid() != 0 {
		if base := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(base) {
			return filepath.Join(base, "socktrail", "geoip"), nil
		}
	}
	var home string
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		u, err := user.Lookup(os.Getenv("SUDO_USER"))
		if err != nil {
			return "", fmt.Errorf("find sudo user home: %w", err)
		}
		home = u.HomeDir
	} else {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(home, ".local", "share", "socktrail", "geoip"), nil
}

// Open accepts either database independently. A bad or missing file only
// removes that part of the enrichment; packet capture remains usable.
func Open(dir string) *DB {
	db := new(DB)
	if dir == "" {
		db.status = "GeoIP directory unavailable; use --geoip-dir to select a database directory"
		return db
	}
	var status []string
	for _, item := range []struct {
		name string
		set  func(*geoip2.Reader)
	}{
		{CountryFile, func(r *geoip2.Reader) { db.country = r }},
		{ASNFile, func(r *geoip2.Reader) { db.asn = r }},
	} {
		r, err := geoip2.Open(filepath.Join(dir, item.name))
		if err == nil {
			err = validate(r, item.name)
		}
		if err != nil && r != nil {
			_ = r.Close()
		}
		if err != nil {
			if os.IsNotExist(err) {
				status = append(status, item.name+" missing")
			} else {
				status = append(status, item.name+": "+err.Error())
			}
			continue
		}
		item.set(r)
		status = append(status, item.name+" ready")
	}
	db.status = "GeoIP " + strings.Join(status, "; ") + "; " + Attribution
	return db
}

func (db *DB) Status() string { return db.status }

func (db *DB) Available() bool { return db != nil && (db.country != nil || db.asn != nil) }

func (db *DB) Close() {
	if db.country != nil {
		_ = db.country.Close()
	}
	if db.asn != nil {
		_ = db.asn.Close()
	}
}

func (db *DB) Lookup(ip netip.Addr) *Location {
	if db == nil || !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Is4In6() && ip.Unmap().IsPrivate() {
		return nil
	}
	ip = ip.Unmap()
	location := new(Location)
	if db.country != nil {
		if country, err := db.country.Country(ip); err == nil && country.HasData() {
			record := country.Country
			if record.ISOCode == "" {
				record = country.RegisteredCountry
			}
			location.CountryCode = record.ISOCode
			location.Country = record.Names.English
		}
	}
	if db.asn != nil {
		if asn, err := db.asn.ASN(ip); err == nil && asn.HasData() {
			location.ASN = asn.AutonomousSystemNumber
			location.Organization = asn.AutonomousSystemOrganization
		}
	}
	if *location == (Location{}) {
		return nil
	}
	return location
}

func validate(r *geoip2.Reader, name string) error {
	ip := netip.MustParseAddr("1.1.1.1")
	var err error
	if name == CountryFile {
		_, err = r.Country(ip)
	} else {
		_, err = r.ASN(ip)
	}
	return err
}
