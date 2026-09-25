package geoip

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang/v2"
)

const maxDatabaseSize = 128 << 20

// Download fetches this month's DB-IP Lite files, validates them, and replaces
// each installed file atomically. An existing database survives a failed fetch.
func Download(ctx context.Context, dir string) error {
	return download(ctx, dir, "https://download.db-ip.com/free", time.Now().UTC(), &http.Client{Timeout: 2 * time.Minute})
}

func download(ctx context.Context, dir, baseURL string, month time.Time, client *http.Client) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create GeoIP directory: %w", err)
	}
	for _, item := range []struct{ slug, file string }{{"country", CountryFile}, {"asn", ASNFile}} {
		url := fmt.Sprintf("%s/dbip-%s-lite-%s.mmdb.gz", baseURL, item.slug, month.Format("2006-01"))
		if err := downloadFile(ctx, client, url, filepath.Join(dir, item.file)); err != nil {
			return fmt.Errorf("download %s: %w", item.file, err)
		}
	}
	return nil
}

func downloadFile(ctx context.Context, client *http.Client, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dbip-*.mmdb")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()
	n, err := io.Copy(tmp, io.LimitReader(gz, maxDatabaseSize+1))
	if err != nil {
		return err
	}
	if n > maxDatabaseSize {
		return fmt.Errorf("database exceeds %d MiB", maxDatabaseSize>>20)
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	r, err := geoip2.Open(tmp.Name())
	if err != nil {
		if r != nil {
			_ = r.Close()
		}
		return fmt.Errorf("invalid MMDB: %w", err)
	}
	if err := validate(r, filepath.Base(path)); err != nil {
		_ = r.Close()
		return fmt.Errorf("unexpected MMDB type: %w", err)
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return nil
}
