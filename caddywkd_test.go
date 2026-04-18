package caddywkd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/emersion/go-openpgp-wkd"
	"go.uber.org/zap"
)

func TestLoadFileBinaryAndDiscover(t *testing.T) {
	w := newTestWKD()
	entity := mustNewEntity(t, "alice@example.com")
	path := filepath.Join(t.TempDir(), "key.gpg")
	mustWriteBinaryKey(t, path, entity)

	w.Provision(caddy.Context{Context: context.Background()})

	if err := w.loadFile(path); err != nil {
		t.Fatalf("loadFile(binary) failed: %v", err)
	}

	hash, err := wkd.HashAddress("alice@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	found, err := w.Discover(hash, "")
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(found))
	}
}

func TestLoadKeys(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		entity := mustNewEntity(t, "alice@example.com")
		path := filepath.Join(t.TempDir(), "key.gpg")
		mustWriteBinaryKey(t, path, entity)

		w := newTestWKD()
		w.Path = path

		pubkeys, err := w.loadKeys()
		if err != nil {
			t.Fatalf("loadKeys(file) failed: %v", err)
		}

		hash, err := wkd.HashAddress("alice@example.com")
		if err != nil {
			t.Fatalf("HashAddress failed: %v", err)
		}
		if len(pubkeys[""][hash]) != 1 {
			t.Fatalf("expected 1 key for hash, got %d", len(pubkeys[""][hash]))
		}
	})

	t.Run("directory", func(t *testing.T) {
		entity := mustNewEntity(t, "bob@example.com")
		dir := t.TempDir()
		mustWriteArmoredKey(t, filepath.Join(dir, "bob.asc"), entity)

		w := newTestWKD()
		w.Path = dir
		w.Extensions = []string{".asc"}

		pubkeys, err := w.loadKeys()
		if err != nil {
			t.Fatalf("loadKeys(directory) failed: %v", err)
		}

		hash, err := wkd.HashAddress("bob@example.com")
		if err != nil {
			t.Fatalf("HashAddress failed: %v", err)
		}
		if len(pubkeys[""][hash]) != 1 {
			t.Fatalf("expected 1 key for hash, got %d", len(pubkeys[""][hash]))
		}
	})
}

func TestLoadFileArmoredAndDiscover(t *testing.T) {
	w := newTestWKD()
	entity := mustNewEntity(t, "bob@example.com")
	path := filepath.Join(t.TempDir(), "key.asc")
	mustWriteArmoredKey(t, path, entity)

	w.Provision(caddy.Context{Context: context.Background()})

	if err := w.loadFile(path); err != nil {
		t.Fatalf("loadFile(armored) failed: %v", err)
	}

	hash, err := wkd.HashAddress("bob@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	found, err := w.Discover(hash, "")
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(found))
	}
}

func TestLoadDirFiltersByExtensions(t *testing.T) {
	w := newTestWKD()
	w.Extensions = []string{".asc"}
	entity := mustNewEntity(t, "carol@example.com")
	dir := t.TempDir()
	mustWriteArmoredKey(t, filepath.Join(dir, "carol.asc"), entity)
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write ignore file failed: %v", err)
	}

	w.Provision(caddy.Context{Context: context.Background()})

	if err := w.loadDir(dir); err != nil {
		t.Fatalf("loadDir failed: %v", err)
	}

	hash, err := wkd.HashAddress("carol@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	if _, err := w.Discover(hash, ""); err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
}

func TestDiscoverDomainFiltering(t *testing.T) {
	w := newTestWKD()
	entityExampleCom := mustNewEntity(t, "dave@example.com")
	entityExampleOrg := mustNewEntity(t, "dave@example.org")

	w.Provision(caddy.Context{Context: context.Background()})

	w.indexEntities(openpgp.EntityList{entityExampleCom, entityExampleOrg})

	hash, err := wkd.HashAddress("dave@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}

	t.Run("empty_domain_returns_all_matches", func(t *testing.T) {
		found, err := w.Discover(hash, "")
		if err != nil {
			t.Fatalf("Discover expected hit, got error: %v", err)
		}
		if len(found) != 2 {
			t.Fatalf("expected 2 entities, got %d", len(found))
		}
	})

	t.Run("matching_domain_returns_matches", func(t *testing.T) {
		found, err := w.Discover(hash, "example.com")
		if err != nil {
			t.Fatalf("Discover expected hit, got error: %v", err)
		}
		if len(found) != 1 {
			t.Fatalf("expected 1 entity, got %d", len(found))
		}
	})

	t.Run("non_matching_domain_returns_not_found", func(t *testing.T) {
		if _, err := w.Discover(hash, "nope.example"); !errors.Is(err, wkd.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("missing_hash_returns_not_found", func(t *testing.T) {
		if _, err := w.Discover("missing", "example.com"); !errors.Is(err, wkd.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})
}

func TestIndexEntitiesAndDiscoverMiss(t *testing.T) {
	w := newTestWKD()
	entity := mustNewEntity(t, "dave@example.com")

	w.Provision(caddy.Context{Context: context.Background()})

	w.indexEntities(openpgp.EntityList{entity})

	hash, err := wkd.HashAddress("dave@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	if _, err := w.Discover(hash, ""); err != nil {
		t.Fatalf("Discover expected hit, got error: %v", err)
	}

	if _, err := w.Discover("missing", ""); !errors.Is(err, wkd.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	var w WKD
	if err := w.Validate(); err == nil {
		t.Fatal("expected validation error for empty path")
	}

	w.Path = "/tmp/keys"
	if err := w.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	w.Domain = "example.com"
	w.DangerousAllowAnyHost = true
	if err := w.Validate(); err != nil {
		t.Fatalf("unexpected validation error when both domain and dangerous_allow_any_host are set: %v", err)
	}

	w.DangerousAllowAnyHost = false
	w.Rescan = caddy.Duration(500 * time.Millisecond)
	if err := w.Validate(); err == nil {
		t.Fatal("expected validation error for rescan interval less than 1s")
	}

	w.Rescan = caddy.Duration(time.Second)
	if err := w.Validate(); err != nil {
		t.Fatalf("unexpected validation error for valid rescan interval: %v", err)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	t.Run("inline", func(t *testing.T) {
		var w WKD
		d := caddyfile.NewTestDispenser("wkd /etc/wkd/keyring.gpg")
		if err := w.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("UnmarshalCaddyfile inline failed: %v", err)
		}
		if w.Path != "/etc/wkd/keyring.gpg" {
			t.Fatalf("unexpected path: %q", w.Path)
		}
	})

	t.Run("block", func(t *testing.T) {
		var w WKD
		d := caddyfile.NewTestDispenser(`wkd {
	path /etc/wkd/keys
	extensions .gpg .asc
	rescan 5m
	domain example.com
	dangerous_allow_any_host
}`)
		if err := w.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("UnmarshalCaddyfile block failed: %v", err)
		}
		if w.Path != "/etc/wkd/keys" {
			t.Fatalf("unexpected path: %q", w.Path)
		}
		if len(w.Extensions) != 2 || w.Extensions[0] != ".gpg" || w.Extensions[1] != ".asc" {
			t.Fatalf("unexpected extensions: %#v", w.Extensions)
		}
		if w.Rescan != caddy.Duration(5*time.Minute) {
			t.Fatalf("unexpected rescan: %v", time.Duration(w.Rescan))
		}
		if w.Domain != "example.com" {
			t.Fatalf("unexpected domain: %q", w.Domain)
		}
		if !w.DangerousAllowAnyHost {
			t.Fatal("expected dangerous_allow_any_host to be true")
		}
	})

	t.Run("invalid_rescan", func(t *testing.T) {
		var w WKD
		d := caddyfile.NewTestDispenser(`wkd {
	path /etc/wkd/keys
	rescan not-a-duration
}`)
		if err := w.UnmarshalCaddyfile(d); err == nil {
			t.Fatal("expected unmarshal error for invalid rescan duration")
		}
	})
}

func TestCaddyfileAdapterAcceptsWKDDirective(t *testing.T) {
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	_, _, err := adapter.Adapt([]byte(`:80 {
	wkd /etc/wkd/keys
}`), nil)
	if err != nil {
		t.Fatalf("expected Caddyfile adaptation to succeed with wkd directive, got: %v", err)
	}
}

func TestProvisionAutoDetectsFileOrDirectory(t *testing.T) {
	ctx := caddy.Context{Context: context.Background()}

	entity := mustNewEntity(t, "erin@example.com")

	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "erin.gpg")
		mustWriteBinaryKey(t, path, entity)

		w := WKD{Path: path}
		if err := w.Provision(ctx); err != nil {
			t.Fatalf("Provision(file) failed: %v", err)
		}

		hash, _ := wkd.HashAddress("erin@example.com")
		if _, err := w.Discover(hash, ""); err != nil {
			t.Fatalf("Discover after file provision failed: %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		mustWriteArmoredKey(t, filepath.Join(dir, "erin.asc"), entity)

		w := WKD{Path: dir}
		if err := w.Provision(ctx); err != nil {
			t.Fatalf("Provision(directory) failed: %v", err)
		}

		hash, _ := wkd.HashAddress("erin@example.com")
		if _, err := w.Discover(hash, ""); err != nil {
			t.Fatalf("Discover after directory provision failed: %v", err)
		}
	})
}

func TestServeHTTP(t *testing.T) {
	entity := mustNewEntity(t, "frank@example.com")
	dir := t.TempDir()
	mustWriteBinaryKey(t, filepath.Join(dir, "frank.gpg"), entity)

	w := WKD{Path: dir}
	ctx := caddy.Context{Context: context.Background()}
	if err := w.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	validHash, err := wkd.HashAddress("frank@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}

	// nextHandler records whether it was called.
	var nextCalled bool
	next := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	t.Run("policy", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/policy", nil)
		if err := w.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if body := rec.Body.String(); body == "" {
			t.Fatal("expected non-empty policy body")
		}
	})

	t.Run("hu_hit", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/hu/"+validHash, nil)
		if err := w.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatal("expected non-empty key body")
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Fatalf("expected Content-Type application/octet-stream, got %q", ct)
		}
	})

	t.Run("host_header_mismatch_returns_404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/hu/"+validHash, nil)
		req.Host = "example.org"
		if err := w.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rec.Code)
		}
	})

	t.Run("configured_domain_overrides_request_host", func(t *testing.T) {
		wOverride := cloneWKDForTesting(&w)
		wOverride.Domain = "example.com"

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/hu/"+validHash, nil)
		req.Host = "example.org"
		if err := wOverride.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("dangerous_allow_any_host_bypasses_domain_filtering", func(t *testing.T) {
		wAnyHost := cloneWKDForTesting(&w)
		wAnyHost.DangerousAllowAnyHost = true

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/hu/"+validHash, nil)
		req.Host = "example.org"
		if err := wAnyHost.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("dangerous_allow_any_host_takes_precedence_over_domain", func(t *testing.T) {
		wAnyHost := cloneWKDForTesting(&w)
		wAnyHost.Domain = "invalid.example"
		wAnyHost.DangerousAllowAnyHost = true

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/hu/"+validHash, nil)
		req.Host = "example.org"
		if err := wAnyHost.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("missing_key_returns_not_found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/hu/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", nil)
		if err := w.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rec.Code)
		}
	})

	t.Run("hu_invalid_hash", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openpgpkey/hu/../../etc/passwd", nil)
		if err := w.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for invalid hash, got %d", rec.Code)
		}
	})

	t.Run("passthrough", func(t *testing.T) {
		nextCalled = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/some/other/path", nil)
		if err := w.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if !nextCalled {
			t.Fatal("expected next handler to be called for non-WKD path")
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/openpgpkey/hu/"+validHash, nil)
		if err := w.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
			t.Fatalf("expected Allow: GET, HEAD, got %q", allow)
		}
	})
}

func TestCleanupCancelsRescanContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &WKD{cancel: cancel}

	if err := w.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("expected context cancellation")
	}
}

func newTestWKD() *WKD {
	return &WKD{
		pubkeys: map[string]map[string]openpgp.EntityList{
			"": make(map[string]openpgp.EntityList),
		},
		logger: zap.NewNop(),
	}
}

func mustNewEntity(t *testing.T, email string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("test", "", email, nil)
	if err != nil {
		t.Fatalf("NewEntity failed: %v", err)
	}
	return e
}

func mustWriteBinaryKey(t *testing.T, path string, e *openpgp.Entity) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer f.Close()

	if err := e.Serialize(f); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
}

func mustWriteArmoredKey(t *testing.T, path string, e *openpgp.Entity) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer f.Close()

	w, err := armor.Encode(f, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode failed: %v", err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close armored writer failed: %v", err)
	}
}

func cloneWKDForTesting(w *WKD) WKD {
	return WKD{
		Path:                  w.Path,
		Extensions:            append([]string(nil), w.Extensions...),
		Rescan:                w.Rescan,
		Domain:                w.Domain,
		DangerousAllowAnyHost: w.DangerousAllowAnyHost,
		pubkeys:               clonePubkeysForTesting(w.pubkeys),
		logger:                w.logger,
	}
}

func clonePubkeysForTesting(src map[string]map[string]openpgp.EntityList) map[string]map[string]openpgp.EntityList {
	dst := make(map[string]map[string]openpgp.EntityList, len(src))
	for hash, domainMap := range src {
		copiedDomainMap := make(map[string]openpgp.EntityList, len(domainMap))
		for domain, entities := range domainMap {
			copiedDomainMap[domain] = append(openpgp.EntityList(nil), entities...)
		}
		dst[hash] = copiedDomainMap
	}
	return dst
}
