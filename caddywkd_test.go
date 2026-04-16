package caddywkd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/emersion/go-openpgp-wkd"
	"go.uber.org/zap"
)

func TestLoadFileBinaryAndDiscover(t *testing.T) {
	w := newTestWKD()
	entity := mustNewEntity(t, "alice@example.com")
	path := filepath.Join(t.TempDir(), "key.gpg")
	mustWriteBinaryKey(t, path, entity)

	if err := w.loadFile(path); err != nil {
		t.Fatalf("loadFile(binary) failed: %v", err)
	}

	hash, err := wkd.HashAddress("alice@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	found, err := w.Discover(hash)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(found))
	}
}

func TestLoadFileArmoredAndDiscover(t *testing.T) {
	w := newTestWKD()
	entity := mustNewEntity(t, "bob@example.com")
	path := filepath.Join(t.TempDir(), "key.asc")
	mustWriteArmoredKey(t, path, entity)

	if err := w.loadFile(path); err != nil {
		t.Fatalf("loadFile(armored) failed: %v", err)
	}

	hash, err := wkd.HashAddress("bob@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	found, err := w.Discover(hash)
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

	if err := w.loadDir(dir); err != nil {
		t.Fatalf("loadDir failed: %v", err)
	}

	hash, err := wkd.HashAddress("carol@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	if _, err := w.Discover(hash); err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
}

func TestIndexEntitiesAndDiscoverMiss(t *testing.T) {
	w := newTestWKD()
	entity := mustNewEntity(t, "dave@example.com")
	w.indexEntities(openpgp.EntityList{entity})

	hash, err := wkd.HashAddress("dave@example.com")
	if err != nil {
		t.Fatalf("HashAddress failed: %v", err)
	}
	if _, err := w.Discover(hash); err != nil {
		t.Fatalf("Discover expected hit, got error: %v", err)
	}

	if _, err := w.Discover("missing"); err != wkd.ErrNotFound {
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
	})
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
		if _, err := w.Discover(hash); err != nil {
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
		if _, err := w.Discover(hash); err != nil {
			t.Fatalf("Discover after directory provision failed: %v", err)
		}
	})
}

func newTestWKD() *WKD {
	return &WKD{
		pubkeys: map[string]openpgp.EntityList{},
		logger:  zap.NewNop(),
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
