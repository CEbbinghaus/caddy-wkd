package caddywkd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/emersion/go-openpgp-wkd"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(WKD{})
	httpcaddyfile.RegisterHandlerDirective("wkd", parseCaddyfile)
}

type WKD struct {
	Path       string   `json:"path"`
	Extensions []string `json:"extensions,omitempty"`

	pubkeys map[string]openpgp.EntityList
	logger  *zap.Logger
}

var defaultExtensions = []string{".gpg", ".asc", ".pub", ".key"}

func (WKD) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.wkd",
		New: func() caddy.Module { return new(WKD) },
	}
}

func (w *WKD) Provision(ctx caddy.Context) error {
	w.logger = ctx.Logger(w)
	w.pubkeys = map[string]openpgp.EntityList{}

	if len(w.Extensions) == 0 {
		w.Extensions = defaultExtensions
	}

	info, err := os.Stat(w.Path)
	if err != nil {
		return fmt.Errorf("cannot access path %s: %v", w.Path, err)
	}

	if info.IsDir() {
		if err := w.loadDir(w.Path); err != nil {
			return err
		}
	} else {
		if err := w.loadFile(w.Path); err != nil {
			return err
		}
	}

	w.logger.Info("loaded WKD keys",
		zap.Int("identities", len(w.pubkeys)),
		zap.String("path", w.Path),
		zap.Bool("is_dir", info.IsDir()),
	)

	return nil
}

func (w *WKD) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	el, err := openpgp.ReadKeyRing(f)
	if err != nil {
		if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
			return seekErr
		}
		el, err = openpgp.ReadArmoredKeyRing(f)
		if err != nil {
			return fmt.Errorf("%s: not a valid binary or armored keyring: %v", path, err)
		}
	}

	w.indexEntities(el)
	return nil
}

func (w *WKD) loadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	extSet := make(map[string]bool, len(w.Extensions))
	for _, ext := range w.Extensions {
		extSet[strings.ToLower(ext)] = true
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !extSet[strings.ToLower(filepath.Ext(entry.Name()))] {
			w.logger.Debug("skipping file", zap.String("file", entry.Name()))
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if err := w.loadFile(path); err != nil {
			return err
		}
		w.logger.Debug("loaded key file", zap.String("file", entry.Name()))
	}
	return nil
}

func (w *WKD) indexEntities(el openpgp.EntityList) {
	for _, e := range el {
		for _, ident := range e.Identities {
			if ident == nil || ident.UserId == nil {
				continue
			}

			hash, err := wkd.HashAddress(ident.UserId.Email)
			if err != nil {
				w.logger.Warn("failed to hash address",
					zap.String("email", ident.UserId.Email),
					zap.Error(err),
				)
				continue
			}
			w.pubkeys[hash] = append(w.pubkeys[hash], e)
		}
	}
}

func (w *WKD) Validate() error {
	if w.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}

func (w *WKD) Discover(hash string) ([]*openpgp.Entity, error) {
	pubkey, ok := w.pubkeys[hash]
	if !ok {
		return nil, wkd.ErrNotFound
	}
	return pubkey, nil
}

func (w *WKD) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !strings.HasPrefix(r.URL.Path, wkd.Base) {
		return next.ServeHTTP(rw, r)
	}

	path := strings.TrimPrefix(r.URL.Path, wkd.Base)
	switch {
	case path == "/policy":
		if _, err := fmt.Fprintf(rw, "protocol-version: %v\n", wkd.Version); err != nil {
			return err
		}
		return nil

	case strings.HasPrefix(path, "/hu/"):
		hash := strings.TrimPrefix(path, "/hu/")
		pubkeys, err := w.Discover(hash)
		if err == wkd.ErrNotFound {
			http.NotFound(rw, r)
			return nil
		}
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return nil
		}

		rw.Header().Set("Content-Type", "application/octet-string")
		for _, e := range pubkeys {
			if err := e.Serialize(rw); err != nil {
				return err
			}
		}
		return nil
	}

	http.NotFound(rw, r)
	return nil
}

func (w *WKD) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			w.Path = d.Val()
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				w.Path = d.Val()

			case "extensions":
				w.Extensions = d.RemainingArgs()
				if len(w.Extensions) == 0 {
					return d.ArgErr()
				}

			default:
				return d.Errf("unknown directive: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var w WKD
	err := w.UnmarshalCaddyfile(h.Dispenser)
	return &w, err
}

var (
	_ caddy.Module                = (*WKD)(nil)
	_ caddy.Provisioner           = (*WKD)(nil)
	_ caddy.Validator             = (*WKD)(nil)
	_ caddyhttp.MiddlewareHandler = (*WKD)(nil)
	_ caddyfile.Unmarshaler       = (*WKD)(nil)
)
