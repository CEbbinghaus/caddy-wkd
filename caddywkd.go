package caddywkd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	wkd "github.com/emersion/go-openpgp-wkd"
	"go.uber.org/zap"
)

// zbase32Alphabet is the alphabet used by z-base-32 encoding (RFC 6189 / Zooko's base32).
const zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// isValidWKDHash returns true if s looks like a valid WKD hash:
// exactly 32 characters from the z-base-32 alphabet.
func isValidWKDHash(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune(zbase32Alphabet, c) {
			return false
		}
	}
	return true
}

func init() {
	caddy.RegisterModule(WKD{})
	httpcaddyfile.RegisterHandlerDirective("wkd", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("wkd", httpcaddyfile.Before, "file_server")
}

type WKD struct {
	Path       string         `json:"path"`
	Extensions []string       `json:"extensions,omitempty"`
	Rescan     caddy.Duration `json:"rescan,omitempty"`

	// Override domain for key filtering. If set, keys are filtered
	// against this domain instead of the request Host header.
	Domain string `json:"domain,omitempty"`

	// Skip domain filtering entirely. Serves all keys regardless
	// of domain. Use with caution.
	DangerousAllowAnyHost bool `json:"dangerous_allow_any_host,omitempty"`

	// public key dictionary split [domain][username_hash] with domain="" containing all keys for a given username
	pubkeys map[string]map[string]openpgp.EntityList
	logger  *zap.Logger
	mu      sync.RWMutex
	cancel  context.CancelFunc
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

	if len(w.Extensions) == 0 {
		w.Extensions = defaultExtensions
	}

	pubkeys, err := w.loadKeys()
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.pubkeys = pubkeys
	w.mu.Unlock()

	if w.Rescan > 0 {
		rctx, cancel := context.WithCancel(ctx)
		w.cancel = cancel
		go w.rescanLoop(rctx, time.Duration(w.Rescan))
	}

	w.mu.RLock()
	identities := len(w.pubkeys[""])
	w.mu.RUnlock()

	w.logger.Info("loaded WKD keys",
		zap.Int("identities", identities),
		zap.String("path", w.Path),
	)

	return nil
}

func (w *WKD) loadKeys() (map[string]map[string]openpgp.EntityList, error) {
	pubkeys := map[string]map[string]openpgp.EntityList{
		"": make(map[string]openpgp.EntityList),
	}

	info, err := os.Stat(w.Path)
	if err != nil {
		return nil, fmt.Errorf("cannot access path %s: %w", w.Path, err)
	}

	if info.IsDir() {
		if err := w.loadDirInto(w.Path, pubkeys); err != nil {
			return nil, err
		}
	} else if err := w.loadFileInto(w.Path, pubkeys); err != nil {
		return nil, err
	}

	return pubkeys, nil
}

func (w *WKD) loadFile(path string) error {
	return w.loadFileInto(path, w.pubkeys)
}

func (w *WKD) loadFileInto(path string, pubkeys map[string]map[string]openpgp.EntityList) error {
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
			return fmt.Errorf("%s: not a valid binary or armored keyring: %w", path, err)
		}
	}

	w.indexEntitiesInto(el, pubkeys)
	return nil
}

func (w *WKD) loadDir(dir string) error {
	return w.loadDirInto(dir, w.pubkeys)
}

func (w *WKD) loadDirInto(dir string, pubkeys map[string]map[string]openpgp.EntityList) error {
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
		if err := w.loadFileInto(path, pubkeys); err != nil {
			return err
		}
		w.logger.Debug("loaded key file", zap.String("file", entry.Name()))
	}
	return nil
}

func emailDomain(email string) (string, bool) {
	if email == "" || strings.Count(email, "@") != 1 {
		return "", false
	}
	parts := strings.SplitN(email, "@", 2)
	if parts[1] == "" {
		return "", false
	}
	return strings.ToLower(parts[1]), true
}

func (w *WKD) indexEntities(el openpgp.EntityList) {
	w.indexEntitiesInto(el, w.pubkeys)
}

func (w *WKD) indexEntitiesInto(el openpgp.EntityList, pubkeys map[string]map[string]openpgp.EntityList) {
	for _, e := range el {
		for _, ident := range e.Identities {
			if ident == nil || ident.UserId == nil {
				continue
			}

			email := ident.UserId.Email
			hash, err := wkd.HashAddress(email)

			if err != nil {
				w.logger.Warn("failed to hash address",
					zap.String("email", email),
					zap.Error(err),
				)
				continue
			}

			pubkeys[""][hash] = append(pubkeys[""][hash], e)

			domain, ok := emailDomain(email)
			if !ok {
				w.logger.Warn("failed to extract domain from email",
					zap.String("email", email),
				)
				continue
			}

			if _, ok := pubkeys[domain]; !ok {
				pubkeys[domain] = make(map[string]openpgp.EntityList)
			}

			pubkeys[domain][hash] = append(pubkeys[domain][hash], e)
		}
	}
}

func (w *WKD) Validate() error {
	if w.Path == "" {
		return fmt.Errorf("path is required")
	}
	if w.Rescan > 0 && time.Duration(w.Rescan) < time.Second {
		return fmt.Errorf("rescan interval must be at least 1s")
	}
	return nil
}

func (w *WKD) Discover(hash, domain string) ([]*openpgp.Entity, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	domainKeys, ok := w.pubkeys[strings.ToLower(domain)]
	if !ok {
		return nil, wkd.ErrNotFound
	}

	matched := domainKeys[hash]
	if len(matched) == 0 {
		return nil, wkd.ErrNotFound
	}

	return matched, nil
}

func (w *WKD) domainFilter(r *http.Request) string {
	if w.DangerousAllowAnyHost {
		return ""
	}
	if w.Domain != "" {
		return w.Domain
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func (w *WKD) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		rw.Header().Set("Allow", "GET, HEAD")
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return nil
	}

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
		if !isValidWKDHash(hash) {
			http.NotFound(rw, r)
			return nil
		}

		pubkeys, err := w.Discover(hash, w.domainFilter(r))
		if errors.Is(err, wkd.ErrNotFound) {
			http.NotFound(rw, r)
			return nil
		}

		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return nil
		}

		var buf bytes.Buffer
		for _, e := range pubkeys {
			if err := e.Serialize(&buf); err != nil {
				return err
			}
		}
		rw.Header().Set("Content-Type", "application/octet-stream")
		_, err = rw.Write(buf.Bytes())
		return err
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

			case "rescan":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid rescan duration: %v", err)
				}
				w.Rescan = caddy.Duration(dur)

			case "domain":
				if !d.NextArg() {
					return d.ArgErr()
				}
				w.Domain = d.Val()

			case "dangerous_allow_any_host":
				w.DangerousAllowAnyHost = true

			default:
				return d.Errf("unknown directive: %s", d.Val())
			}
		}
	}
	return nil
}

func (w *WKD) rescanLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fresh, err := w.loadKeys()
			if err != nil {
				w.logger.Error("rescan failed", zap.Error(err))
				continue
			}

			w.mu.Lock()
			w.pubkeys = fresh
			identities := len(w.pubkeys[""])
			w.mu.Unlock()

			w.logger.Info("rescanned WKD keys",
				zap.Int("identities", identities),
				zap.String("path", w.Path),
			)
		}
	}
}

func (w *WKD) Cleanup() error {
	if w.cancel != nil {
		w.cancel()
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
	_ caddy.CleanerUpper          = (*WKD)(nil)
	_ caddyhttp.MiddlewareHandler = (*WKD)(nil)
	_ caddyfile.Unmarshaler       = (*WKD)(nil)
)
