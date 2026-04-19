# caddy-wkd

[OpenPGP Web Key Directory][1] plugin for Caddy

## Usage

`wkd` is a Caddy v2 HTTP handler.

### Caddyfile

Inline form (auto-detects whether `path` is a file or directory):

```caddyfile
wkd * /etc/wkd/keyring.gpg
wkd * /etc/wkd/keys/
```

> [!IMPORTANT]
> The `*` is required as caddy treats the first argument as a path matcher if it starts with `/`.

Block form:

```caddyfile
wkd {
    path /etc/wkd/keys/
    extensions .gpg .asc .pub .key
}
```

If `path` is a file, it is loaded as a keyring (binary first, then armored).
If `path` is a directory, all files matching `extensions` are loaded. Only
files in the top-level of the directory are read — subdirectories are not
scanned recursively.
If `extensions` is omitted, defaults are: `.gpg`, `.asc`, `.pub`, `.key`.

## WKD Methods

The plugin supports both WKD discovery methods defined in [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230):

- **Direct method**: `https://example.com/.well-known/openpgpkey/hu/<hash>`
- **Advanced method**: `https://openpgpkey.example.com/.well-known/openpgpkey/example.com/hu/<hash>`

Both methods are handled automatically — no additional configuration needed.

### Domain Filtering

By default, keys are filtered by the request `Host` header at request time.
Only keys with matching email domains are served.

Modes:

- **Default**: filter by domain of the request
- **`domain`**: override host-based filtering with a fixed domain
- **`dangerous_allow_any_host`**: disable domain filtering and serve all matches

If both `domain` and `dangerous_allow_any_host` are set, `dangerous_allow_any_host`
takes precedence and `domain` is ignored.

Examples:

```caddyfile
# Default: filters by Host header automatically
example.com {
    wkd * /etc/wkd/keys/
}

# Override domain
wkd {
    path /etc/wkd/keys/
    domain example.com
}

# No domain filtering (dangerous)
wkd {
    path /etc/wkd/keys/
    dangerous_allow_any_host
}
```

### JSON

```json
{
  "handler": "wkd",
  "path": "/etc/wkd/keys/",
  "extensions": [".gpg", ".asc"],
  "domain": "example.com",
  "dangerous_allow_any_host": true
}
```

## License

MIT

[1]: https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-06
