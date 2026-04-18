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

The `*` is Caddy's "match all" matcher for handler directives in this form.

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

### Domain Filtering

By default, keys are filtered by the request `Host` header at request time.
Only keys with matching email domains are served.

Modes:

- **Default**: filter by request host
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
  "domain": "example.com"
}
```

## License

MIT

[1]: https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-06
