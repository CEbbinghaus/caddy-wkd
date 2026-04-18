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

The `*` is required for inline paths that start with `/`. In Caddyfile parsing,
`/`-prefixed tokens are interpreted as request path matchers unless you provide
an explicit matcher first. `*` is the "match all" matcher (same idiom as
`root * /var/www/html`).

Complete site block example:

```caddyfile
example.com {
    wkd * /etc/wkd/keys/
}
```

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

### JSON

```json
{
  "handler": "wkd",
  "path": "/etc/wkd/keys/",
  "extensions": [".gpg", ".asc"]
}
```

## License

MIT

[1]: https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-06
