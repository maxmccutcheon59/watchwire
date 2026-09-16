# Test fixtures

Fake secret-shaped strings for Watchwire demos and tests.
**Never real credentials.** Safe to commit; scanner should flag them.

## `fp/` — false-positive classes

Files under `fp/` must stay **clean** (no findings):

| File | Class |
|------|--------|
| `uuids.txt` | RFC 4122 UUIDs / nodash |
| `hashes.txt` | MD5 / SHA-1 / SHA-256 hex digests |
| `base64_padding.txt` | Low-diversity `AAAA…==` noise |
| `demo.lock` / `package-lock.json` | Lockfile paths excluded by default globs |
