# Content-addressed skill corpus

Ingestion writes deterministic bundles and manifests at:

```text
corpus/sha256/<first-two-hex>/<sha256>/bundle.tar.zst
corpus/sha256/<first-two-hex>/<sha256>/manifest.json
```

The public skill ID is `sha256:v1:<hex>`. Archive timestamps, ownership, and
compression do not affect the ID; file bytes, relative paths, entry kind,
executable bits, and symlink targets do.
