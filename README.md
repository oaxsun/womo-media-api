# WOMO Media API v2 - Cloudflare media bridge trial

This version keeps the existing `/register` and `/playback` routes and adds `/media` so Womo can stream `.wmo` byte ranges from Archive.org without GoDaddy/cPanel.

## Existing Cloudflare configuration

Required bindings/secrets:

- D1 binding: `DB` -> `womo-media`
- Secret: `REGISTER_TOKEN`
- Secret: `FIREBASE_API_KEY`

Optional but recommended later:

- Secret: `MEDIA_TOKEN_SECRET` - a long random secret dedicated to short-lived media session tokens. If it is not configured, v2 temporarily falls back to `REGISTER_TOKEN`, so you can run the trial without changing Cloudflare settings.

## Routes

- `POST /register` - Encoder key registration
- `POST /playback` - Firebase-authenticated AES key retrieval; also returns a 2-hour `mediaToken`
- `POST /media` - authenticated byte-range bridge to `archive.org` `.wmo` files
- `GET /health`

`/media` only accepts HTTPS Archive.org hosts and `.wmo` paths. It requires a valid Womo media token or Firebase ID token and only accepts explicit byte ranges.

## Deploy

Replace the files in the existing private `womo-media-api` GitHub repo and push to `main`. Cloudflare should deploy with the current Git integration.

The included `wrangler.jsonc` retains the existing D1 binding.
