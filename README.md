# WOMO Media API v2.2 - Firebase register auth

`/register` now requires a valid Firebase ID Token from an authorized Encoder admin. The Encoder no longer needs the shared `REGISTER_TOKEN`.

## Required Cloudflare configuration
- D1 binding: `DB` -> `womo-media`
- Secret: `FIREBASE_API_KEY`
- Variable: `ENCODER_ADMIN_UIDS` (comma-separated Firebase UIDs) OR `ENCODER_ADMIN_EMAILS` (comma-separated emails)

Optional: a Firebase custom claim `encoderAdmin: true` is also accepted.

## Existing media-token secret
Do **not** delete `REGISTER_TOKEN` yet if your current `/playback` still uses it as the fallback media signing secret. Prefer creating a dedicated `MEDIA_TOKEN_SECRET`; after that, `REGISTER_TOKEN` can be removed entirely. It is no longer accepted by `/register`.

## Routes
- `POST /register` - Firebase-authenticated admin registration
- `POST /playback` - Firebase-authenticated AES key retrieval
- `POST /media` - byte-range bridge
- `POST /check-media` - media health
- `GET /health`

## Deploy
Replace the files in the private `womo-media-api` repository and push to `main`. Keep the existing D1 binding. Add one admin allowlist variable in Cloudflare before testing `/register`.
