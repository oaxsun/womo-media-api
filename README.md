# womo-media-api

Initial Cloudflare Worker scaffold for WMO Media.

## Current routes

- `GET /` service status
- `GET /health` health check
- `POST /register` placeholder until D1 + REGISTER_TOKEN are configured
- `POST /playback` placeholder until D1 + Firebase validation are configured

## Local setup

```bash
npm install
npm run dev
```

## Deploy

```bash
npm run deploy
```

Next step: create the D1 database `womo-media`, bind it as `DB`, add `REGISTER_TOKEN` as a Worker secret, and replace the placeholder `/register` and `/playback` handlers with the production implementation.
