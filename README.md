# WOMO Media API v1

Cloudflare Worker para registrar y recuperar claves AES de WMO usando D1.

## Bindings requeridos en Cloudflare

- `DB` -> D1 database `womo-media`
- `REGISTER_TOKEN` -> Secret
- `FIREBASE_API_KEY` -> Secret

## Tabla D1

```sql
CREATE TABLE media_keys (
  content_id TEXT PRIMARY KEY,
  media_key TEXT NOT NULL,
  created_at TEXT NOT NULL
);
```

## Endpoints

### GET /health
Comprueba el estado del Worker y la conexión a D1.

### POST /register
Header:
`Authorization: Bearer <REGISTER_TOKEN>`

Body:
```json
{
  "contentId": "uuid",
  "key": "AES-256-key-base64"
}
```

### POST /playback
Header:
`Authorization: Bearer <FIREBASE_ID_TOKEN>`

Body:
```json
{
  "contentId": "uuid"
}
```

Valida el ID Token usando Firebase Auth REST y devuelve la key correspondiente desde D1.

## Nota

Las claves no se guardan en GitHub. `REGISTER_TOKEN` y `FIREBASE_API_KEY` deben permanecer como Secrets del Worker.
