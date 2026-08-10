const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "authorization,content-type",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    if (request.method === "GET" && url.pathname === "/") {
      return json(
        {
          ok: true,
          service: "womo-media-api",
          version: "0.1.0",
          status: "ready",
        },
        200,
        corsHeaders
      );
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true }, 200, corsHeaders);
    }

    if (url.pathname === "/register" || url.pathname === "/playback") {
      return json(
        {
          ok: false,
          error: "not_configured_yet",
          message: "D1 and Worker secrets still need to be connected.",
        },
        501,
        corsHeaders
      );
    }

    return json({ ok: false, error: "not_found" }, 404, corsHeaders);
  },
};
