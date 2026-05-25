const BACKEND_URL = (Deno.env.get('OMNIPUBLISH_BACKEND_URL') || '').replace(/\/$/, '');
const ALLOWED_ORIGINS = (Deno.env.get('OMNIPUBLISH_APP_ORIGIN') || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const isAllowedOrigin = (origin: string | null) => {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  return /^https?:\/\/(localhost|127(?:\.\d{1,3}){3})(:\d+)?$/i.test(origin);
};

const buildCorsHeaders = (origin: string | null) => ({
  'Access-Control-Allow-Origin': origin && isAllowedOrigin(origin) ? origin : (ALLOWED_ORIGINS[0] || 'http://localhost:3000'),
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-csrf-token, idempotency-key, x-request-id',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  Vary: 'Origin',
});

const stripProxyPrefix = (pathname: string) => pathname.replace(/^\/(?:functions\/v1\/api-proxy|api-proxy)/, '') || '/';

Deno.serve(async (req) => {
  const origin = req.headers.get('origin');
  const headers = buildCorsHeaders(origin);

  if (req.method === 'OPTIONS') {
    return new Response('ok', { status: 204, headers });
  }

  if (!BACKEND_URL) {
    return Response.json({ error: 'OMNIPUBLISH_BACKEND_URL is not configured' }, { status: 500, headers });
  }

  const incomingUrl = new URL(req.url);
  const targetUrl = new URL(stripProxyPrefix(incomingUrl.pathname) + incomingUrl.search, BACKEND_URL);
  const upstreamHeaders = new Headers(req.headers);
  upstreamHeaders.delete('host');
  upstreamHeaders.delete('content-length');

  const upstreamResponse = await fetch(targetUrl, {
    method: req.method,
    headers: upstreamHeaders,
    body: req.method === 'GET' || req.method === 'HEAD' ? undefined : req.body,
  });

  const responseHeaders = new Headers(upstreamResponse.headers);
  for (const [key, value] of Object.entries(headers)) {
    responseHeaders.set(key, value);
  }

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    headers: responseHeaders,
  });
});
