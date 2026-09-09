import luaSource from "./lua-source.generated";

const SCRIPT_PATH = "/main.lua";
const encoder = new TextEncoder();

const HTML = `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Hola</title>
  <style>html,body{height:100%;margin:0}body{display:grid;place-items:center;font:600 2rem system-ui,sans-serif;color:#111;background:#fff}</style>
</head>
<body><main>Hola</main></body>
</html>`;

const HTML_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  "Content-Type": "text/html; charset=utf-8",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

const LUA_HEADERS = {
  "Cache-Control": "private, no-store, no-cache, max-age=0, must-revalidate",
  "CDN-Cache-Control": "no-store",
  "Cloudflare-CDN-Cache-Control": "no-store",
  "Content-Disposition": 'inline; filename="main.lua"',
  "Content-Type": "text/plain; charset=utf-8",
  "Expires": "0",
  "Pragma": "no-cache",
  "Referrer-Policy": "no-referrer",
  "Vary": "Authorization, X-Lua-Token, User-Agent",
  "X-Content-Type-Options": "nosniff",
} as const;

function htmlResponse(status = 200): Response {
  return new Response(HTML, { status, headers: HTML_HEADERS });
}

function isBrowserNavigation(request: Request): boolean {
  const headers = request.headers;
  const accept = headers.get("Accept")?.toLowerCase() ?? "";
  return (
    headers.get("Sec-Fetch-Mode")?.toLowerCase() === "navigate" ||
    headers.get("Sec-Fetch-Dest")?.toLowerCase() === "document" ||
    accept.includes("text/html")
  );
}

function getProvidedToken(request: Request): string {
  const customHeader = request.headers.get("X-Lua-Token");
  if (customHeader !== null) return customHeader.trim();

  const authorization = request.headers.get("Authorization") ?? "";
  const bearer = authorization.match(/^Bearer\s+(.+)$/i);
  return bearer?.[1]?.trim() ?? "";
}

async function timingSafeTokenMatch(provided: string, expected: string): Promise<boolean> {
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(providedHash, expectedHash);
}

export function matchesHeuristicAllowlist(request: Request, allowlist: string): boolean {
  if (isBrowserNavigation(request)) return false;

  const userAgent = request.headers.get("User-Agent")?.toLowerCase() ?? "";
  if (!userAgent) return false;

  return allowlist
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean)
    .some((entry) => userAgent.includes(entry));
}

function luaResponse(request: Request): Response {
  const body = request.method === "HEAD" ? null : luaSource;
  return new Response(body, { status: 200, headers: LUA_HEADERS });
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url);

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { ...HTML_HEADERS, Allow: "GET, HEAD" },
      });
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return htmlResponse();
    }

    if (url.pathname !== SCRIPT_PATH) {
      return htmlResponse(404);
    }

    if (!env.LUA_ACCESS_TOKEN) {
      return htmlResponse(503);
    }

    const providedToken = getProvidedToken(request);
    const tokenIsValid = await timingSafeTokenMatch(providedToken, env.LUA_ACCESS_TOKEN);
    const heuristicMatch = matchesHeuristicAllowlist(
      request,
      env.HEURISTIC_UA_ALLOWLIST,
    );

    if (tokenIsValid || heuristicMatch) {
      return luaResponse(request);
    }

    if (isBrowserNavigation(request)) {
      return Response.redirect(new URL("/", request.url).toString(), 302);
    }

    return htmlResponse(401);
  } catch (error) {
    console.error(JSON.stringify({
      event: "worker_error",
      message: error instanceof Error ? error.message : "Unknown error",
    }));
    return htmlResponse(500);
  }
}

export default {
  fetch: handleRequest,
} satisfies ExportedHandler<Env>;
