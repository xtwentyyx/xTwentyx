import { describe, expect, it } from "vitest";
import { handleRequest, matchesHeuristicAllowlist } from "../src/index";

const secureEnv = {
  HEURISTIC_UA_ALLOWLIST: "",
  LUA_ACCESS_TOKEN: "test-token-only",
} satisfies Env;

function fetchWith(
  path: string,
  init?: RequestInit,
  env: Env = secureEnv,
): Promise<Response> {
  return handleRequest(new Request(`https://example.test${path}`, init), env);
}

describe("xTwentyx Worker", () => {
  it("shows Hola at the root", async () => {
    const response = await fetchWith("/");
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("text/html");
    expect(await response.text()).toContain("Hola");
  });

  it("redirects a normal browser navigation away from the Lua path", async () => {
    const response = await fetchWith("/main.lua", {
      headers: {
        Accept: "text/html",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
      },
      redirect: "manual",
    });
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toBe("https://example.test/");
  });

  it("returns Lua only with the correct custom header", async () => {
    const response = await fetchWith("/main.lua", {
      headers: { "X-Lua-Token": "test-token-only" },
    });
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("text/plain");
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    expect(body.length).toBeGreaterThan(100_000);
    expect(body).not.toContain("<main>Hola</main>");
  });

  it("never returns Lua for a wrong token", async () => {
    const response = await fetchWith("/main.lua", {
      headers: { "X-Lua-Token": "wrong-token" },
    });
    expect(response.status).toBe(401);
    expect(response.headers.get("Content-Type")).toContain("text/html");
    expect(await response.text()).toContain("Hola");
  });

  it("keeps the heuristic mode disabled by default", async () => {
    const response = await fetchWith("/main.lua", {
      headers: { "User-Agent": "LegacyExecutor/1.0" },
    });
    expect(response.status).toBe(401);
  });

  it("can recognize an explicitly enabled, spoofable compatibility signature", () => {
    const request = new Request("https://example.test/main.lua", {
      headers: { "User-Agent": "LegacyExecutor/1.0" },
    });
    expect(matchesHeuristicAllowlist(request, "legacyexecutor")).toBe(true);
  });
});
