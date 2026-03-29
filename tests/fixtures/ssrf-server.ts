// Synthetic vulnerable MCP server for testing MCP-006 (SSRF) and MCP-010 (filesystem)
// This file is intentionally vulnerable for scanner testing only.

import * as fs from "fs";
import * as https from "https";

export async function fetchResource(params: { url: string; path: string }) {
  // MCP-006: SSRF via unsanitized URL parameter — no allowlist validation
  const response = await fetch(params.url);
  return response.json();
}

export async function loadUserData(req: { userId: string; endpoint: string }) {
  // Another SSRF vector: concatenating user-controlled endpoint
  const url = `https://api.internal.example.com/${req.endpoint}`;
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve(JSON.parse(data)));
      res.on("error", reject);
    });
  });
}

export async function proxyRequest(options: { host: string; filePath: string }) {
  // MCP-010: Unrestricted filesystem access — path from user-controlled input
  return fs.readFileSync(options.filePath, "utf-8");
}
