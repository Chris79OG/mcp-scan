// Clean MCP server with no security issues — should produce 0 findings.

const ALLOWED_PATHS = new Set(["/data/reports", "/data/exports"]);

export async function readDocument(params: { documentId: string }): Promise<string> {
  // Safe: validates documentId is a known identifier, no direct path injection
  const validId = /^[a-z0-9-]{3,64}$/.test(params.documentId);
  if (!validId) {
    throw new Error("Invalid document ID");
  }
  return `Document content for ${params.documentId}`;
}

export async function fetchExternalData(resourceKey: string): Promise<unknown> {
  // Safe: uses an allowlist of known-safe endpoints
  const ALLOWED_ENDPOINTS: Record<string, string> = {
    "weather-api": "https://api.weather.example.com/current",
    "news-api": "https://api.news.example.com/top",
  };
  const endpoint = ALLOWED_ENDPOINTS[resourceKey];
  if (!endpoint) {
    throw new Error(`Unknown resource key: ${resourceKey}`);
  }
  const response = await fetch(endpoint);
  return response.json();
}

export function validatePath(inputPath: string): string {
  // Safe: strict allowlist before any filesystem operation
  if (!ALLOWED_PATHS.has(inputPath)) {
    throw new Error("Path not in allowlist");
  }
  return inputPath;
}
