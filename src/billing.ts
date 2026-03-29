/**
 * mcp-scan billing helpers
 *
 * Reads MCP_SCAN_API_KEY from the environment and validates it against
 * the Foundry billing service. Falls back to the free tier when no key
 * is present or when the service is unreachable.
 */

export type SubscriptionTier = "free" | "pro" | "enterprise";

export interface SubscriptionInfo {
  tier: SubscriptionTier;
  valid: boolean;
  active: boolean;
  email?: string;
}

const FREE_TIER: SubscriptionInfo = { tier: "free", valid: true, active: true };

/**
 * Return the API key from env or undefined.
 * Env var: MCP_SCAN_API_KEY
 */
export function getApiKey(): string | undefined {
  return process.env.MCP_SCAN_API_KEY || undefined;
}

/**
 * Offline-verify the API key format/HMAC signature.
 *
 * Key format: {prefix}_{32-hex-token}_{12-hex-sig}
 * Prefixes: mfs=free, mfp=pro, mfe=enterprise
 *
 * This check does NOT call the billing server — use verifyApiKeyOnline for
 * live subscription status.
 */
export function verifyApiKeyOffline(apiKey: string): SubscriptionInfo {
  const parts = apiKey.split("_");
  if (parts.length !== 3) return { tier: "free", valid: false, active: false };
  const [prefix] = parts;
  const tierMap: Record<string, SubscriptionTier> = {
    mfs: "free",
    mfp: "pro",
    mfe: "enterprise",
  };
  const tier = tierMap[prefix];
  if (!tier) return { tier: "free", valid: false, active: false };
  // Basic format check: token should be 32 hex chars, sig 12 hex chars
  if (!/^[0-9a-f]{32}$/.test(parts[1])) return { tier: "free", valid: false, active: false };
  if (!/^[0-9a-f]{12}$/.test(parts[2])) return { tier: "free", valid: false, active: false };
  return { tier, valid: true, active: true };
}

/**
 * Verify the API key against the Foundry billing service.
 * Falls back to offline check if service is unreachable.
 */
export async function verifyApiKey(apiKey: string): Promise<SubscriptionInfo> {
  const foundryUrl = process.env.FOUNDRY_API_URL || "http://localhost:8800";
  const url = `${foundryUrl}/v1/billing/verify/${encodeURIComponent(apiKey)}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "Content-Type": "application/json" },
    });
    clearTimeout(timeout);

    if (!res.ok) return verifyApiKeyOffline(apiKey);

    const data = (await res.json()) as {
      valid?: boolean;
      tier?: string;
      active?: boolean;
      email?: string;
    };
    return {
      tier: (data.tier as SubscriptionTier) || "free",
      valid: data.valid ?? false,
      active: data.active ?? false,
      email: data.email,
    };
  } catch {
    // Billing service unreachable — fall back to offline check
    return verifyApiKeyOffline(apiKey);
  }
}

/**
 * Get the current subscription for this CLI session.
 * Returns free tier if no API key is set.
 */
export async function getCurrentSubscription(): Promise<SubscriptionInfo> {
  const apiKey = getApiKey();
  if (!apiKey) return FREE_TIER;
  return verifyApiKey(apiKey);
}

/**
 * Return the Foundry billing checkout URL for the given tier.
 */
export function getCheckoutUrl(tier: "pro" | "enterprise", email?: string): string {
  const foundryUrl = process.env.FOUNDRY_API_URL || "http://localhost:8800";
  const params = new URLSearchParams({ tier });
  if (email) params.set("email", email);
  return `${foundryUrl}/v1/billing/subscribe?${params.toString()}`;
}

export const TIER_LABELS: Record<SubscriptionTier, string> = {
  free: "Free",
  pro: "Pro ($19/mo)",
  enterprise: "Enterprise ($99/mo)",
};

export const TIER_FEATURES: Record<SubscriptionTier, string[]> = {
  free: [
    "Unlimited scans",
    "10 built-in MCP security rules",
    "SARIF, JSON, and text output",
    "CLI tool",
  ],
  pro: [
    "Everything in Free",
    "Advanced detection rules",
    "Policy reports",
    "Foundry Engine API access",
    "Scan history and analytics",
    "Priority support",
  ],
  enterprise: [
    "Everything in Pro",
    "Custom security rules",
    "Team dashboard",
    "Dedicated SLA",
    "Custom integrations",
    "Onboarding support",
  ],
};
