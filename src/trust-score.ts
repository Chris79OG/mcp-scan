/**
 * Trust scoring algorithm for MCP server security assessments.
 *
 * Computes a weighted 0-100 score across five security dimensions:
 *
 *   Authentication  (25%) — server enforces credentials
 *   Encryption      (20%) — endpoint uses TLS
 *   Input validation(25%) — tool schemas use additionalProperties:false
 *   Rate limiting   (15%) — rate-limit headers present
 *   Error handling  (15%) — errors don't leak internal details
 *
 * Grade thresholds: A≥90, B≥75, C≥60, D≥45, F<45
 */

import { TrustScore, TrustScoreBreakdown } from "./types";

/** Inputs required to compute the trust score. */
export interface TrustScoreInputs {
  /** Server rejects unauthenticated requests. */
  requiresAuth: boolean;
  /** Server endpoint uses HTTPS. */
  usesHttps: boolean;
  /** Fraction (0–1) of tools whose input schemas have additionalProperties:false. */
  strictSchemaRatio: number;
  /** Server advertises rate-limiting headers. */
  hasRateLimit: boolean;
  /** Server leaks stack traces or internal details in error responses. */
  leaksErrors: boolean;
}

/** Weights for each dimension (must sum to 1.0). */
const WEIGHTS: Record<keyof TrustScoreBreakdown, number> = {
  authentication: 0.25,
  encryption: 0.20,
  inputValidation: 0.25,
  rateLimiting: 0.15,
  errorHandling: 0.15,
};

/**
 * Convert a raw 0-100 weighted overall score to a letter grade.
 *
 * A  90–100  Excellent — enterprise-grade security posture.
 * B  75–89   Good — minor gaps that should be addressed.
 * C  60–74   Fair — meaningful risk present; remediation recommended.
 * D  45–59   Poor — significant vulnerabilities; immediate action needed.
 * F  0–44    Critical — fundamental security controls missing.
 */
function toGrade(score: number): TrustScore["grade"] {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

/**
 * Compute a TrustScore from the results of a live endpoint scan.
 *
 * Each dimension is scored 0 or 100 (binary for most checks), with
 * inputValidation using the strict-schema ratio as a continuous value.
 *
 * @param inputs - Security posture inputs from the live scan probes.
 * @returns A TrustScore with per-dimension breakdown and letter grade.
 */
export function computeTrustScore(inputs: TrustScoreInputs): TrustScore {
  const breakdown: TrustScoreBreakdown = {
    authentication: inputs.requiresAuth ? 100 : 0,
    encryption: inputs.usesHttps ? 100 : 0,
    inputValidation: Math.round(inputs.strictSchemaRatio * 100),
    rateLimiting: inputs.hasRateLimit ? 100 : 0,
    errorHandling: inputs.leaksErrors ? 0 : 100,
  };

  const overall = Math.round(
    (Object.keys(breakdown) as Array<keyof TrustScoreBreakdown>).reduce(
      (sum, key) => sum + breakdown[key] * WEIGHTS[key],
      0,
    ),
  );

  return {
    overall,
    breakdown,
    grade: toGrade(overall),
  };
}

/**
 * Format a TrustScore as a human-readable summary string.
 *
 * @param score - The TrustScore to format.
 * @returns Multi-line string suitable for console output.
 */
export function formatTrustScore(score: TrustScore): string {
  const gradeColor = (g: string) => {
    switch (g) {
      case "A": return `\x1b[32m${g}\x1b[0m`;  // green
      case "B": return `\x1b[32m${g}\x1b[0m`;  // green
      case "C": return `\x1b[33m${g}\x1b[0m`;  // yellow
      case "D": return `\x1b[31m${g}\x1b[0m`;  // red
      default:  return `\x1b[31m${g}\x1b[0m`;  // red
    }
  };

  const bar = (score100: number) => {
    const filled = Math.round(score100 / 10);
    return "█".repeat(filled) + "░".repeat(10 - filled);
  };

  const lines = [
    `Trust Score: ${score.overall}/100  Grade: ${gradeColor(score.grade)}`,
    "",
    `  Authentication  [${bar(score.breakdown.authentication)}] ${score.breakdown.authentication}`,
    `  Encryption      [${bar(score.breakdown.encryption)}] ${score.breakdown.encryption}`,
    `  Input Validation[${bar(score.breakdown.inputValidation)}] ${score.breakdown.inputValidation}`,
    `  Rate Limiting   [${bar(score.breakdown.rateLimiting)}] ${score.breakdown.rateLimiting}`,
    `  Error Handling  [${bar(score.breakdown.errorHandling)}] ${score.breakdown.errorHandling}`,
  ];

  return lines.join("\n");
}
