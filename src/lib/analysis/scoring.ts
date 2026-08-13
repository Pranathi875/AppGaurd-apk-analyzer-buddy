/**
 * Transparent, evidence-aware scoring: every score starts at a configured
 * baseline and is reduced only by the weights of findings that actually fired.
 *
 * A score is never inflated when evidence is missing. Instead it is marked
 * PARTIAL (value is a lower bound) or UNAVAILABLE (no number is reported).
 */

import { SCORE_DEFINITIONS } from "./config/rules";
import type { Finding, Score, ScoreKey, ScoreStatus } from "./types";

const SCORE_ORDER: ScoreKey[] = ["security", "privacy", "quality", "coverage"];

export interface EvidenceAvailability {
  manifestParsed: boolean;
  dexParsed: boolean;
  /** True when every discovered DEX file was scanned to completion. */
  dexComplete: boolean;
}

const FULL_EVIDENCE: EvidenceAvailability = { manifestParsed: true, dexParsed: true, dexComplete: true };

export function computeScores(findings: Finding[], evidence: EvidenceAvailability = FULL_EVIDENCE): Score[] {
  return SCORE_ORDER.map((key) => {
    const definition = SCORE_DEFINITIONS[key];
    const relevant = findings.filter((finding) => finding.scoreTarget === key);
    const contributions = relevant
      .map((finding) => ({
        ruleId: finding.ruleId,
        title: finding.title,
        severity: finding.severity,
        deduction: finding.weight,
      }))
      .sort((a, b) => b.deduction - a.deduction);
    const total = contributions.reduce((sum, contribution) => sum + contribution.deduction, 0);
    const { status, statusReason } = statusFor(key, evidence);

    return {
      key,
      label: definition.label,
      start: definition.start,
      value: status === "UNAVAILABLE" ? null : clamp(definition.start - total),
      status,
      statusReason,
      contributions,
      methodology: definition.methodology,
    } satisfies Score;
  });
}

function statusFor(
  key: ScoreKey,
  evidence: EvidenceAvailability,
): { status: ScoreStatus; statusReason: string | null } {
  if (key === "coverage") return { status: "COMPLETE", statusReason: null };

  if ((key === "security" || key === "privacy") && !evidence.manifestParsed) {
    return {
      status: "UNAVAILABLE",
      statusReason: "AndroidManifest.xml could not be decoded, so no configuration evidence exists for this score.",
    };
  }

  if (key === "security" && !evidence.dexParsed) {
    return {
      status: "PARTIAL",
      statusReason: "No DEX bytecode could be read; code-level evidence is missing, so the value is a lower bound.",
    };
  }

  if (key === "security" && !evidence.dexComplete) {
    return {
      status: "PARTIAL",
      statusReason: "At least one DEX file could not be scanned to completion, so some code evidence is missing.",
    };
  }

  if (key === "quality" && !evidence.manifestParsed) {
    return { status: "PARTIAL", statusReason: "Manifest evidence is missing; only container facts were scored." };
  }

  return { status: "COMPLETE", statusReason: null };
}

export function overallScore(scores: Score[]): number {
  // Coverage is reported but excluded from the headline: it measures how much
  // evidence we had, not the quality of the application. Scores without a
  // value are skipped rather than counted as 0 or 100.
  const weighted = scores.filter((score) => score.key !== "coverage" && score.value !== null);
  if (weighted.length === 0) return 0;
  return Math.round(weighted.reduce((sum, score) => sum + (score.value ?? 0), 0) / weighted.length);
}

export function scoreBand(value: number): "strong" | "fair" | "weak" {
  if (value >= 80) return "strong";
  if (value >= 55) return "fair";
  return "weak";
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}
