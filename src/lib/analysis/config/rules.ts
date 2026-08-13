/**
 * Rule catalogue and scoring weights.
 *
 * Metadata (severity, weights, thresholds, copy) is configuration. The
 * predicates that decide whether a rule fires live in rules-engine.ts and
 * reference these ids. Changing a weight never requires touching logic.
 */

import type { FindingCategory, ScoreKey, Severity } from "../types";

export const RULES_VERSION = "2026.02.1";

export interface RuleDefinition {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  scoreTarget: ScoreKey;
  /** Points deducted from the target score when the rule fires once. */
  weight: number;
  /** Optional cap when the rule can fire multiple times. */
  maxDeduction?: number;
  description: string;
  /** What the finding means in practice; falls back to the description. */
  impact?: string;
  recommendation: string;
}

export const THRESHOLDS = {
  /** Target SDK considered current at the time of this rules version. */
  currentTargetSdk: 35,
  targetSdkWarnBelow: 33,
  targetSdkHighBelow: 29,
  minSdkVeryOldBelow: 21,
  apkSizeWarnBytes: 60 * 1024 * 1024,
  apkSizeHighBytes: 150 * 1024 * 1024,
  largeAssetBytes: 10 * 1024 * 1024,
  dangerousPermissionWarnCount: 6,
  dangerousPermissionHighCount: 10,
  exportedComponentWarnCount: 8,
  exportedComponentHighCount: 20,
} as const;

export const SCORE_DEFINITIONS: Record<ScoreKey, { label: string; start: number; methodology: string }> = {
  quality: {
    label: "Quality",
    start: 100,
    methodology:
      "Starts at 100. Deductions come from build-hygiene rules: target SDK age, APK size, oversized assets, missing native ABI coverage and debug configuration. Each rule has a fixed weight declared in rules configuration.",
  },
  security: {
    label: "Security / configuration",
    start: 100,
    methodology:
      "Starts at 100. Deductions come from manifest and component configuration rules such as debuggable builds, cleartext traffic, exported components without permission guards and backup configuration.",
  },
  privacy: {
    label: "Privacy / permissions",
    start: 100,
    methodology:
      "Starts at 100. Deductions are driven by the number and sensitivity of requested permissions and by capabilities with a strong privacy footprint.",
  },
  coverage: {
    label: "Analysis coverage",
    start: 100,
    methodology:
      "Starts at 100 and is reduced when a part of the pipeline could not run: unparsed manifest, unreadable DEX, truncated string scanning or absent resource table. A low coverage score means the other scores rest on less evidence.",
  },
};

export const RULE_DEFINITIONS: RuleDefinition[] = [
  {
    id: "MANIFEST_DEBUGGABLE",
    title: "Application is marked debuggable",
    category: "MANIFEST",
    severity: "HIGH",
    scoreTarget: "security",
    weight: 25,
    description:
      "android:debuggable=\"true\" allows a debugger to attach to the process and inspect or modify runtime state on any device.",
    recommendation:
      "Remove the attribute and rely on debug build variants. Verify the release manifest after merge, since library manifests can reintroduce it.",
  },
  {
    id: "MANIFEST_CLEARTEXT_TRAFFIC",
    title: "Cleartext HTTP traffic is permitted",
    category: "MANIFEST",
    severity: "MEDIUM",
    scoreTarget: "security",
    weight: 12,
    description:
      "android:usesCleartextTraffic=\"true\" re-enables unencrypted HTTP for the whole app, which exposes traffic to interception on hostile networks.",
    recommendation:
      "Remove the flag and, if specific hosts genuinely need cleartext, scope them in a network security configuration instead.",
  },
  {
    id: "MANIFEST_NO_NETWORK_SECURITY_CONFIG",
    title: "No network security configuration declared",
    category: "MANIFEST",
    severity: "INFO",
    scoreTarget: "security",
    // Informational only: platform defaults are already safe on modern Android,
    // so the absence of an explicit config is not evidence of a weakness.
    weight: 0,
    description:
      "The app relies entirely on platform defaults for TLS trust and cleartext policy. This is acceptable, but an explicit configuration documents intent and enables pinning.",
    recommendation:
      "Consider adding a network security configuration that pins or restricts trust anchors for your own domains.",
  },
  {
    id: "MANIFEST_BACKUP_ALLOWED",
    title: "Application backup is enabled without documented rules",
    category: "MANIFEST",
    severity: "LOW",
    scoreTarget: "security",
    weight: 6,
    description:
      "android:allowBackup is enabled and no backup rules resource was declared, so app-private files may be included in device backups.",
    recommendation:
      "Declare android:dataExtractionRules / android:fullBackupContent to exclude credentials, tokens and caches, or disable backup for sensitive apps.",
  },
  {
    id: "COMPONENT_EXPORTED_RISKY",
    title: "Externally reachable component with a risky surface",
    category: "COMPONENT",
    severity: "HIGH",
    scoreTarget: "security",
    weight: 8,
    maxDeduction: 24,
    description:
      "A component is reachable from any other application, declares no android:permission, and its manifest evidence points to a sensitive surface (custom deep-link scheme, provider-like data handling, or an intent filter that accepts arbitrary external input).",
    impact:
      "Any installed app, or a web page in the case of a browsable filter, can invoke this entry point directly with attacker-chosen extras.",
    recommendation:
      "Set android:exported=\"false\" if external access is not required, otherwise guard the component with a signature-level android:permission and validate every incoming Intent field.",
  },
  {
    id: "COMPONENT_EXPORTED_REVIEW",
    title: "Exported component worth reviewing",
    category: "COMPONENT",
    severity: "MEDIUM",
    scoreTarget: "security",
    weight: 2,
    maxDeduction: 10,
    description:
      "A component is exported without a permission and is not one of the expected entry points (launcher, share target, or known tooling/library component). There is no direct evidence of a vulnerability, only an entry point that should be intentional.",
    impact:
      "The component forms part of the app's external contract, so its Intent handling must be validated and kept stable.",
    recommendation:
      "Confirm the export is deliberate and that all incoming Intent extras are validated; otherwise set android:exported=\"false\".",
  },
  {
    id: "COMPONENT_EXPORTED_EXPECTED",
    title: "Expected exported entry points",
    category: "COMPONENT",
    severity: "INFO",
    scoreTarget: "security",
    // Normal, required Android behaviour: recorded for transparency, never scored.
    weight: 0,
    description:
      "These components are exported because Android requires it: launcher activities, share/view targets, and components contributed by common libraries and build tooling (WorkManager, Firebase, Play services, leak/debug tooling).",
    impact: "No impact on its own; these exports are required for the app to be launchable and for its libraries to function.",
    recommendation: "No action needed. Keep tooling-only components out of release builds where the library supports it.",
  },
  {
    id: "COMPONENT_EXPORTED_PROVIDER",
    title: "Exported content provider",
    category: "COMPONENT",
    severity: "MEDIUM",
    scoreTarget: "security",
    weight: 8,
    maxDeduction: 24,
    description:
      "A content provider is exported. Providers expose structured data and URI permissions, so an unguarded provider can leak or accept data from any installed app.",
    recommendation:
      "Configuration requires attention: set android:exported=\"false\" unless external access is required, and otherwise enforce read/write permissions and path restrictions.",
  },
  {
    id: "COMPONENT_EXPORTED_COUNT_HIGH",
    title: "Large externally reachable attack surface",
    category: "COMPONENT",
    severity: "LOW",
    scoreTarget: "security",
    weight: 8,
    description:
      "The number of exported components is high relative to typical applications, which increases the amount of input validation that must be maintained.",
    recommendation: "Audit the exported set and close entry points that are not part of a documented contract.",
  },
  {
    id: "COMPONENT_BROWSABLE_DEEP_LINK",
    title: "Browsable deep links present",
    category: "COMPONENT",
    severity: "INFO",
    scoreTarget: "security",
    weight: 2,
    maxDeduction: 6,
    description:
      "Components accept BROWSABLE intent filters, so a web page can launch them with attacker-controlled URI data.",
    recommendation:
      "Potential risk indicator: validate every deep-link parameter and prefer verified App Links (android:autoVerify) over unverified schemes.",
  },
  {
    id: "PERMISSION_DANGEROUS_MANY",
    title: "High number of sensitive permissions requested",
    category: "PERMISSION",
    severity: "MEDIUM",
    scoreTarget: "privacy",
    weight: 12,
    description:
      "The application requests many runtime-protected permissions. Each one widens the privacy surface and needs a user-facing justification.",
    recommendation: "Remove permissions no longer used by the current feature set and prefer scoped alternatives such as photo picker or Companion Device Manager.",
  },
  {
    id: "PERMISSION_SPECIAL",
    title: "Special / restricted permission requested",
    category: "PERMISSION",
    severity: "HIGH",
    scoreTarget: "privacy",
    weight: 10,
    maxDeduction: 30,
    description:
      "A permission with a restricted protection level or store policy declaration requirement is present.",
    recommendation:
      "Confirm the use case matches the platform policy for this permission and document it, otherwise remove it.",
  },
  {
    id: "PERMISSION_QUERY_ALL_PACKAGES",
    title: "QUERY_ALL_PACKAGES requested",
    category: "PRIVACY",
    severity: "MEDIUM",
    scoreTarget: "privacy",
    weight: 10,
    description:
      "The app can enumerate every installed application, which is a strong fingerprinting signal and is policy-restricted on major stores.",
    recommendation: "Replace with a <queries> element listing only the packages or intents the app genuinely needs.",
  },
  {
    id: "PERMISSION_CUSTOM_UNDOCUMENTED",
    title: "Custom or uncatalogued permissions requested",
    category: "PERMISSION",
    severity: "INFO",
    scoreTarget: "privacy",
    weight: 2,
    maxDeduction: 6,
    description:
      "Permissions outside the configured catalogue were requested. Their protection level cannot be resolved from this APK alone.",
    recommendation: "Document the purpose of each custom permission and confirm the declaring app's protection level.",
  },
  {
    id: "QUALITY_TARGET_SDK_OLD",
    title: "Target SDK is behind the current platform",
    category: "QUALITY",
    severity: "MEDIUM",
    scoreTarget: "quality",
    weight: 15,
    description:
      "Targeting an older API level opts the app out of newer platform privacy and security behaviour and eventually blocks store updates.",
    recommendation: "Raise targetSdkVersion and re-test the behaviour changes documented for each intermediate release.",
  },
  {
    id: "QUALITY_MIN_SDK_VERY_OLD",
    title: "Minimum SDK covers unsupported platform versions",
    category: "QUALITY",
    severity: "LOW",
    scoreTarget: "quality",
    weight: 6,
    description:
      "Supporting very old API levels forces compatibility shims and keeps devices without modern platform hardening in scope.",
    recommendation: "Review install-base data and raise minSdkVersion when the long tail no longer justifies the maintenance cost.",
  },
  {
    id: "QUALITY_APK_SIZE",
    title: "APK size is large",
    category: "QUALITY",
    severity: "LOW",
    scoreTarget: "quality",
    weight: 8,
    description:
      "Large downloads reduce install conversion and update adoption, particularly on constrained networks.",
    recommendation: "Ship an Android App Bundle, enable resource shrinking and split native ABIs and densities.",
  },
  {
    id: "QUALITY_LARGE_ASSETS",
    title: "Individual oversized entries in the package",
    category: "QUALITY",
    severity: "INFO",
    scoreTarget: "quality",
    weight: 3,
    maxDeduction: 9,
    description: "Single files above the configured size threshold dominate the package payload.",
    recommendation: "Move large media and models to on-demand delivery or a CDN, and compress what must ship in-package.",
  },
  {
    id: "QUALITY_MULTIPLE_ABIS",
    title: "Multiple native ABIs shipped in one artifact",
    category: "QUALITY",
    severity: "LOW",
    scoreTarget: "quality",
    weight: 5,
    description:
      "The package contains native libraries for several ABIs, so every device downloads code it cannot execute.",
    recommendation: "Use App Bundle ABI splits so each device receives only its own native libraries.",
  },
  {
    id: "QUALITY_NO_V2_SIGNATURE_BLOCK",
    title: "No APK signing block detected",
    category: "QUALITY",
    severity: "MEDIUM",
    scoreTarget: "security",
    weight: 10,
    description:
      "No APK Signing Block was found before the central directory, which suggests the artifact is unsigned or only carries a legacy v1 JAR signature.",
    recommendation: "Sign release artifacts with APK Signature Scheme v2 or later; v1-only signatures are rejected by modern platforms.",
  },
  {
    id: "QUALITY_DEBUG_CERT",
    title: "Debug signing certificate indicators",
    category: "QUALITY",
    severity: "MEDIUM",
    scoreTarget: "security",
    weight: 10,
    description: "The signing metadata resembles the Android debug keystore, which must never reach production.",
    recommendation: "Re-sign the artifact with the release keystore managed by your signing infrastructure.",
  },
  {
    id: "CAPABILITY_WEBVIEW_JS_BRIDGE",
    title: "JavaScript bridge indicators in WebView usage",
    category: "COMPONENT",
    severity: "MEDIUM",
    scoreTarget: "security",
    weight: 8,
    description:
      "References to addJavascriptInterface were found alongside WebView usage. A bridge exposes native methods to page content.",
    recommendation:
      "Review recommended: restrict the bridge to trusted origins, avoid loading remote content into bridged WebViews and annotate exposed methods narrowly.",
  },
  {
    id: "PRIVACY_HIGH_SENSITIVITY_CAPABILITIES",
    title: "Multiple high-sensitivity capabilities detected",
    category: "PRIVACY",
    severity: "LOW",
    scoreTarget: "privacy",
    weight: 8,
    description:
      "Camera, microphone and location together form a privacy-sensitive combination that requires a clear disclosure in the store listing and in-app.",
    recommendation: "Ensure the privacy policy and data-safety declaration match the detected capabilities.",
  },
  {
    id: "COVERAGE_MANIFEST_UNPARSED",
    title: "AndroidManifest could not be decoded",
    category: "COVERAGE",
    severity: "HIGH",
    scoreTarget: "coverage",
    weight: 60,
    description: "The binary manifest failed to parse, so permission and component analysis is unavailable.",
    recommendation: "Confirm the file is a valid APK. Obfuscated or non-standard packers may require tool-based extraction.",
  },
  {
    id: "COVERAGE_DEX_UNPARSED",
    title: "No DEX bytecode could be read",
    category: "COVERAGE",
    severity: "MEDIUM",
    scoreTarget: "coverage",
    weight: 30,
    description:
      "Class and string evidence is unavailable, so capability and library detection relies on manifest evidence only.",
    recommendation: "The package may be packed or compressed with an unsupported method. Consider an offline tool-assisted run.",
  },
  {
    id: "COVERAGE_DEX_TRUNCATED",
    title: "DEX string scanning was truncated",
    category: "COVERAGE",
    severity: "LOW",
    scoreTarget: "coverage",
    weight: 10,
    description: "The string pool exceeded the configured scan limit, so some evidence may be missing.",
    recommendation: "Treat NOT_DETECTED capability results as weaker evidence for this run.",
  },
  {
    id: "COVERAGE_NO_RESOURCE_TABLE",
    title: "No resource table present",
    category: "COVERAGE",
    severity: "INFO",
    scoreTarget: "coverage",
    weight: 5,
    description: "resources.arsc is absent, so resource-reference values in the manifest cannot be resolved to literals.",
    recommendation: "Values shown as @resource identifiers should be checked in the source project.",
  },
];

export const RULE_INDEX: Record<string, RuleDefinition> = Object.fromEntries(
  RULE_DEFINITIONS.map((rule) => [rule.id, rule]),
);