import { PERMISSION_CATALOG, classifyUnknownPermission } from "./config/permissions";
import type { ManifestModel, PermissionInfo, Severity } from "./types";

export function analyzePermissions(manifest: ManifestModel): PermissionInfo[] {
  const declared = new Set(manifest.declaredPermissions);
  return manifest.permissions
    .map((permission) => {
      const rule = PERMISSION_CATALOG[permission.name] ?? classifyUnknownPermission(permission.name);
      const parts = permission.name.split(".");
      return {
        name: permission.name,
        shortName: parts[parts.length - 1] ?? permission.name,
        category: rule.category,
        group: rule.group,
        whyItMatters: rule.whyItMatters,
        commonlyExpected: rule.commonlyExpected,
        severityHint: rule.severityHint,
        assessment: buildAssessment(rule.category, rule.commonlyExpected, permission.maxSdkVersion),
        maxSdkVersion: permission.maxSdkVersion,
        declaredOnly: declared.has(permission.name),
      } satisfies PermissionInfo;
    })
    .sort((a, b) => severityRank(b) - severityRank(a) || a.name.localeCompare(b.name));
}

/** Non-judgemental note describing how routine the request looks. */
function buildAssessment(
  category: PermissionInfo["category"],
  commonlyExpected: boolean,
  maxSdkVersion: number | null,
): string {
  const scope =
    maxSdkVersion !== null ? ` Requested only up to API ${maxSdkVersion}, so newer devices are unaffected.` : "";
  if (category === "SPECIAL") {
    return `Restricted permission: platform or store policy usually requires a documented justification.${scope}`;
  }
  if (category === "DANGEROUS") {
    return commonlyExpected
      ? `Runtime permission, routine for apps with this feature set; the user is prompted before it takes effect.${scope}`
      : `Runtime permission that is not routine for most apps; confirm a feature actually depends on it.${scope}`;
  }
  if (category === "SIGNATURE") {
    return `Signature-level permission: granted only to apps signed with the same certificate as the declaring app.${scope}`;
  }
  if (category === "UNKNOWN") {
    return `Not in the catalogue, so the protection level cannot be resolved from this APK alone.${scope}`;
  }
  return commonlyExpected
    ? `Install-time permission with no user prompt; routine for this kind of app.${scope}`
    : `Install-time permission with no user prompt; worth confirming it is still used.${scope}`;
}

function severityRank(permission: PermissionInfo): number {
  const order: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const categoryBoost = permission.category === "SPECIAL" ? 1 : 0;
  return order[permission.severityHint] * 2 + categoryBoost;
}

export function countByCategory(permissions: PermissionInfo[]): Record<string, number> {
  return permissions.reduce<Record<string, number>>((accumulator, permission) => {
    accumulator[permission.category] = (accumulator[permission.category] ?? 0) + 1;
    return accumulator;
  }, {});
}
