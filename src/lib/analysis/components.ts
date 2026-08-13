/**
 * Context-aware classification of exported components.
 *
 * Android requires many components to be exported (launchers, share targets,
 * library and build-tooling components). Treating all of them as equally risky
 * produces noise, so each exported component is classified from manifest
 * evidence alone and the reason is always recorded.
 */

import type { ComponentInfo, ManifestModel } from "./types";

export type ExportRisk = "RISKY" | "REVIEW" | "EXPECTED";

export interface ClassifiedComponent {
  component: ComponentInfo;
  risk: ExportRisk;
  /** Human-readable justification shown next to the component. */
  reason: string;
}

/** Class-name prefixes of components that common libraries export by design. */
const TOOLING_PREFIXES = [
  "androidx.startup.",
  "androidx.work.impl.",
  "androidx.profileinstaller.",
  "androidx.core.content.FileProvider",
  "androidx.sqlite.",
  "androidx.room.",
  "com.google.android.gms.",
  "com.google.firebase.",
  "com.google.android.play.core.",
  "com.squareup.leakcanary.",
  "leakcanary.",
  "io.flutter.",
  "com.facebook.react.",
  "expo.modules.",
  "com.android.installreferrer.",
  "androidx.test.",
  "androidx.lifecycle.ProcessLifecycleOwnerInitializer",
];

const STANDARD_ACTIONS = new Set([
  "android.intent.action.MAIN",
  "android.intent.action.VIEW",
  "android.intent.action.SEND",
  "android.intent.action.SEND_MULTIPLE",
  "android.intent.action.SEARCH",
  "android.intent.action.BOOT_COMPLETED",
  "android.intent.action.MY_PACKAGE_REPLACED",
  "com.google.firebase.MESSAGING_EVENT",
  "com.google.android.c2dm.intent.RECEIVE",
]);

const WEB_SCHEMES = new Set(["http", "https"]);

export function classifyExportedComponents(manifest: ManifestModel): ClassifiedComponent[] {
  return manifest.components
    .filter((component) => component.exported && component.enabled)
    .map((component) => classifyComponent(component));
}

function classifyComponent(component: ComponentInfo): ClassifiedComponent {
  const actions = component.intentFilters.flatMap((filter) => filter.actions);
  const categories = component.intentFilters.flatMap((filter) => filter.categories);
  const schemes = component.intentFilters.flatMap((filter) => filter.dataSchemes);

  if (component.permission) {
    return {
      component,
      risk: "EXPECTED",
      reason: `Exported but guarded by android:permission="${component.permission}", so callers must hold that permission.`,
    };
  }

  if (isTooling(component.name)) {
    return {
      component,
      risk: "EXPECTED",
      reason: "Belongs to a well-known library or build-tooling package that requires this component to be exported.",
    };
  }

  const isLauncher =
    actions.includes("android.intent.action.MAIN") && categories.includes("android.intent.category.LAUNCHER");
  if (isLauncher) {
    return {
      component,
      risk: "EXPECTED",
      reason: "Launcher entry point: Android requires MAIN/LAUNCHER activities to be exported so the app can be started.",
    };
  }

  // Custom (non-web) deep-link schemes reachable from a browser are the classic
  // hijack/unvalidated-input surface, so they are the one HIGH case here.
  const browsable = categories.includes("android.intent.category.BROWSABLE");
  const customSchemes = schemes.filter((scheme) => scheme && !WEB_SCHEMES.has(scheme.toLowerCase()));
  if (browsable && customSchemes.length > 0) {
    return {
      component,
      risk: "RISKY",
      reason: `Browsable deep link on custom scheme ${customSchemes.join(", ")} with no permission guard: any web page can invoke it with attacker-controlled data.`,
    };
  }

  if (component.type === "provider") {
    return {
      component,
      risk: "RISKY",
      reason: "Content provider exported with no android:permission, so any installed app can query or write through it.",
    };
  }

  if (component.type === "service" && component.intentFilters.length > 0) {
    const nonStandard = actions.filter((action) => !STANDARD_ACTIONS.has(action));
    if (nonStandard.length > 0) {
      return {
        component,
        risk: "RISKY",
        reason: `Exported service accepting custom action(s) ${nonStandard.slice(0, 3).join(", ")} without a permission guard: any app can bind to or start it.`,
      };
    }
  }

  if (browsable) {
    return {
      component,
      risk: "REVIEW",
      reason: "Browsable web deep link (http/https). Expected for App Links, but incoming URLs must be validated.",
    };
  }

  if (component.intentFilters.length === 0 && component.exportedExplicit) {
    return {
      component,
      risk: "REVIEW",
      reason: 'Explicitly marked android:exported="true" with no intent filter; confirm external access is intentional.',
    };
  }

  if (actions.every((action) => STANDARD_ACTIONS.has(action)) && actions.length > 0) {
    return {
      component,
      risk: "EXPECTED",
      reason: `Handles only standard platform action(s) ${[...new Set(actions)].slice(0, 3).join(", ")}, which must be exported to work.`,
    };
  }

  return {
    component,
    risk: "REVIEW",
    reason: "Exported without a permission guard and not a recognised standard entry point; review the Intent handling.",
  };
}

function isTooling(name: string): boolean {
  return TOOLING_PREFIXES.some((prefix) => name.startsWith(prefix));
}
