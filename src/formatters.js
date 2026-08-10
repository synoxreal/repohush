import path from "node:path";
import { RULE_METADATA } from "./rules.js";
import { VERSION } from "./constants.js";

const COLOR = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  red: "\u001b[31m",
  yellow: "\u001b[33m",
  cyan: "\u001b[36m",
  green: "\u001b[32m",
};

function paint(value, color, enabled) {
  return enabled ? `${COLOR[color]}${value}${COLOR.reset}` : value;
}

export function formatPretty(report, options = {}) {
  const colors = options.colors ?? Boolean(process.stdout.isTTY && !process.env.NO_COLOR);
  const output = [];
  output.push(paint("RepoHush", "bold", colors));
  output.push(paint(`Scanned ${report.filesScanned} files in ${report.durationMs}ms`, "dim", colors));
  if (report.findings.length === 0) {
    output.push(paint("✓ No findings", "green", colors));
    return output.join("\n");
  }
  output.push("");
  for (const finding of report.findings) {
    const color = finding.severity === "critical" || finding.severity === "high" ? "red" : "yellow";
    const location = `${finding.path}:${finding.line}`;
    output.push(`${paint(finding.severity.toUpperCase().padEnd(8), color, colors)} ${paint(finding.ruleId, "cyan", colors)} ${location}`);
    output.push(`         ${finding.message}`);
  }
  output.push("");
  output.push(
    `${report.findings.length} finding(s): `
    + `${report.counts.critical} critical, ${report.counts.high} high, `
    + `${report.counts.medium} medium, ${report.counts.low} low`,
  );
  return output.join("\n");
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

export function formatSarif(report) {
  const usedRuleIds = new Set(report.findings.map((finding) => finding.ruleId));
  const rules = [...usedRuleIds].map((id) => {
    const rule = RULE_METADATA[id];
    return {
      id,
      name: rule.name.replace(/\s+/g, ""),
      shortDescription: { text: rule.name },
      defaultConfiguration: {
        level: rule.severity === "critical" || rule.severity === "high" ? "error" : "warning",
      },
    };
  });
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "RepoHush",
          version: VERSION,
          informationUri: "https://github.com/synoxreal/repohush",
          rules,
        },
      },
      results: report.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: finding.severity === "critical" || finding.severity === "high" ? "error" : "warning",
        message: { text: finding.message },
        partialFingerprints: { repoHushFingerprint: finding.fingerprint },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.path.split(path.sep).join("/") },
            region: { startLine: finding.line },
          },
        }],
      })),
    }],
  };
  return JSON.stringify(sarif, null, 2);
}
