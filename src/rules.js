import path from "node:path";
import { AGENT_CONFIG_NAMES } from "./constants.js";
import { lineAt, redact } from "./utils.js";

const SECRET_RULES = Object.freeze([
  {
    id: "RH101",
    title: "Private key",
    severity: "critical",
    expression: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    message: () => "Private key material is stored in the repository.",
  },
  {
    id: "RH102",
    title: "AWS access key",
    severity: "critical",
    expression: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    message: (value) => `Possible AWS access key ${redact(value)} detected.`,
  },
  {
    id: "RH103",
    title: "GitHub token",
    severity: "critical",
    expression: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b/g,
    message: (value) => `Possible GitHub token ${redact(value)} detected.`,
  },
  {
    id: "RH104",
    title: "OpenAI API key",
    severity: "critical",
    expression: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g,
    message: (value) => `Possible OpenAI API key ${redact(value)} detected.`,
  },
  {
    id: "RH105",
    title: "Slack token",
    severity: "critical",
    expression: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    message: (value) => `Possible Slack token ${redact(value)} detected.`,
  },
  {
    id: "RH106",
    title: "Stripe secret key",
    severity: "critical",
    expression: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    message: (value) => `Possible Stripe secret key ${redact(value)} detected.`,
  },
  {
    id: "RH107",
    title: "Google API key",
    severity: "high",
    expression: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    message: (value) => `Possible Google API key ${redact(value)} detected.`,
  },
  {
    id: "RH108",
    title: "Hardcoded credential",
    severity: "high",
    expression: /\b(?:api[_-]?key|secret|password|passwd|access[_-]?token)\s*[:=]\s*["']([^"'\r\n]{12,})["']/gi,
    validate: (match) => !/^(?:example|sample|test|dummy|changeme|your[_-]|\$\{|process\.env)/i.test(match[1]),
    message: (value, match) => `Possible hardcoded credential ${redact(match[1])} detected.`,
  },
]);

const DANGEROUS_CONFIG_RULES = Object.freeze([
  {
    id: "RH201",
    title: "Sandbox disabled",
    severity: "critical",
    expression: /(?:dangerouslyDisableSandbox|disable[_-]?sandbox|sandbox_mode\s*=\s*["']?danger-full-access|--dangerously-bypass-approvals-and-sandbox)/gi,
    message: "Agent configuration appears to disable sandbox protections.",
  },
  {
    id: "RH202",
    title: "Permission checks bypassed",
    severity: "critical",
    expression: /(?:bypassPermissions|skip[_-]?permissions|--dangerously-skip-permissions|approval_policy\s*=\s*["']?never)/gi,
    message: "Agent configuration appears to bypass permission checks.",
  },
  {
    id: "RH203",
    title: "Remote script execution",
    severity: "critical",
    expression: /(?:curl|wget)(?:[^\r\n|;&]{0,300})(?:\||%7C)\s*(?:ba)?sh\b/gi,
    message: "Configuration downloads and directly executes a remote script.",
  },
  {
    id: "RH204",
    title: "Encoded PowerShell command",
    severity: "high",
    expression: /powershell(?:\.exe)?[^\r\n]{0,200}-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}/gi,
    message: "Configuration contains an encoded PowerShell command.",
  },
  {
    id: "RH205",
    title: "Destructive recursive command",
    severity: "critical",
    expression: /(?:rm\s+-[a-z]*r[a-z]*f|Remove-Item[^\r\n]{0,100}-Recurse[^\r\n]{0,100}-Force)\s+(?:\/|~|\$HOME|%USERPROFILE%)/gi,
    message: "Configuration contains a destructive command targeting a broad path.",
  },
  {
    id: "RH206",
    title: "Wildcard tool permission",
    severity: "high",
    expression: /["'](?:allow|permissions)["']\s*:\s*\[\s*["']\*["']\s*\]/gi,
    message: "Agent configuration grants a wildcard permission.",
  },
]);

const INSTRUCTION_RULES = Object.freeze([
  {
    id: "RH301",
    title: "Sensitive file instruction",
    severity: "high",
    expression: /(?:read|open|print|upload|send|exfiltrat\w*)[^\r\n]{0,100}(?:\.env|private key|credentials?|secrets?)/gi,
    message: "Agent instructions request access to potentially sensitive material.",
  },
  {
    id: "RH302",
    title: "Security override instruction",
    severity: "high",
    expression: /(?:ignore|override|bypass|disable)[^\r\n]{0,80}(?:security|safety|sandbox|approval|permission)/gi,
    message: "Agent instructions appear to override a security boundary.",
  },
]);

function finding(rule, relativePath, content, index, evidence = "") {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    path: relativePath,
    line: lineAt(content, index),
    message: typeof rule.message === "function" ? rule.message(evidence.value, evidence.match) : rule.message,
  };
}

function runRules(rules, relativePath, content) {
  const findings = [];
  for (const rule of rules) {
    rule.expression.lastIndex = 0;
    let match;
    while ((match = rule.expression.exec(content)) !== null) {
      if (!rule.validate || rule.validate(match)) {
        findings.push(finding(rule, relativePath, content, match.index, { value: match[0], match }));
      }
      if (match[0].length === 0) rule.expression.lastIndex += 1;
    }
  }
  return findings;
}

export function inspectFileName(relativePath) {
  const name = path.basename(relativePath).toLowerCase();
  const findings = [];
  const secretFile = name === ".env" || /^\.env\.(?!example|sample|template)/i.test(name);
  const keyFile = /^(?:id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:p12|pfx|key|pem))$/i.test(name);

  if (secretFile) {
    findings.push({
      ruleId: "RH001",
      title: "Sensitive environment file",
      severity: "high",
      path: relativePath,
      line: 1,
      message: "Environment file may expose credentials to source control or coding agents.",
    });
  }
  if (keyFile && !/public|pub\./i.test(name)) {
    findings.push({
      ruleId: "RH002",
      title: "Sensitive key file",
      severity: "critical",
      path: relativePath,
      line: 1,
      message: "Private key or certificate bundle is present in the scanned tree.",
    });
  }
  return findings;
}

export function inspectContent(relativePath, content) {
  const name = path.basename(relativePath).toLowerCase();
  const normalized = relativePath.toLowerCase();
  const isAgentConfig = AGENT_CONFIG_NAMES.has(name)
    || normalized.includes("/.cursor/")
    || normalized.includes("/.claude/")
    || normalized.includes("/.codex/");
  const isInstructions = name === "agents.md" || name === "claude.md";

  return [
    ...runRules(SECRET_RULES, relativePath, content),
    ...(isAgentConfig ? runRules(DANGEROUS_CONFIG_RULES, relativePath, content) : []),
    ...(isInstructions ? runRules(INSTRUCTION_RULES, relativePath, content) : []),
  ];
}

export const RULE_METADATA = Object.freeze(
  [...SECRET_RULES, ...DANGEROUS_CONFIG_RULES, ...INSTRUCTION_RULES].reduce((result, rule) => {
    result[rule.id] = { id: rule.id, name: rule.title, severity: rule.severity };
    return result;
  }, {
    RH001: { id: "RH001", name: "Sensitive environment file", severity: "high" },
    RH002: { id: "RH002", name: "Sensitive key file", severity: "critical" },
  }),
);
