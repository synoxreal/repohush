import path from "node:path";

export function normalizePath(value) {
  return value.split(path.sep).join("/").replace(/^\.\//, "");
}

export function globToRegExp(glob) {
  let source = "";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    if (char === "*" && glob[index + 1] === "*") {
      source += ".*";
      index += 1;
    } else if (char === "*") {
      source += "[^/]*";
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += char.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
    }
  }
  return new RegExp(`^(?:${source})(?:/.*)?$`, "i");
}

export function createMatcher(patterns) {
  const expressions = patterns
    .map((pattern) => pattern.trim())
    .filter((pattern) => pattern && !pattern.startsWith("#"))
    .map(globToRegExp);
  return (relativePath) => expressions.some((expression) => expression.test(relativePath));
}

export function redact(value) {
  const compact = String(value).trim();
  if (compact.length <= 8) return "[REDACTED]";
  return `${compact.slice(0, 4)}…${compact.slice(-4)}`;
}

export function lineAt(content, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) {
    if (content.charCodeAt(index) === 10) line += 1;
  }
  return line;
}

export function fingerprint(finding) {
  const input = `${finding.ruleId}:${finding.path}:${finding.line}:${finding.message}`;
  let hash = 2166136261;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}
