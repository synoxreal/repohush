export const VERSION = "0.2.5";

export const SEVERITY_WEIGHT = Object.freeze({
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

export const DEFAULT_IGNORES = Object.freeze([
  ".git/**",
  "node_modules/**",
  "dist/**",
  "build/**",
  "coverage/**",
  "vendor/**",
  ".next/**",
  ".cache/**",
  "target/**",
  "*.min.js",
  "*.map",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

export const TEXT_EXTENSIONS = new Set([
  "", ".c", ".cc", ".conf", ".config", ".cpp", ".cs", ".css", ".env",
  ".go", ".h", ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx",
  ".kt", ".lock", ".lua", ".md", ".mjs", ".php", ".properties", ".ps1",
  ".py", ".rb", ".rs", ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx",
  ".txt", ".vue", ".xml", ".yaml", ".yml", ".zsh",
]);

export const AGENT_CONFIG_NAMES = new Set([
  ".mcp.json",
  "mcp.json",
  "settings.json",
  "config.toml",
  "agents.md",
  "claude.md",
]);
