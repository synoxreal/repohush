import fs from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORES, SEVERITY_WEIGHT, TEXT_EXTENSIONS } from "./constants.js";
import { inspectContent, inspectFileName } from "./rules.js";
import { createMatcher, fingerprint, normalizePath } from "./utils.js";

const DEFAULT_MAX_FILE_SIZE = 1024 * 1024;
const DEFAULT_CONCURRENCY = 16;

async function readIgnoreFile(root) {
  try {
    return (await fs.readFile(path.join(root, ".repohushignore"), "utf8")).split(/\r?\n/);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function collectFiles(root, matcher) {
  const files = [];
  const directories = [root];
  while (directories.length > 0) {
    const current = directories.pop();
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(current, entry.name);
      const relative = normalizePath(path.relative(root, absolute));
      if (matcher(relative)) continue;
      if (entry.isDirectory()) directories.push(absolute);
      else if (entry.isFile()) files.push({ absolute, relative });
    }
  }
  return files;
}

async function isTextFile(file, handle) {
  const extension = path.extname(file.relative).toLowerCase();
  if (!TEXT_EXTENSIONS.has(extension) && !file.relative.includes(".")) return false;
  const probe = Buffer.allocUnsafe(512);
  const { bytesRead } = await handle.read(probe, 0, probe.length, 0);
  for (let index = 0; index < bytesRead; index += 1) {
    if (probe[index] === 0) return false;
  }
  return true;
}

async function inspectOne(file, maxFileSize) {
  const nameFindings = inspectFileName(file.relative);
  const stats = await fs.stat(file.absolute);
  if (stats.size === 0 || stats.size > maxFileSize) return nameFindings;
  const handle = await fs.open(file.absolute, "r");
  try {
    if (!(await isTextFile(file, handle))) return nameFindings;
  } finally {
    await handle.close();
  }
  const content = await fs.readFile(file.absolute, "utf8");
  return [...nameFindings, ...inspectContent(file.relative, content)];
}

async function mapConcurrent(items, concurrency, operation) {
  const result = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      result[index] = await operation(items[index]);
    }
  }
  const count = Math.min(concurrency, Math.max(items.length, 1));
  await Promise.all(Array.from({ length: count }, worker));
  return result;
}

export async function scan(options = {}) {
  const startedAt = performance.now();
  const root = path.resolve(options.root ?? process.cwd());
  const rootStats = await fs.stat(root);
  if (!rootStats.isDirectory()) throw new Error(`Scan target is not a directory: ${root}`);

  const customIgnores = await readIgnoreFile(root);
  const matcher = createMatcher([
    ...DEFAULT_IGNORES,
    ...customIgnores,
    ...(options.exclude ?? []),
  ]);
  const files = await collectFiles(root, matcher);
  const groups = await mapConcurrent(
    files,
    options.concurrency ?? DEFAULT_CONCURRENCY,
    (file) => inspectOne(file, options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE),
  );
  const findings = groups.flat()
    .map((item) => ({ ...item, fingerprint: fingerprint(item) }))
    .sort((left, right) => (
      SEVERITY_WEIGHT[right.severity] - SEVERITY_WEIGHT[left.severity]
      || left.path.localeCompare(right.path)
      || left.line - right.line
    ));

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) counts[item.severity] += 1;
  return {
    root,
    filesScanned: files.length,
    durationMs: Math.round((performance.now() - startedAt) * 100) / 100,
    counts,
    findings,
  };
}

export function shouldFail(report, threshold = "high") {
  const minimum = SEVERITY_WEIGHT[threshold];
  if (!minimum) throw new Error(`Unknown severity threshold: ${threshold}`);
  return report.findings.some((finding) => SEVERITY_WEIGHT[finding.severity] >= minimum);
}
