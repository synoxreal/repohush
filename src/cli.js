#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { VERSION } from "./constants.js";
import { formatJson, formatPretty, formatSarif } from "./formatters.js";
import { scan, shouldFail } from "./scanner.js";

const HELP = `RepoHush ${VERSION}

Local-first security scanner for AI coding agent repositories.

Usage:
  repohush scan [path] [options]
  repohush init [path]
  repohush --version

Options:
  --format <pretty|json|sarif>  Output format (default: pretty)
  --output <file>               Write the report to a file
  --fail-on <severity>          Exit 1 at critical, high, medium, or low (default: high)
  --exclude <glob>              Exclude a path; repeatable
  --no-fail                     Always exit successfully after scanning
  --no-color                    Disable ANSI colors
  -h, --help                    Show this help
`;

function parseArguments(argv) {
  const result = {
    command: "scan",
    root: ".",
    format: "pretty",
    threshold: "high",
    excludes: [],
    noFail: false,
    noColor: false,
    output: null,
  };
  const args = [...argv];
  if (args[0] === "scan" || args[0] === "init") result.command = args.shift();
  if (args[0] && !args[0].startsWith("-")) result.root = args.shift();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    const next = () => {
      const value = args[index + 1];
      if (!value || value.startsWith("-")) throw new Error(`${argument} requires a value`);
      index += 1;
      return value;
    };
    if (argument === "--format") result.format = next();
    else if (argument === "--output") result.output = next();
    else if (argument === "--fail-on") result.threshold = next().toLowerCase();
    else if (argument === "--exclude") result.excludes.push(next());
    else if (argument === "--no-fail") result.noFail = true;
    else if (argument === "--no-color") result.noColor = true;
    else if (argument === "--version" || argument === "-v") result.version = true;
    else if (argument === "--help" || argument === "-h") result.help = true;
    else throw new Error(`Unknown option: ${argument}`);
  }
  return result;
}

async function initialize(root) {
  const target = path.resolve(root);
  await fs.mkdir(target, { recursive: true });
  const ignorePath = path.join(target, ".repohushignore");
  try {
    await fs.writeFile(ignorePath, "# Test fixtures and generated files\nfixtures/**\ndist/**\n", { flag: "wx" });
    process.stdout.write(`Created ${ignorePath}\n`);
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`${ignorePath} already exists`);
    throw error;
  }
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
    if (options.version) {
      process.stdout.write(`${VERSION}\n`);
      return;
    }
    if (options.help) {
      process.stdout.write(HELP);
      return;
    }
    if (options.command === "init") {
      await initialize(options.root);
      return;
    }
    if (!new Set(["pretty", "json", "sarif"]).has(options.format)) {
      throw new Error(`Unknown output format: ${options.format}`);
    }
    const report = await scan({ root: options.root, exclude: options.excludes });
    const rendered = options.format === "json"
      ? formatJson(report)
      : options.format === "sarif"
        ? formatSarif(report)
        : formatPretty(report, { colors: !options.noColor });
    if (options.output) {
      await fs.writeFile(path.resolve(options.output), `${rendered}\n`, "utf8");
    } else {
      process.stdout.write(`${rendered}\n`);
    }
    if (!options.noFail && shouldFail(report, options.threshold)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`repohush: ${error.message}\n`);
    process.exitCode = 2;
  }
}

await main();
