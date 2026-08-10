import fs from "node:fs";
import { scan, shouldFail } from "./scanner.js";
import { formatPretty } from "./formatters.js";

function emit(name, value) {
  process.stdout.write(`::${name}::${String(value).replace(/\r?\n/g, "%0A")}\n`);
}

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`, "utf8");
  }
}

try {
  const root = process.env.INPUT_PATH || process.env.GITHUB_WORKSPACE || process.cwd();
  const threshold = (process.env.INPUT_FAIL_ON || "high").toLowerCase();
  const report = await scan({ root });
  process.stdout.write(`${formatPretty(report, { colors: false })}\n`);
  setOutput("findings", report.findings.length);
  setOutput("critical", report.counts.critical);
  setOutput("high", report.counts.high);
  if (shouldFail(report, threshold)) {
    emit("error", `RepoHush found ${report.findings.length} issue(s) at or above ${threshold}.`);
    process.exitCode = 1;
  }
} catch (error) {
  emit("error", error.message);
  process.exitCode = 2;
}
