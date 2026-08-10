import fs from "node:fs/promises";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const source = path.join(root, "src");
const destination = path.join(root, "dist");
const packageData = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));

await fs.rm(destination, { recursive: true, force: true });
await fs.mkdir(destination, { recursive: true });
const files = await fs.readdir(source);
for (const file of files) {
  if (!file.endsWith(".js")) continue;
  let content = await fs.readFile(path.join(source, file), "utf8");
  if (file === "constants.js") {
    content = content.replace(/VERSION = "[^"]+"/, `VERSION = "${packageData.version}"`);
  }
  await fs.writeFile(path.join(destination, file), content, "utf8");
}
await fs.chmod(path.join(destination, "cli.js"), 0o755);
process.stdout.write(`RepoHush v${packageData.version} built (${files.filter((file) => file.endsWith(".js")).length} modules).\n`);
