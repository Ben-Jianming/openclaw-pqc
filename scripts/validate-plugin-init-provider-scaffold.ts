import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runPluginsInitCommand } from "../src/cli/plugins-authoring-command.js";
import { resolveNpmRunner } from "./npm-runner.mjs";

type InspectorReport = {
  status?: unknown;
  summary?: {
    breakageCount?: unknown;
    warningCount?: unknown;
    issueCount?: unknown;
  };
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const artifactRoot = path.resolve(
  process.env.OPENCLAW_PLUGIN_INIT_VALIDATE_ROOT ?? ".artifacts/plugin-init-provider-scaffold",
);
const projectDir = path.join(artifactRoot, "plugin-init-test");
const reportPath = path.join(projectDir, ".clawhub-validation", "plugin-inspector-report.json");

function run(command: string, args: string[], cwd: string): void {
  console.log(`$ ${[command, ...args].join(" ")}`);
  const invocation =
    command === "npm" ? resolveNpmRunner({ npmArgs: args }) : { command, args, shell: false };
  const result = spawnSync(invocation.command, invocation.args, {
    ...invocation,
    cwd,
    env: "env" in invocation ? invocation.env : process.env,
    stdio: "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with status ${result.status}`);
  }
}

function readInspectorReport(): InspectorReport {
  if (!fs.existsSync(reportPath)) {
    throw new Error(`ClawHub validation report not found: ${reportPath}`);
  }
  return JSON.parse(fs.readFileSync(reportPath, "utf8")) as InspectorReport;
}

function assertCleanInspectorReport(report: InspectorReport): void {
  const breakageCount = Number(report.summary?.breakageCount ?? Number.NaN);
  const warningCount = Number(report.summary?.warningCount ?? Number.NaN);
  const issueCount = Number(report.summary?.issueCount ?? Number.NaN);
  if (report.status !== "pass" || breakageCount !== 0 || warningCount !== 0 || issueCount !== 0) {
    throw new Error(
      `Plugin Inspector was not clean: status=${String(
        report.status,
      )}, breakages=${breakageCount}, warnings=${warningCount}, issues=${issueCount}`,
    );
  }
}

fs.rmSync(projectDir, { force: true, recursive: true });
fs.mkdirSync(artifactRoot, { recursive: true });

await runPluginsInitCommand("plugin-init-test", {
  directory: projectDir,
  name: "Plugin Init Test",
  type: "provider",
});

// Build the checkout package so registry latest cannot hide a fork SDK regression.
const tarballPath = path.join(artifactRoot, "openclaw-under-test.tgz");
run(
  process.execPath,
  [
    path.join(repoRoot, "scripts/package-openclaw-for-docker.mjs"),
    "--allow-unreleased-changelog",
    "--output-dir",
    artifactRoot,
    "--output-name",
    path.basename(tarballPath),
  ],
  repoRoot,
);
const manifestPath = path.join(projectDir, "package.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
manifest.devDependencies.openclaw = "file:" + tarballPath.replaceAll("\\", "/");
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
run("npm", ["install", "--no-audit", "--fund=false"], projectDir);
run("npm", ["run", "build"], projectDir);
run("npm", ["test"], projectDir);
run("npm", ["run", "validate"], projectDir);
assertCleanInspectorReport(readInspectorReport());

console.log(`Generated provider scaffold passed ClawHub validation: ${projectDir}`);
