import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "astra-action-dry-run-"));
try {
  const reportPath = path.join(directory, "report.json");
  const eventPath = path.join(directory, "event.json");
  const outputPath = path.join(directory, "output.txt");
  const errorPath = path.join(directory, "error.txt");
  fs.writeFileSync(reportPath, JSON.stringify({
    status: "fail",
    changed_files: 1,
    routes: [{ path: "/transfer" }],
    affected_routes: [{
      route: { method: "POST", path: "/transfer" },
      severity: "breaking",
      confidence: "exact",
      resolution: "unresolved",
      reason: "required argument added",
      chain: ["transfer", "service.move"],
      call_sites: [{ file: "internal/caller.go", line: 42 }],
    }],
    violations: ["POST /transfer: required argument added"],
    needs_review: [],
    active_waivers: [{
      route: "POST /transfer",
      reason: "temporary migration",
      owner: "payments",
      expires: "2099-12-31",
    }],
    warnings: [],
  }));
  fs.writeFileSync(errorPath, "");

  for (const [fork, expectedComment] of [[false, "true"], [true, "false"]]) {
    fs.writeFileSync(eventPath, JSON.stringify({
      pull_request: { head: { repo: { fork } } },
    }));
    fs.writeFileSync(outputPath, "");
    const result = spawnSync(process.execPath, [
      ".github/actions/astra-check/report.mjs",
      reportPath,
      eventPath,
      outputPath,
      "1",
      "true",
      errorPath,
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const output = fs.readFileSync(outputPath, "utf8");
    assert.match(output, /status=fail/);
    assert.match(output, new RegExp(`comment=${expectedComment}`));
    assert.match(output, /POST \| \/transfer/);
    assert.match(output, /unresolved/);
    assert.match(output, /internal\/caller\.go:42/);
    assert.match(output, /temporary migration/);
  }

  for (const [failOnError, expectedStatus] of [["true", "fail"], ["false", "pass"]]) {
    fs.writeFileSync(outputPath, "");
    const result = spawnSync(process.execPath, [
      ".github/actions/astra-check/report.mjs",
      reportPath,
      eventPath,
      outputPath,
      "2",
      failOnError,
      errorPath,
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const output = fs.readFileSync(outputPath, "utf8");
    assert.match(output, new RegExp(`status=${expectedStatus}`));
    assert.match(output, /tool_error=true/);
  }
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
