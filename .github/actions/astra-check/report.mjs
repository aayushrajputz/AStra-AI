import fs from "node:fs";
import crypto from "node:crypto";

const [reportPath, eventPath, outputPath, cliExitCode, failOnError, errorPath] =
  process.argv.slice(2);
const errorCode = Number(cliExitCode);
let report;

try {
  report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  if (!["pass", "fail"].includes(report.status)) {
    throw new Error("AStra JSON report has no valid gate status");
  }
  if (errorCode === 2 || (errorCode === 0 && report.status === "fail") ||
      (errorCode === 1 && report.status !== "fail")) {
    throw new Error("AStra exit code did not match its gate report");
  }
} catch (error) {
  if (errorCode !== 2) throw error;
  const detail = fs.existsSync(errorPath) ? fs.readFileSync(errorPath, "utf8").trim() : "";
  report = {
    status: failOnError === "true" ? "fail" : "pass",
    changed_files: 0,
    routes: [],
    affected_routes: [],
    violations: failOnError === "true" ? ["AStra tool error; the gate failed closed."] : [],
    needs_review: [],
    active_waivers: [],
    warnings: [{ file: "AStra", line: 0, message: detail || String(error) }],
  };
}

fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));
const commentEnabled = event.pull_request?.head?.repo?.fork === false;
const escapeCell = value =>
  String(value ?? "").replaceAll("|", "\\|").replaceAll("\n", " ").slice(0, 160);
const impacts = report.affected_routes ?? [];
const rows = impacts.slice(0, 50).map(impact => {
  const route = impact.route ?? {};
  const chain = (impact.chain ?? []).join(" → ");
  const callers = (impact.call_sites ?? [])
    .map(site => `${site.file}:${site.line}`).join(", ");
  return `| ${escapeCell(route.method)} | ${escapeCell(route.path)} | ${escapeCell(impact.severity)} | ${escapeCell(impact.confidence)} | ${escapeCell(impact.resolution || "needs review")} | ${escapeCell(impact.reason)} | ${escapeCell(chain)} | ${escapeCell(callers)} |`;
});
const body = [
  "<!-- astra-route-impact-report -->",
  `## AStra merge gate: ${report.status.toUpperCase()}`,
  "",
  `Analyzed ${report.changed_files ?? 0} changed file(s); ${(report.routes ?? []).length} route(s) indexed.`,
  "",
  "| Method | Route | Severity | Confidence | Resolution | Finding | Call chain | Incompatible callers |",
  "|---|---|---|---|---|---|---|---|",
  ...(rows.length ? rows : ["| — | — | — | — | — | No affected routes detected. | — | — |"]),
  ...(impacts.length > rows.length ? ["", `Showing ${rows.length} of ${impacts.length} findings.`] : []),
  "",
  ...(report.violations?.length
    ? ["### Gate violations", ...report.violations.map(item => `- ${escapeCell(item)}`), ""] : []),
  ...(report.needs_review?.length
    ? ["### Needs review", ...report.needs_review.map(item => `- ${escapeCell(item)}`), ""] : []),
  ...(report.active_waivers?.length
    ? ["### Active waivers", ...report.active_waivers.map(waiver =>
      `- ${escapeCell(waiver.symbol || waiver.route)} — ${escapeCell(waiver.reason)} (owner: ${escapeCell(waiver.owner)}, expires: ${escapeCell(waiver.expires)})`), ""] : []),
  ...(report.warnings?.length
    ? ["### Warnings", ...report.warnings.map(warning =>
      `- \`${escapeCell(warning.file)}:${warning.line}\`: ${escapeCell(warning.message)}`), ""] : []),
  "_Heuristic and dynamic findings are informational and should be reviewed._",
].join("\n");
const delimiter = `ASTRA_${crypto.randomUUID().replaceAll("-", "")}`;
const output = [
  `status=${report.status}`,
  `report=${reportPath}`,
  `comment=${commentEnabled}`,
  `tool_error=${errorCode === 2}`,
  `comment_body<<${delimiter}`,
  body,
  delimiter,
  "",
].join("\n");
fs.appendFileSync(outputPath, output);
