"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  assetName,
  ensureBinary,
  parseChecksum,
  resolveVersion,
  resolveTarget,
} = require("../lib/launcher.js");

test("defaults the launcher to its published package version", () => {
  assert.equal(resolveVersion(undefined), require("../package.json").version);
  assert.equal(resolveVersion("9.8.7"), "9.8.7");
});

test("maps supported Node platforms to Go release targets", () => {
  assert.deepEqual(resolveTarget("win32", "x64"), { goos: "windows", goarch: "amd64" });
  assert.deepEqual(resolveTarget("darwin", "arm64"), { goos: "darwin", goarch: "arm64" });
  assert.deepEqual(resolveTarget("linux", "arm64"), { goos: "linux", goarch: "arm64" });
  assert.throws(() => resolveTarget("freebsd", "x64"), /does not support operating system/i);
  assert.throws(() => resolveTarget("linux", "ia32"), /does not support architecture/i);
});

test("names raw GoReleaser assets consistently", () => {
  assert.equal(assetName("0.1.0", "linux", "amd64"), "astra_0.1.0_linux_amd64");
  assert.equal(assetName("0.1.0", "windows", "amd64"), "astra_0.1.0_windows_amd64.exe");
});

test("parses the exact checksum record and rejects missing assets", () => {
  const checksum = "ab".repeat(32);
  assert.equal(parseChecksum(`${checksum}  astra_1.2.3_linux_amd64\n${"cd".repeat(32)}  astra_1.2.3_darwin_arm64\n`,
    "astra_1.2.3_linux_amd64"), checksum);
  assert.throws(() => parseChecksum(`${checksum}  unrelated\n`, "astra_1.2.3_linux_amd64"),
    /checksum.*not found/i);
  assert.throws(() => parseChecksum("invalid checksum  asset\n", "asset"), /invalid sha-256 checksum/i);
});

test("downloads a matching binary, verifies SHA-256, then reuses cache", async t => {
  const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), "astra-package-cache-"));
  t.after(() => fs.rm(cacheDir, { recursive: true, force: true }));
  const payload = Buffer.from("fake astra release binary");
  const digest = crypto.createHash("sha256").update(payload).digest("hex");
  const expectedAsset = "astra_0.1.0_linux_amd64";
  let requests = 0;
  const fetchImpl = async url => {
    requests++;
    if (url.endsWith("/checksums.txt")) {
      return new Response(`${digest}  ${expectedAsset}\n`, { status: 200 });
    }
    if (url.endsWith(`/${expectedAsset}`)) {
      return new Response(payload, { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
  const options = {
    version: "0.1.0", platform: "linux", arch: "x64",
    cacheDir, releaseBaseURL: "https://release.example/v0.1.0", fetchImpl,
  };
  const first = await ensureBinary(options);
  assert.deepEqual(await fs.readFile(first), payload);
  if (process.platform !== "win32") {
    assert.equal((await fs.stat(first)).mode & 0o111, 0o111);
  }
  const second = await ensureBinary(options);
  assert.equal(second, first);
  assert.equal(requests, 2, "cached executable should not trigger another download");
});

test("streams large release downloads and reports progress", async t => {
  const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), "astra-package-progress-"));
  t.after(() => fs.rm(cacheDir, { recursive: true, force: true }));
  const payload = Buffer.alloc(2 * 1024 * 1024, 7);
  const digest = crypto.createHash("sha256").update(payload).digest("hex");
  const expectedAsset = "astra_0.1.0_linux_amd64";
  const originalWrite = process.stderr.write;
  let progressOutput = "";
  process.stderr.write = chunk => {
    progressOutput += String(chunk);
    return true;
  };
  try {
    const binaryPath = await ensureBinary({
      version: "0.1.0", platform: "linux", arch: "x64", cacheDir,
      releaseBaseURL: "https://release.example/v0.1.0",
      fetchImpl: async url => url.endsWith("/checksums.txt")
        ? new Response(`${digest}  ${expectedAsset}\n`)
        : new Response(payload, { headers: { "content-length": String(payload.length) } }),
    });
    assert.deepEqual(await fs.readFile(binaryPath), payload);
    assert.match(progressOutput, /AStra binary download: 2\.0\/2\.0 MB/);
  } finally {
    process.stderr.write = originalWrite;
  }
});

test("rejects a downloaded binary with a mismatching checksum", async t => {
  const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), "astra-package-bad-checksum-"));
  t.after(() => fs.rm(cacheDir, { recursive: true, force: true }));
  const payload = Buffer.from("tampered binary");
  const fetchImpl = async url => {
    if (url.endsWith("/checksums.txt")) {
      return new Response(`${"0".repeat(64)}  astra_0.1.0_linux_amd64\n`, { status: 200 });
    }
    return new Response(payload, { status: 200 });
  };
  await assert.rejects(ensureBinary({
    version: "0.1.0", platform: "linux", arch: "x64",
    cacheDir, releaseBaseURL: "https://release.example/v0.1.0", fetchImpl,
  }), /checksum mismatch/i);
  assert.deepEqual(await fs.readdir(cacheDir), []);
});
