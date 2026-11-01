"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { version: packageVersion } = require("../package.json");

const platformTargets = {
  win32: "windows",
  linux: "linux",
  darwin: "darwin",
};

const architectureTargets = {
  x64: "amd64",
  arm64: "arm64",
};

function resolveTarget(platform = process.platform, architecture = process.arch) {
  const goos = platformTargets[platform];
  if (!goos) {
    throw new Error(`AStra does not support operating system ${platform}`);
  }
  const goarch = architectureTargets[architecture];
  if (!goarch) {
    throw new Error(`AStra does not support architecture ${architecture}`);
  }
  return { goos, goarch };
}

function assetName(version, goos, goarch) {
  if (!/^[0-9A-Za-z][0-9A-Za-z.+-]*$/.test(version)) {
    throw new Error(`Invalid AStra package version ${JSON.stringify(version)}`);
  }
  const executableExtension = goos === "windows" ? ".exe" : "";
  return `astra_${version}_${goos}_${goarch}${executableExtension}`;
}

function parseChecksum(checksumText, filename) {
  for (const line of checksumText.split(/\r?\n/)) {
    const match = /^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/.exec(line);
    if (match && match[2] === filename) {
      return match[1].toLowerCase();
    }
    if (line.trimEnd().endsWith(`  ${filename}`) || line.trimEnd().endsWith(` *${filename}`)) {
      throw new Error(`Invalid SHA-256 checksum for release asset ${filename}`);
    }
  }
  throw new Error(`SHA-256 checksum not found for release asset ${filename}`);
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function resolveVersion(version) {
  return version ?? packageVersion;
}

function constantTimeEqual(left, right) {
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && crypto.timingSafeEqual(leftBytes, rightBytes);
}

async function fetchBytes(fetchImpl, url, label) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10 * 60 * 1000);
  process.stderr.write(`Downloading AStra ${label} from GitHub Releases...\n`);
  try {
    let response;
    try {
      response = await fetchImpl(url, { signal: controller.signal });
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error(`Timed out downloading AStra ${label} from ${url} after 10 minutes`, { cause: error });
      }
      throw new Error(`Could not download AStra ${label} from ${url}: ${error.message}`, { cause: error });
    }
    if (!response.ok) {
      throw new Error(`Could not download AStra ${label}: HTTP ${response.status} for ${url}`);
    }
    if (!response.body) {
      return Buffer.from(await response.arrayBuffer());
    }
    const reader = response.body.getReader();
    const chunks = [];
    let downloaded = 0;
    let reported = 0;
    const expected = Number(response.headers.get("content-length")) || 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value));
      downloaded += value.byteLength;
      if (label === "binary" && downloaded - reported >= 1024 * 1024) {
        const progress = expected > 0
          ? `${(downloaded / 1024 / 1024).toFixed(1)}/${(expected / 1024 / 1024).toFixed(1)} MB`
          : `${(downloaded / 1024 / 1024).toFixed(1)} MB`;
        process.stderr.write(`AStra binary download: ${progress}\n`);
        reported = downloaded;
      }
    }
    return Buffer.concat(chunks, downloaded);
  } catch (error) {
    if (error.message.startsWith("Could not download AStra") ||
        error.message.startsWith("Timed out downloading AStra")) {
      throw error;
    }
    if (controller.signal.aborted) {
      throw new Error(`Timed out downloading AStra ${label} from ${url} after 10 minutes`, { cause: error });
    }
    throw new Error(`Could not read AStra ${label} from ${url}: ${error.message}`, { cause: error });
  } finally {
    clearTimeout(timeout);
  }
}

async function ensureBinary(options = {}) {
  const version = options.version;
  if (typeof version !== "string" || !/^[0-9A-Za-z][0-9A-Za-z.+-]*$/.test(version)) {
    throw new Error(`Invalid AStra package version ${JSON.stringify(version)}`);
  }
  const { goos, goarch } = resolveTarget(options.platform, options.arch);
  const filename = assetName(version, goos, goarch);
  const releaseBaseURL = (options.releaseBaseURL ??
    `https://github.com/aayushrajputz/AStra-AI/releases/download/v${version}`).replace(/\/+$/, "");
  const cacheDir = options.cacheDir ??
    path.join(os.homedir(), ".astra", "bin", version);
  const binaryPath = path.join(cacheDir, filename);
  const checksumPath = `${binaryPath}.sha256`;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("AStra launcher requires a Node.js runtime with global fetch support (Node.js 18+)");
  }

  await fs.mkdir(cacheDir, { recursive: true });
  try {
    const [existingBinary, expectedChecksum] = await Promise.all([
      fs.readFile(binaryPath),
      fs.readFile(checksumPath, "utf8"),
    ]);
    if (sha256(existingBinary) === expectedChecksum.trim()) {
      return binaryPath;
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw new Error(`Could not verify cached AStra binary ${binaryPath}: ${error.message}`, { cause: error });
    }
  }

  const checksumText = (await fetchBytes(fetchImpl, `${releaseBaseURL}/checksums.txt`, "checksums")).toString("utf8");
  const expectedChecksum = parseChecksum(checksumText, filename);
  const binary = await fetchBytes(fetchImpl, `${releaseBaseURL}/${filename}`, "binary");
  const actualChecksum = sha256(binary);
  if (!constantTimeEqual(actualChecksum, expectedChecksum)) {
    throw new Error(`SHA-256 checksum mismatch for downloaded AStra binary ${filename}`);
  }

  const temporaryPath = `${binaryPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporaryPath, binary, { flag: "wx", mode: 0o755 });
    if (process.platform !== "win32") {
      await fs.chmod(temporaryPath, 0o755);
    }
    await fs.rm(binaryPath, { force: true });
    await fs.rename(temporaryPath, binaryPath);
    await fs.writeFile(checksumPath, `${expectedChecksum}\n`, { mode: 0o600 });
  } catch (error) {
    await fs.rm(temporaryPath, { force: true });
    throw new Error(`Could not cache verified AStra binary ${binaryPath}: ${error.message}`, { cause: error });
  }
  return binaryPath;
}

async function run(args, options = {}) {
  const binaryPath = await ensureBinary({
    ...options,
    version: resolveVersion(options.version),
  });
  await new Promise((resolve, reject) => {
    const child = spawn(binaryPath, args, { stdio: "inherit", windowsHide: true });
    child.once("error", error => reject(new Error(`Could not start AStra: ${error.message}`, { cause: error })));
    child.once("close", (code, signal) => {
      if (signal) {
        process.exitCode = 1;
      } else {
        process.exitCode = code ?? 1;
      }
      resolve();
    });
  });
}

module.exports = {
  assetName,
  ensureBinary,
  parseChecksum,
  resolveVersion,
  resolveTarget,
  run,
};
