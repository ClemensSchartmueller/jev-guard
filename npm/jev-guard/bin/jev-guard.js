#!/usr/bin/env node
'use strict';

const { createHash } = require('node:crypto');
const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { version } = require('../package.json');

const RELEASES = 'https://github.com/ClemensSchartmueller/jev-guard/releases/download';
const MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024;

function assetName(platform = process.platform, arch = process.arch) {
  const osName = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[platform];
  const cpu = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!osName || !cpu || (platform === 'win32' && arch !== 'x64')) {
    throw new Error(`Unsupported platform: ${platform}/${arch}. Use a source build for this platform.`);
  }
  return `jev-guard-${osName}-${cpu}${platform === 'win32' ? '.exe' : ''}`;
}

function expectedDigest(checksums, filename) {
  const line = checksums.split(/\r?\n/).find((entry) => entry.endsWith(`  ${filename}`) || entry.endsWith(` *${filename}`));
  const digest = line && /^([a-fA-F0-9]{64})\s+[*]?\S+$/.exec(line)?.[1];
  if (!digest) throw new Error(`No SHA256 checksum for ${filename} in release checksums.txt`);
  return digest.toLowerCase();
}

async function download(url, fetchImpl = fetch) {
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error(`Download failed (${response.status}): ${url}`);
  if (!response.body) throw new Error(`Empty response: ${url}`);
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > MAX_DOWNLOAD_BYTES) throw new Error(`Download exceeds ${MAX_DOWNLOAD_BYTES} bytes: ${url}`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function install({ platform = process.platform, arch = process.arch, home = os.homedir(), fetchImpl = fetch } = {}) {
  const filename = assetName(platform, arch);
  const base = `${RELEASES}/v${version}`;
  const checksums = (await download(`${base}/checksums.txt`, fetchImpl)).toString('utf8');
  const expected = expectedDigest(checksums, filename);
  const installDir = path.join(home, '.jevguard', 'bin');
  const target = path.join(installDir, platform === 'win32' ? 'jev-guard.exe' : 'jev-guard');

  // A repeat invocation checks the release checksum, but avoids a binary download.
  try {
    const existing = await fs.readFile(target);
    if (createHash('sha256').update(existing).digest('hex') === expected) return target;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const binary = await download(`${base}/${filename}`, fetchImpl);
  if (createHash('sha256').update(binary).digest('hex') !== expected) {
    throw new Error(`SHA256 mismatch for ${filename}; existing installation was kept`);
  }

  await fs.mkdir(installDir, { recursive: true });
  const staged = path.join(installDir, `.${path.basename(target)}-${process.pid}-${Date.now()}.tmp`);
  try {
    await fs.writeFile(staged, binary, { mode: 0o755, flag: 'wx' });
    if (platform !== 'win32') await fs.chmod(staged, 0o755);
    await fs.rename(staged, target);
  } finally {
    await fs.rm(staged, { force: true });
  }
  return target;
}

async function main(args = process.argv.slice(2)) {
  const binary = await install();
  const child = spawn(binary, ['init', ...args], { stdio: 'inherit' });
  child.on('error', (error) => {
    console.error(`jev-guard: ${error.message}`);
    process.exitCode = 1;
  });
  child.on('exit', (code, signal) => {
    process.exitCode = code ?? (signal ? 1 : 0);
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`jev-guard: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { assetName, expectedDigest, install };
