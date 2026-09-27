'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { assetName, expectedDigest, install } = require('../bin/jev-guard');

test('maps supported release assets and rejects unsupported platforms', () => {
  assert.equal(assetName('linux', 'x64'), 'jev-guard-linux-amd64');
  assert.equal(assetName('darwin', 'arm64'), 'jev-guard-darwin-arm64');
  assert.equal(assetName('win32', 'x64'), 'jev-guard-windows-amd64.exe');
  assert.throws(() => assetName('win32', 'arm64'), /Unsupported platform/);
});

test('selects the exact checksum entry', () => {
  const digest = 'a'.repeat(64);
  assert.equal(expectedDigest(`${digest}  jev-guard-linux-amd64\n`, 'jev-guard-linux-amd64'), digest);
  assert.throws(() => expectedDigest(`${digest}  jev-guard-linux-amd64.extra\n`, 'jev-guard-linux-amd64'), /No SHA256/);
});

test('installs a verified binary from the package version and reuses it', async (t) => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'jev-guard-npm-'));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const binary = Buffer.from('test executable');
  const digest = createHash('sha256').update(binary).digest('hex');
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(url);
    return new Response(url.endsWith('checksums.txt')
      ? `${digest}  jev-guard-linux-amd64\n`
      : binary);
  };
  const target = await install({ platform: 'linux', arch: 'x64', home, fetchImpl });
  assert.equal(target, path.join(home, '.jevguard', 'bin', 'jev-guard'));
  assert.deepEqual(await fs.readFile(target), binary);
  assert.deepEqual(urls.map((url) => new URL(url).pathname), [
    '/ClemensSchartmueller/jev-guard/releases/download/v0.2.0/checksums.txt',
    '/ClemensSchartmueller/jev-guard/releases/download/v0.2.0/jev-guard-linux-amd64',
  ]);
  await install({ platform: 'linux', arch: 'x64', home, fetchImpl });
  assert.equal(urls.length, 3);
});

test('rejects a corrupted download and preserves the previous binary', async (t) => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'jev-guard-npm-'));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const target = path.join(home, '.jevguard', 'bin', 'jev-guard');
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, 'previous binary');
  const fetchImpl = async (url) => new Response(url.endsWith('checksums.txt')
    ? `${'a'.repeat(64)}  jev-guard-linux-amd64\n`
    : 'corrupted binary');
  await assert.rejects(install({ platform: 'linux', arch: 'x64', home, fetchImpl }), /SHA256 mismatch/);
  assert.equal(await fs.readFile(target, 'utf8'), 'previous binary');
});
