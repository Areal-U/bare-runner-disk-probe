'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync, spawn} = require('node:child_process');

const PIN = 'cf430e030ddbb5b0abf93d22962f4752f3646cd9';
const BUNDLE = '7b3f92ae681d6eeca5f5e5e4cf892ad0dfb254ea';
const STOP = new Set(['apk', 'no-progress', 'verify-only', 'size-exceeded', 'failed', 'cancelled']);
const MAX_PLAIN = 7 * 1024 ** 3 / 2;

function requireCondition(ok, message) {
  if (!ok) throw new Error(message);
}

function regular(file, maxSize) {
  const info = fs.lstatSync(file);
  requireCondition(info.isFile() && info.size > 0 && info.size <= maxSize &&
    fs.realpathSync(file) === file, 'A required regular file is missing or out of bounds');
  return info.size;
}

function validateScope(env) {
  const run = env.GITHUB_RUN_ID;
  const slot = Number(env.R28_SLOT);
  requireCondition(env.GITHUB_REPOSITORY === 'Areal-U/bare-runner-disk-probe' &&
    env.GITHUB_JOB === 'compile-probe' && env.GITHUB_RUN_ATTEMPT === '1' &&
    /^[1-9]\d*$/.test(run) && Number.isSafeInteger(Number(run)) &&
    /^(?:[1-9]|1[0-3])$/.test(env.R28_SLOT), 'Unexpected originating worker or slot');
  const name = `r28-${run}-a1-s${String(slot).padStart(2, '0')}-outcome`;
  requireCondition(env.INPUT_NAME === name && env.INPUT_OVERWRITE === 'false' &&
    env['INPUT_RETENTION-DAYS'] === '1' && env['INPUT_COMPRESSION-LEVEL'] === '0' &&
    env['INPUT_IF-NO-FILES-FOUND'] === 'error', 'Invalid immutable upload settings');
  const base = path.join(env.RUNNER_TEMP, 'r28-normal');
  const outcome = path.join(base, 'outcome.json');
  regular(outcome, 64 * 1024);
  const receipt = JSON.parse(fs.readFileSync(outcome, 'utf8'));
  requireCondition(receipt.run === Number(run) && receipt.attempt === 1 && receipt.ordinal === slot &&
    receipt.key === `bare-coexist-204-${run}-1-checkpoint-production-s${slot}` &&
    receipt.producer_sha === env.R28_HEAD_SHA && /^[a-f0-9]{40}$/.test(receipt.producer_sha),
    'Outcome is not bound to this run, slot and source');
  const paths = [outcome];
  if (receipt.status === 'candidate') {
    const sealed = path.join(base, 'checkpoint.cms');
    requireCondition(slot <= 12 && Number.isSafeInteger(receipt.bytes) && receipt.bytes > 0 &&
      receipt.bytes <= MAX_PLAIN && receipt.sealed_bytes > receipt.bytes &&
      receipt.sealed_bytes === regular(sealed, receipt.bytes + 16 * 1024 ** 2) &&
      /^[a-f0-9]{64}$/.test(receipt.sealed_sha), 'Invalid sealed checkpoint receipt');
    paths.push(sealed);
  } else {
    requireCondition(STOP.has(receipt.status), 'Unknown terminal outcome');
  }
  requireCondition(env.INPUT_PATH === paths.join('\n'), 'Upload path differs from the bounded outcome');
}

function checkedBundle(temp) {
  const root = path.join(temp, 'r28-uploader');
  const bundle = path.join(root, 'dist', 'upload', 'index.js');
  regular(bundle, 64 * 1024 ** 2);
  regular(path.join(root, 'package.json'), 128 * 1024);
  const git = (...args) => execFileSync('git', ['-C', root, ...args], {encoding: 'utf8', timeout: 15000}).trim();
  requireCondition(git('rev-parse', 'HEAD') === PIN &&
    git('status', '--porcelain', '--untracked-files=all', '--', 'package.json', 'dist/upload') === '',
    'Official uploader checkout differs from the pinned revision');
  const code = fs.readFileSync(bundle);
  const oid = crypto.createHash('sha1').update(`blob ${code.length}\0`).update(code).digest('hex');
  requireCondition(oid === BUNDLE, 'Official uploader bundle failed identity verification');
  return bundle;
}

// Never relay child console text as workflow commands. Only a complete,
// recognized official storage-quota annotation is evidence of a quota stop.
function watchQuota(stream, signal) {
  let line = '';
  let oversized = false;
  function endLine() {
    if (!oversized && /^::error::(?:Failed to CreateArtifact: )?Artifact storage quota has been hit\. Unable to upload any new artifacts\.(?:\s|%0[AD]|$)/i.test(line)) signal();
    line = '';
    oversized = false;
  }
  stream.setEncoding('utf8');
  stream.on('data', chunk => {
    const parts = chunk.split('\n');
    for (let i = 0; i < parts.length; i++) {
      if (!oversized) {
        if (line.length + parts[i].length <= 16384) line += parts[i];
        else oversized = true;
      }
      if (i < parts.length - 1) endLine();
    }
  });
  stream.on('end', endLine);
}

function parseReceipt(file) {
  const length = fs.statSync(file).size;
  requireCondition(length > 0 && length <= 16384, 'Missing or oversized SDK output');
  const rows = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n').trimEnd().split('\n');
  const values = new Map();
  for (let i = 0; i < rows.length; i++) {
    const header = /^(artifact-id|artifact-digest|artifact-url)<<(ghadelimiter_[a-zA-Z0-9-]+)$/.exec(rows[i]);
    requireCondition(header && !values.has(header[1]) && i + 2 < rows.length && rows[i + 2] === header[2],
      'Unexpected SDK output format');
    values.set(header[1], rows[i + 1]);
    i += 2;
  }
  const id = values.get('artifact-id');
  const digest = values.get('artifact-digest');
  requireCondition(typeof id === 'string' && /^[1-9]\d*$/.test(id) &&
    typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest), 'SDK returned an invalid artifact receipt');
  return {id, digest};
}

async function invoke(bundle, env) {
  const root = fs.mkdtempSync(path.join(env.RUNNER_TEMP, 'r28-upload-client-'));
  const file = path.join(root, 'output');
  fs.writeFileSync(file, '', {mode: 0o600});
  try {
    const childEnv = {...env, GITHUB_OUTPUT: file, 'INPUT_INCLUDE-HIDDEN-FILES': 'false', INPUT_ARCHIVE: 'true'};
    delete childEnv.NODE_OPTIONS;
    delete childEnv.NODE_PATH;
    const child = spawn(process.execPath, [bundle], {env: childEnv, stdio: ['ignore', 'pipe', 'pipe']});
    let quota = false;
    for (const stream of [child.stdout, child.stderr]) watchQuota(stream, () => { quota = true; });
    const code = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
    if (code !== 0) {
      return {status: quota && code === 1 ? 'quota-denied' : 'transfer-unknown'};
    }
    return {status: 'uploaded', ...parseReceipt(file)};
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
}

async function main() {
  const env = process.env;
  validateScope(env);
  const result = await invoke(checkedBundle(env.RUNNER_TEMP), env);
  let output = `upload-status=${result.status}\n`;
  if (result.status === 'uploaded') output += `artifact-id=${result.id}\nartifact-digest=${result.digest}\n`;
  fs.appendFileSync(env.GITHUB_OUTPUT, output);
  process.stdout.write(`Pinned artifact client result: ${result.status}\n`);
}

module.exports = {checkedBundle, invoke, validateScope};
if (require.main === module) {
  main().catch(() => {
    // Exception text can contain unchecked SDK input. Keep workflow commands private.
    process.stderr.write('Normal artifact uploader failed its local integrity or receipt checks.\n');
    process.exitCode = 1;
  });
}
