'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {invoke, validateScope, checkedBundle} = require('./index.cjs');

function fixture() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'normal-upload-test-'));
  const normal = path.join(temp, 'r28-normal');
  fs.mkdirSync(normal);
  const outcome = path.join(normal, 'outcome.json');
  const cipher = path.join(normal, 'checkpoint.cms');
  const env = {
    ...process.env,
    GITHUB_REPOSITORY: 'Areal-U/bare-runner-disk-probe', GITHUB_RUN_ID: '45508307820', GITHUB_RUN_ATTEMPT: '1',
    GITHUB_JOB: 'compile-probe', R28_SLOT: '2', R28_HEAD_SHA: '3'.repeat(40),
    RUNNER_TEMP: temp, GITHUB_OUTPUT: path.join(temp, 'real-output'),
    INPUT_NAME: 'r28-45508307820-a1-s02-outcome', INPUT_PATH: outcome + '\n' + cipher, INPUT_OVERWRITE: 'false',
    'INPUT_RETENTION-DAYS': '1', 'INPUT_COMPRESSION-LEVEL': '0', 'INPUT_IF-NO-FILES-FOUND': 'error',
  };
  const record = {schema: 'bare-r28-checkpoint-private-v1', run: Number(env.GITHUB_RUN_ID), attempt: 1, ordinal: 2, producer_sha: env.R28_HEAD_SHA,
    key: 'bare-coexist-204-45508307820-1-checkpoint-production-s2', status: 'candidate',
    bytes: 12, sealed_bytes: 24, sealed_sha: '8'.repeat(64)};
  fs.writeFileSync(outcome, JSON.stringify(record));
  fs.writeFileSync(cipher, Buffer.alloc(24));
  fs.writeFileSync(env.GITHUB_OUTPUT, '');
  return {temp, outcome, cipher, env, record, close: () => fs.rmSync(temp, {recursive: true, force: true})};
}

test('only fixed attempt, ordinal, name, canonical paths, retention and unchanged encrypted extent', () => {
  const f = fixture();
  try {
    assert.doesNotThrow(() => validateScope(f.env));
    for (const change of [
      {GITHUB_RUN_ATTEMPT: '2'}, {GITHUB_JOB: 'send'}, {INPUT_NAME: f.env.INPUT_NAME + '-retry'},
      {'INPUT_COMPRESSION-LEVEL': '9'}, {INPUT_OVERWRITE: 'true'}, {'INPUT_RETENTION-DAYS': '2'},
      {'INPUT_IF-NO-FILES-FOUND': 'ignore'}, {INPUT_PATH: f.env.INPUT_PATH + '\n*'},
    ]) assert.throws(() => validateScope({...f.env, ...change}));
    fs.appendFileSync(f.cipher, 'wrong size');
    assert.throws(() => validateScope(f.env));
    fs.unlinkSync(f.cipher);
    fs.symlinkSync(f.outcome, f.cipher);
    assert.throws(() => validateScope(f.env));
    fs.writeFileSync(f.outcome, JSON.stringify({...f.record, status: 'verify-only'}));
    assert.doesNotThrow(() => validateScope({...f.env, INPUT_PATH: f.outcome}));
    assert.throws(() => validateScope(f.env));
  } finally { f.close(); }
});

test('storage quota annotations are distinct from generic errors, forged log commands, and incomplete summaries', async () => {
  const f = fixture();
  try {
    const bundle = path.join(f.temp, 'test-sdk.cjs');
    const quota = '::error::Failed to CreateArtifact: Artifact storage quota has been hit. Unable to upload any new artifacts.';
    for (const [log, status] of [
      [quota + ' Usage is recalculated every 6-12 hours.', 'quota-denied'],
      ['Upload failed because of a quota on the local volume', 'transfer-unknown'],
      ['source file: ' + quota, 'transfer-unknown'],
      ['::error::Failed to CreateArtifact: Artifact storage quota', 'transfer-unknown'],
      ['::set-output name=artifact-id::12345', 'transfer-unknown'],
      ['::error::InternalServerError', 'transfer-unknown'],
    ]) {
      fs.writeFileSync(bundle, `console.error(${JSON.stringify(log)}); process.exitCode = 1\n`);
      assert.deepEqual(await invoke(bundle, f.env), {status});
    }
    assert.equal(fs.readFileSync(f.env.GITHUB_OUTPUT, 'utf8'), '');
  } finally { f.close(); }
});

test('passes official multiline output format while isolating SDK output from the real step', async () => {
  const f = fixture();
  try {
    const bundle = path.join(f.temp, 'test-sdk.cjs');
    const delimiter = 'ghadelimiter_2772ae1b-9004-4ee8-8e67-4c6d60826580';
    const digest = 'a'.repeat(64);
    const out = (key, value) => `${key}<<${delimiter}\n${value}\n${delimiter}\n`;
    const good = out('artifact-id', '2345') + out('artifact-url', 'https://github.com/example/artifacts/2345') + out('artifact-digest', digest);
    for (const [contents, valid] of [
      [good, true], [out('artifact-id', '2345'), false], [good + out('danger', 'spoof'), false],
      [good + out('artifact-id', '4567'), false], [out('artifact-id', '1\nabc') + out('artifact-digest', digest), false],
    ]) {
      fs.writeFileSync(bundle, `if (process.env.INPUT_ARCHIVE !== 'true' || process.env['INPUT_INCLUDE-HIDDEN-FILES'] !== 'false') process.exit(1);
        require('node:fs').appendFileSync(process.env.GITHUB_OUTPUT, ${JSON.stringify(contents)})\n`);
      if (valid) assert.deepEqual(await invoke(bundle, {...f.env, INPUT_ARCHIVE: 'false', 'INPUT_INCLUDE-HIDDEN-FILES': 'true'}),
        {status: 'uploaded', id: '2345', digest});
      else await assert.rejects(invoke(bundle, f.env));
    }
    assert.equal(fs.readFileSync(f.env.GITHUB_OUTPUT, 'utf8'), '');
    assert.throws(() => checkedBundle(f.temp));
  } finally { f.close(); }
});
