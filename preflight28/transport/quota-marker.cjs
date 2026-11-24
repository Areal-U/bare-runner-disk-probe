// A step-local marker for an explicit provider rejection of Artifact creation.
// Forward all output unchanged; retain no logs, paths supplied by peers, or tokens.
const fs = require('node:fs');
const path = require('node:path');
const marker = path.join(process.env.RUNNER_TEMP,'r28-split','full-quota-evidence');
if (process.env.GITHUB_JOB === 'produce') {
  for (const stream of [process.stdout, process.stderr]) {
    const original = stream.write;
    stream.write = function (chunk, ...args) {
      if (typeof chunk === 'string' || Buffer.isBuffer(chunk)) {
        const line = String(chunk);
        if (/Failed to CreateArtifact:\s*Artifact storage quota has been hit\b/i.test(line)) {
          try { fs.writeFileSync(marker,'create-rejected-storage-quota\n',{flag:'wx',mode:0o600}); }
          catch (err) { if (err.code !== 'EEXIST') throw err; }
        }
      }
      return original.call(this,chunk,...args);
    };
  }
}
