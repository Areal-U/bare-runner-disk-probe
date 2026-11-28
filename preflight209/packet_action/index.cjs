'use strict';
const {spawnSync} = require('node:child_process');
const {resolve} = require('node:path');
const scripts = {
  send: ['compile-probe', 'preflight209/checkpoint_send.py', 'send'],
  receive: ['draft-publisher', 'preflight28/bridge/normal.py', 'wait', 'outcome']
};
const args = scripts[process.env.INPUT_MODE];
if (!args || args[0] !== process.env.GITHUB_JOB) throw Error('Unexpected physical packet role');
const run = spawnSync('/usr/bin/python3', [resolve(process.env.GITHUB_WORKSPACE, args[1]), ...args.slice(2)], {
  stdio: 'inherit', env: {...process.env, R209_PACKET_NODE: process.execPath}
});
if (run.error) throw run.error;
process.exit(run.status ?? 1);
