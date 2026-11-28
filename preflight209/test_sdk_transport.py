"""Run the workflow's pinned uploader and downloader against an isolated loopback service.

Set R209_UPLOAD_SDK and R209_DOWNLOAD_SDK to clean checkouts of the revisions in
the slot workflow. No GitHub credentials, artifacts or production endpoints are used.
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree
import zipfile

import test_outcome_transport as producer

REPO = Path(__file__).resolve().parents[1]
SHIM = REPO / 'preflight28/bridge/normal_upload/index.cjs'
ARTIFACT = '5902'
DOWNLOAD_HEAD = '9000827ccba6bdab643e8b6fd33ac0654aef8333'
DOWNLOAD_BLOB = 'e5fe23803e0378f1f365aa0d6326cd288f5b660c'


class BlobHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, payload=b'', mime='application/json'):
        if isinstance(payload, dict):
            payload = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def body(self):
        return self.rfile.read(int(self.headers['Content-Length']))

    def do_POST(self):
        req = json.loads(self.body())
        method = self.path.rsplit('/', 1)[-1]
        s = self.server
        s.calls.append(method)
        if method == 'CreateArtifact' and req['name'] == s.name and 'expires_at' in req:
            self.reply(200, dict(ok=True, signed_upload_url=s.url+'/test/blob'))
        elif method == 'FinalizeArtifact' and req['name'] == s.name:
            s.digest = 'sha256:' + hashlib.sha256(s.archive).hexdigest()
            if req['hash'] != s.digest or int(req['size']) != len(s.archive):
                self.reply(400, dict(msg='digest or size differs'))
                return
            self.reply(200, dict(ok=True, artifact_id=ARTIFACT))
        elif method == 'ListArtifacts' and req.get('id_filter', ARTIFACT) == ARTIFACT:
            self.reply(200, dict(artifacts=[dict(
                workflow_run_backend_id='run', workflow_job_run_backend_id='worker',
                database_id=ARTIFACT, name=s.name, size=str(len(s.archive)), digest=s.digest,
                created_at='2026-11-27T00:00:00Z')]))
        elif method == 'GetSignedArtifactURL' and req['name'] == s.name:
            self.reply(200, dict(signed_url=s.url+'/test/blob'))
        else:
            self.reply(400, dict(msg='unexpected RPC'))

    def do_PUT(self):
        uri = urlsplit(self.path)
        q = parse_qs(uri.query)
        body = self.body()
        if uri.path == '/test/blob' and q.get('comp') == ['block']:
            self.server.blocks[q['blockid'][0]] = body
        elif uri.path == '/test/blob' and q.get('comp') == ['blocklist']:
            keys = [el.text for el in ElementTree.fromstring(body)]
            self.server.archive = b''.join(self.server.blocks[i] for i in keys)
        else:
            self.reply(400)
            return
        self.reply(201)

    def do_GET(self):
        if self.path == '/test/blob':
            self.reply(200, self.server.archive, 'application/zip')
        else:
            self.reply(404)


@unittest.skipUnless(os.getenv('R209_UPLOAD_SDK') and os.getenv('R209_DOWNLOAD_SDK'),
                     'select the two pinned official artifact SDK checkouts')
class WorkflowTransport(unittest.TestCase):
    def setUp(self):
        self.source = producer.OutcomeTransport()
        self.addCleanup(self.source.doCleanups)
        self.source.setUp()
        self.work = self.source.tmp
        self.payload = self.source.normal
        upload = Path(os.environ['R209_UPLOAD_SDK']).resolve()
        shutil.copytree(upload, self.work/'r28-uploader')
        download = Path(os.environ['R209_DOWNLOAD_SDK']).resolve()
        self.downloader = download/'dist/index.js'
        for args, expected in ((['rev-parse','HEAD'], DOWNLOAD_HEAD),
                               (['hash-object','dist/index.js'], DOWNLOAD_BLOB),
                               (['status','--porcelain','--','package.json','dist'], '')):
            self.assertEqual(subprocess.check_output(['git','-C',download,*args], text=True).strip(), expected)

        cert, key = self.work/'tls.pem', self.work/'tls-key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1',
                        '-keyout',key,'-out',cert], capture_output=True, check=True)
        s = ThreadingHTTPServer(('127.0.0.1', 0), BlobHandler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        s.socket = tls.wrap_socket(s.socket, server_side=True)
        s.url = f'https://127.0.0.1:{s.server_port}'
        s.name = self.source.name
        s.blocks, s.archive, s.calls = {}, b'', []
        self.service = s
        threading.Thread(target=s.serve_forever,daemon=True).start()
        self.addCleanup(s.server_close)
        self.addCleanup(s.shutdown)

        scope = base64.urlsafe_b64encode(b'{"scp":"Actions.Results:run:worker"}').decode().rstrip('=')
        self.out = self.source.outputs
        self.env = self.source.env | dict(PATH=os.environ['PATH'], HOME=str(self.work), GITHUB_WORKSPACE=str(self.work),
                        GITHUB_SERVER_URL='https://github.com', ACTIONS_RESULTS_URL=s.url, NODE_EXTRA_CA_CERTS=str(cert),
                        ACTIONS_RUNTIME_TOKEN='e30.'+scope+'.fixture')

    def invoke(self, argv, **env):
        proc = subprocess.run(argv, env=self.env | env, capture_output=True, text=True, timeout=25)
        self.assertEqual(proc.returncode, 0, proc.stdout+proc.stderr)
        return proc.stdout

    def roundtrip(self, candidate):
        outcome = self.payload/'outcome.json'
        paths = [outcome]
        if candidate:
            archive, peer, owner_key, draft = self.source.make_candidate()
            paths.append(self.payload/'checkpoint.cms')
            shutil.copyfile(self.payload/'input.json',peer/'input.json')
        else:
            self.source.command('stop','--reason','failed')
            peer = self.work/'receiver'
            peer.mkdir()
            info = producer.normal.context() | producer.normal.sender_times(int(time.time()),23)
            (peer/'input.json').write_text(json.dumps(info))
        self.out.write_text('')
        self.invoke(['node',SHIM], INPUT_NAME=self.source.name, INPUT_PATH='\n'.join(map(str,paths)))
        fields = dict(i.split('=',1) for i in self.out.read_text().splitlines())
        self.assertEqual(fields, {'upload-status':'uploaded','artifact-id':ARTIFACT,
                                  'artifact-digest':hashlib.sha256(self.service.archive).hexdigest()})
        expected = {p.name:p.read_bytes() for p in paths}
        with zipfile.ZipFile(io.BytesIO(self.service.archive)) as z:
            self.assertCountEqual(z.namelist(), list(expected))
            self.assertEqual({p:z.read(p) for p in expected}, expected)
        receiver = peer/'incoming'
        download_options = {'INPUT_ARTIFACT-IDS':fields['artifact-id'],'INPUT_MERGE-MULTIPLE':'true',
                            'INPUT_SKIP-DECOMPRESS':'false','INPUT_DIGEST-MISMATCH':'error'}
        self.invoke(['node',self.downloader], INPUT_PATH=str(receiver), **download_options)
        self.assertEqual({p.name:p.read_bytes() for p in receiver.iterdir()}, expected)
        self.assertEqual(self.service.calls[:2], ['CreateArtifact','FinalizeArtifact'])
        self.assertIn('GetSignedArtifactURL', self.service.calls[2:])
        with patch.object(producer.normal,'ROOT',peer), patch.object(producer.bridge,'ROOT',peer):
            producer.normal.publish()
        verdict = 'candidate' if candidate else 'failed'
        self.assertIn('peer_status='+verdict,self.out.read_text().splitlines())
        if candidate:
            self.assertTrue(any(a['name']=='r209-17-a1-s01-manifest.json' for a in draft.assets))
            self.assertIn('private_readback_verified=true',self.out.read_text().splitlines())
            raw_zip = self.work/'sdk.zip'
            raw_zip.write_bytes(self.service.archive)
            row = dict(name=self.source.name, id=int(ARTIFACT), expired=False, expires_at='2099-01-01T00:00:00Z',
                       digest=self.service.digest, size_in_bytes=raw_zip.stat().st_size,
                       workflow_run=dict(id=17,head_sha=self.env['GITHUB_SHA']))
            head, parent = self.env['GITHUB_SHA'], self.env['R28_PARENT_SHA']
            receipt = producer.owner_recovery.service_record(row,17,1,head,parent,97,expect_id=int(ARTIFACT))
            rescued = self.work/'rescue.tar.zst'
            producer.owner_recovery.open_saved(raw_zip,receipt,owner_key,rescued,artifact_id=int(ARTIFACT),
                                               run=17,ordinal=1,head=head,parent_sha=parent,claim_id=97)
            self.assertEqual(rescued.read_bytes(),archive.read_bytes())
        else:
            self.service.digest = 'sha256:'+'0'*64
            bad_env = self.env | download_options | {'INPUT_PATH':str(self.work/'changed-receipt')}
            refused = subprocess.run(['node',self.downloader],env=bad_env,capture_output=True,text=True,timeout=25)
            self.assertNotEqual(refused.returncode,0)
            self.assertIn('Digest validation failed',refused.stdout+refused.stderr)

    def test_failed_outcome(self):
        self.roundtrip(False)

    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'requires age tools for fixture keys')
    def test_candidate_outcome(self):
        self.roundtrip(True)
