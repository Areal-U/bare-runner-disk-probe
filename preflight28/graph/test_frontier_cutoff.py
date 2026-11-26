"""Exercise the ordinary 'after' CLI when the runner cannot execute a finalizer."""
from contextlib import redirect_stdout
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

import test_segment_graph as fixtures
from graph import canonical
from retained import STATE
from segment_graph import begin, PROOF


@unittest.skipUnless(os.environ.get('SISO'), 'set SISO to the pinned Siso binary')
class InterruptedFrontier(unittest.TestCase):
    def setUp(self):
        fixtures.NormalSegmentTest.setUp(self)
        self.root = self.report.parent
        self.cli = Path(__file__).resolve().with_name('segment_graph.py')
        with redirect_stdout(io.StringIO()) as previous:
            begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)
        self.baseline_log = previous.getvalue()
        self.metrics = self.root / 'siso-metrics-restore.json'
        subprocess.run([*self.command, '-C', str(self.out), '-metrics_json', str(self.metrics),
                        'obj/b.o', 'obj/c.o'], check=True, capture_output=True)
        self.report.write_text(json.dumps(dict(target='chrome_public_apk', phase='restore',
            reason='time-limit', container_quiescence_verified=True, ready_for_restore_test=True,
            failed_step_count=0, forced_kill=False, metrics_path=str(self.metrics))))
        launcher = self.root / 'autoninja'
        launcher.write_text('#!/bin/sh\nexec "$SISO" ninja -load= "$@"\n')
        launcher.chmod(0o700)

    def launch(self):
        return subprocess.Popen([sys.executable, self.cli, '--out', self.out, 'after',
            '--host-quiesced', '--private-intermediates', '--baseline', self.baseline,
            '--trial', self.report], env=dict(os.environ, PATH=str(self.root)+':'+os.environ['PATH']),
            start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    @staticmethod
    def opened_by_reader(fifo, process):
        until = time.monotonic() + 15
        while time.monotonic() < until and process.poll() is None:
            try:
                return os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                if error.errno != errno.ENXIO:
                    raise
                time.sleep(0.01)
        raise AssertionError('CLI did not block on the expected stream')

    @staticmethod
    def phases(text):
        return [json.loads(line.removeprefix('BARE_FRONTIER_PHASE ')) for line in text.splitlines()
                if line.startswith('BARE_FRONTIER_PHASE ')]

    def kill_at_metrics(self, split):
        records = [json.loads(line) for line in self.metrics.read_text().splitlines()]
        partial = b''.join((json.dumps(row)+'\n').encode() for row in records
                           if 'obj/b.o' not in row.get('outputs',[]))
        self.metrics.unlink()
        os.mkfifo(self.metrics)
        process = self.launch()
        held = []
        try:
            held.append(self.opened_by_reader(self.metrics, process))
            if split:
                # Give the real first pass an incomplete success table, and block its second read
                # of the same name until the runner terminates it during the detailed diagnosis.
                other = self.root / 'second-read'
                os.mkfifo(other)
                os.replace(other, self.metrics)
                os.write(held[0], partial)
                os.close(held.pop())
                held.append(self.opened_by_reader(self.metrics, process))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            output = process.communicate(timeout=10)[0]
            for fd in held:
                os.close(fd)
        self.assertEqual(process.returncode,-signal.SIGKILL)
        self.assertFalse((self.out/PROOF).exists())
        self.assertNotIn('"frontier_status":', output)
        self.assertFalse(any(item in output for item in ('implicit.dat','obj/b.o','included.h')))
        return self.phases(output), output

    def test_kill_during_success_metrics(self):
        phases, _ = self.kill_at_metrics(False)
        self.assertEqual(self.phases(self.baseline_log)[-1]['parent_sha256'], self.parent)
        self.assertEqual(next(r['parent_sha256'] for r in phases if r['stage']=='read-controller'), self.parent)
        self.assertEqual(phases[-1], {'stage':'invocation-metrics'})

    def test_kill_during_rejection_detail(self):
        phases, output = self.kill_at_metrics(True)
        group = canonical(['implicit.dat','obj/b.o'])
        self.assertEqual(phases[-2],dict(stage='first-unproved-change',group_id=group,members=2))
        self.assertEqual(phases[-1],dict(stage='rejection-detail',group_id=group,count=1))
        self.assertNotIn('BARE_FRONTIER_REJECTION ',output)

    def test_kill_inside_plan_does_not_authorize_local_child(self):
        accepted = self.launch()
        self.assertEqual(json.loads(accepted.communicate(timeout=15)[0].splitlines()[-1])['frontier_status'], 'candidate')
        self.assertEqual(accepted.returncode, 0)
        archive = self.root/'accepted-parent.tar'
        # GNU pax preserves the nanosecond timestamps consumed by the actual Siso state.
        omitted = ['--exclude=Bare/'+p.name for p in self.out.iterdir()
                   if p.is_symlink() and STATE.fullmatch(p.name)]
        subprocess.run(['tar','--format=posix', *omitted, '-C',self.out.parent,
                        '-cf',archive,'Bare'], check=True, capture_output=True)
        parent_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.out.rename(self.root/'sender-output')
        subprocess.run(['tar','-C',self.out.parent,'-xf',archive], check=True, capture_output=True)
        self.baseline = self.root/'next-baseline.json'
        with redirect_stdout(io.StringIO()) as receipt:
            restored = begin(self.out, self.baseline, parent_sha, self.command, verify_only=True)
        self.assertTrue(restored['parent_frontier_verified'])
        inherited_proof = (self.out/PROOF).read_bytes()
        log = self.out/'.ninja_log'
        original = log.read_bytes()
        fifo = self.root/'planner-running'
        os.mkfifo(fifo)
        launcher = self.root/'autoninja'
        launcher.write_text('#!/bin/sh\nprintf "unfinished probe" > out/Bare/.ninja_log\n'
                            'cat planner-running >/dev/null\n')
        process = self.launch()
        try:
            fd = self.opened_by_reader(fifo, process)
            try:
                os.killpg(process.pid, signal.SIGKILL)
                output = process.communicate(timeout=10)[0]
            finally:
                os.close(fd)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(self.phases(output)[-1], dict(stage='apk-plan', pending_before=1))
        self.assertEqual(self.phases(receipt.getvalue())[-1]['parent_sha256'], parent_sha)
        self.assertEqual(next(r['parent_sha256'] for r in self.phases(output) if r['stage']=='read-controller'), parent_sha)
        self.assertEqual((self.out/PROOF).read_bytes(), inherited_proof)
        self.assertNotIn('"frontier_status":', output)
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), parent_sha)
        # A SIGKILL skips the planner's finally. The test mutates only the disposable runner.
        self.assertNotEqual(log.read_bytes(), original)
        self.assertEqual([p.read_bytes() for p in self.out.glob('.round28-plan-*/original')], [original])

    def test_real_output_disappearing_after_plan(self):
        # The negative control removes one declared implicit output after Siso has observed the
        # clean plan, before the classifier's independent inventory begins.
        (self.root/'autoninja').write_text(
            '#!/bin/sh\n"$SISO" ninja -load= "$@" || exit $?\nrm -f out/Bare/implicit.dat\n')
        process = self.launch()
        output = process.communicate(timeout=15)[0]
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.phases(output)[-1], dict(stage='missing-output',
                         group_id=canonical(['implicit.dat','obj/b.o']), members=2, missing=1))
        self.assertFalse((self.out/PROOF).exists())
        self.assertFalse(any(item in output for item in ('implicit.dat','obj/b.o','included.h')))

    def test_unchanged_acceptance_output_and_size_bound(self):
        process = self.launch()
        output = process.communicate(timeout=15)[0]
        self.assertEqual(process.returncode, 0, output)
        self.assertTrue((self.out/PROOF).is_file())
        self.assertEqual(json.loads(output.splitlines()[-1])['frontier_status'], 'candidate')
        rows = self.phases(output)
        self.assertEqual(rows[-1]['stage'], 'write-proof')
        self.assertLessEqual(len(rows), 16)
        self.assertLess(sum(len(json.dumps(row))+21 for row in rows), 4096)


if __name__=='__main__':
    unittest.main()
