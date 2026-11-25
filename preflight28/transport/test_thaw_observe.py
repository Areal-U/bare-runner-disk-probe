"""Exercise the original receiver observer with a real pinned Siso binary and a fresh child."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import thaw_observe as obs

GRAPH = Path(__file__).resolve().parents[1]/"graph"
sys.path.insert(0,str(GRAPH))
import test_graph as fixture
import graph

class ObserverTest(unittest.TestCase):
    def test_original_program_pin(self):
        if not os.environ.get("FROZEN_TREE"):
            self.skipTest("supply the 81105d5 original checkout")
        root=Path(os.environ["FROZEN_TREE"]).resolve()
        before=os.environ.copy()
        try:
            os.environ.update(GITHUB_WORKSPACE=str(root),RUNNER_TEMP="/tmp")
            import importlib.util
            spec=importlib.util.spec_from_file_location("original_prepare",root/"preflight28/transport/prepare.py")
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            raw=module.build_recipe(module.commands(module.READ))
        finally:
            os.environ.clear()
            os.environ.update(before)
        out=obs.observed_recipe(raw)
        subprocess.run(["bash","-n"],input=out.encode(),check=True)
        self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(),obs.PRODUCER_RECIPE)
        with self.assertRaises(ValueError):
            obs.observed_recipe(raw+' ')
        self.assertEqual(out.count('autoninja "${read_mode[@]}" -C out/Bare -j 2 -v '),3)

    @unittest.skipUnless(os.environ.get("SISO"),"supply the pinned Siso executable")
    def test_real_isolated_dry_metrics(self):
        c=fixture.FrontierTest("test_independent_restore_and_damage")
        c.setUp()
        try:
            root=c.out.parent.parent
            # Seed a genuine historical Siso default telemetry and compile the new child.
            initial=subprocess.run([*c.command,"-C",c.out,"-j","2","obj/a.o"],capture_output=True,check=True)
            self.assertIn(b"0 steps",initial.stderr)
            graph.produce(c.out,c.proof,c.command)
            saved=c.out.parent/"deposited"
            c.out.rename(saved)
            shutil.copytree(saved,c.out,symlinks=True)
            before={p.name:graph.sha(p) for p in c.out.glob("siso_metrics*.json")}
            tools=root/"tools"
            tools.mkdir()
            wrapper=tools/"autoninja"
            wrapper.write_text('#!/bin/sh\nexec "$SISO" ninja -load= "$@"\n')
            wrapper.chmod(0o755)
            # The scratch machine has less than the hosted 20-GiB operational floor.
            # Supply only the hosted disk counters, keep all Siso I/O and SHA checks real.
            df=tools/"df"
            df.write_text('#!/bin/sh\nif test "$1" = "-B1"; then echo Available; echo 32212254720; else echo Inodes; echo "test 60000 10000 50000 16% /"; fi\n')
            df.chmod(0o755)
            probe='autoninja "${read_mode[@]}" -C out/Bare -j 2 -v obj/a.o\n'
            # Run the native graph verifier in the same shell before its final state comparison.
            check=[sys.executable,str(GRAPH/"graph.py"),"receive","--out",str(c.out),"--proof",str(c.proof)]
            import shlex
            script="set -euo pipefail\n"+obs.OBSERVE+probe*3+obs.FINISH+shlex.join(check)+"\n"+obs.AFTER_GRAPH
            res=subprocess.run(["bash","-c",script],env={**os.environ,"PATH":str(tools)+":"+os.environ["PATH"],"R28_ROLE":"receive"},
                               capture_output=True,text=True)
            self.assertEqual(res.returncode,0,res.stderr)
            self.assertEqual(res.stderr.count("0 steps"),3)
            self.assertIn("original_ninja_siso_state_and_metrics_after_apk_plan=unchanged",res.stdout)
            self.assertIn("original_ninja_siso_state_and_metrics=unchanged",res.stdout)
            self.assertEqual(before,{p.name:graph.sha(p) for p in c.out.glob("siso_metrics*.json")})
            self.assertEqual(graph.receive(c.out,c.proof,c.command)["restored_dirty"],1)
            # Control: original dry marker is zero real build steps but mutates metrics and violates the proof.
            baseline=subprocess.run([*c.command,"-n","-C",c.out,"-j","2","-v","obj/a.o"],capture_output=True,check=True)
            self.assertIn(b"0 steps",baseline.stderr)
            self.assertNotEqual(before,{p.name:graph.sha(p) for p in c.out.glob("siso_metrics*.json")})
            with self.assertRaisesRegex(ValueError,"retained output"):
                graph.receive(c.out,c.proof,c.command)
        finally:
            c.doCleanups()

if __name__=="__main__": unittest.main()
