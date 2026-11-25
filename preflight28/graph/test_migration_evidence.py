"""Offline migrations operate on the entire bounded archive and read-only graphs."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import migration_graph
import retained
import test_gn_diagnostic
import test_retained


GRAPH = (b"rule gn\n  command = false\nbuild build.ninja.stamp: gn\n"
         b"  generator = 1\n  depfile = build.ninja.d\nbuild build.ninja: phony build.ninja.stamp\n"
         b"  generator = 1\nsubninja rules.ninja\n")
DEP = ("build.ninja.stamp: ../../BUILD.gn gn_logs.txt " + " ".join(sorted(retained.DESCRIPTORS))).encode()


def metric(i):
    build_id=f"7a404a41-1a39-4a31-9d08-{i:012x}"
    return b"".join((json.dumps({"build_id":build_id,"duration_nanos":t},
                                separators=(",",":"))+"\n").encode() for t in range(3))


class MigrationTest(unittest.TestCase):
    audit = test_gn_diagnostic.DiagnosticTest.audit
    write = test_retained.ArchiveTest.write
    log = test_gn_diagnostic.DiagnosticTest.log

    def pair(self):
        old={"build.ninja":GRAPH,"rules.ninja":b"build chrome_public_apk: phony obj/b.o\n",
             "build.ninja.d":DEP, "gn_logs.txt":self.log+b"ram16\n"}
        old.update({k:metric(i+1) for i,k in enumerate(retained.METRICS)})
        new={**old,"gn_logs.txt":self.log+b"ram17\n",
             **{k:metric(20+i) if i<3 else old[retained.METRICS[i-3]] for i,k in enumerate(retained.METRICS)},
             **{k:b"display metadata" for k in retained.DESCRIPTORS}}
        return old,new

    def test_isolated_historical_cli_and_every_role(self):
        old,new=self.pair()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            parent, ps=self.write(root,"parent",old)
            new["obj/b.o"]=b"B"
            byte_rows={k:retained.record(0o644,len(v),hashlib.sha256(v).hexdigest()) for k,v in new.items()}
            proof={"format":"bare-28-apk-frontier-2","target":"chrome_public_apk","target_path":"obj/b.o",
                   "outputs":{"obj/b.o":[1,hashlib.sha256(b"B").hexdigest()]},
                   "child_content":retained.commitment(byte_rows)}
            child, cs=self.write(root,"child",new,proof)
            # Exercise isolated mode with a fixed fixture digest. The deployed CLI has only the fixed actual S2.
            code=Path(retained.__file__).resolve()
            fixed=root/"retained.py"
            fixed.write_text(code.read_text().replace(retained.S2,ps,1))
            shutil.copy(code.with_name("metrics_evidence.py"),root)
            report=root/"audit.json"
            subprocess.run([sys.executable,"-I",str(fixed),"archives","--parent",str(parent),
                            "--child",str(child),"--parent-sha",ps,"--child-sha",cs,"--report",str(report)],
                           check=True,capture_output=True)
            data=json.loads(report.read_bytes())
            self.assertEqual(data["status"],"passed")
            self.assertEqual(data["metric_rotation"],{"steps":3,"matched":8,"bounded_files":11})
            self.assertEqual(data["counts"]["siso_metrics"],11)
            self.assertEqual(data["metrics"][0]["evidence"]["child"]["summary_rows"],3)
            self.assertEqual(sum(x.get("role")=="gn-generated-packaging-descriptor" for x in data["differences"]),2)
            self.assertEqual(data["diagnostics"][0]["evidence"]["parent"]["regeneration_dependency"]["role"],"regeneration-input")

    def test_refuse_real_consumer_malformed_rotation_and_wrong_make_edge(self):
        for override in [{"build.ninja.d":DEP.replace(b"build.ninja.stamp:", b"another.o:")},
                         {"build.ninja.d":DEP+b"\nother: gn_logs.txt"},
                         {"rules.ninja":b"build chrome_public_apk: phony gn_logs.txt\n"},
                         {"rules.ninja":b"s = siso_\nm = metrics.json\nbuild chrome_public_apk: phony ${s}${m}\n"},
                         {"siso_metrics.9.json":metric(99)},{"siso_metrics.json":b'{"bogus":true}\n'}]:
            old,new=self.pair()
            report=self.audit(old,{**new,**override})
            self.assertEqual(report["status"],"rejected", override)
            self.assertIn("base64",report["forensic"]["child"]["regular_samples"]["gn_logs.txt"])

    def test_normal_preexisting_metrics_and_payloads_remain_committed_across_gn(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/"out/Bare";out.mkdir(parents=True)
            old,_=self.pair()
            old["inherited.o"]=b"old"
            for name,data in old.items():
                (out/name).write_bytes(data)
            original=retained.commitment(retained.inventory(out))
            state=root/"proof"
            migration_graph.observe("before",out,state,required_content=original)
            (out/"apks").mkdir()
            for name in retained.DESCRIPTORS:
                (out/name).write_bytes(b"GN descriptor")
            (out/"gn_logs.txt").write_bytes(self.log+b"ram99\n")
            result=migration_graph.observe("after",out,state,required_content=original)
            self.assertEqual(set(result["descriptor_outputs"]),retained.DESCRIPTORS)
            for name in ("siso_metrics.json","inherited.o"):
                oldbytes=(out/name).read_bytes()
                (out/name).write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError,"another inherited"):
                    migration_graph.observe("after",out,state,required_content=original)
                (out/name).write_bytes(oldbytes)
            (out/"apks/ChromeAndWebView32.ssargs").unlink()
            with self.assertRaises((ValueError,OSError)):
                migration_graph.observe("after",out,state,required_content=original)


if __name__=="__main__":
    unittest.main()
