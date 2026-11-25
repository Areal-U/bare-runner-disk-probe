import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import storage_admission as s


class Provider:
    def __init__(self):
        self.repo = dict(id=s.REPO_ID, full_name=s.REPO, fork=False, private=False, visibility="public")
        self.runs = []
        self.rows = []
        self.cache = []
        self.cache_limit = 10
        self.usage = 0

    def get(self, path):
        if path == s.BASE:
            return self.repo
        if "/actions/runs?status=" in path:
            return dict(total_count=len(self.runs), workflow_runs=self.runs)
        if "/actions/artifacts?" in path:
            return dict(total_count=len(self.rows), artifacts=self.rows)
        if path.endswith("/actions/cache/storage-limit"):
            return dict(max_cache_size_gb=self.cache_limit)
        if path.endswith("/actions/cache/usage"):
            return dict(active_caches_size_in_bytes=self.usage)
        if "/actions/caches?" in path:
            return dict(total_count=len(self.cache), actions_caches=self.cache)
        raise AssertionError(path)


ENV = dict(RUNNER_ENVIRONMENT="github-hosted", GITHUB_RUN_ID="81",
           R28_STORAGE_CEILING=str(10 * 1024**3), R28_STORAGE_UNTIL="4102444800")


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.p = Provider()
        self.env = ENV.copy()
        self.now = 1780000000
        self.args = dict(stage="outcome", now=self.now)

    def admit(self, size=20, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return s.admit(self.p.get, self.env, size, 1, **(self.args | kwargs))

    def test_owner_and_collector_bind_policy(self):
        known = dict(storage_policy=s.POLICY, artifact_ceiling_bytes=123, storage_valid_until="2027-01-08T00:00:00Z")
        self.assertEqual(s.policy(known, known)[0], 123)
        for override in ({"artifact_ceiling_bytes":0}, {"artifact_ceiling_bytes":True}, {"storage_policy":"unchecked"},
                         {"storage_valid_until":"unknown"}):
            with self.assertRaises(ValueError):
                s.policy(known | override, known | override)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            s.policy(known, known | {"artifact_ceiling_bytes":456})
        for key in ("R28_STORAGE_CEILING","R28_STORAGE_UNTIL"):
            with patch.dict(self.env, {key:""}), self.assertRaisesRegex(ValueError, key):
                self.admit()

    def test_peak_counts_expired_visible_and_new_zip_and_controls(self):
        self.p.rows = [dict(id=1,size_in_bytes=901,name="old",expired=True,expires_at="2019-01-10T00:00:00Z")]
        peak = 901 + 20 + s.CONTROL_RESERVE
        self.env["R28_STORAGE_CEILING"] = str(peak)
        self.assertEqual(self.admit(), "admitted")
        self.env["R28_RELAY_BYTE_CEILING"] = str(peak+500)
        with self.assertRaises(s.StorageFull):
            self.admit(21)
        self.env["R28_RELAY_BYTE_CEILING"] = str(peak-1)
        with self.assertRaises(s.StorageFull):
            self.admit()
        self.assertEqual(self.admit(exact_name="old"), "existing")

    def test_lease_covers_end_plus_long_lived_small_receipts(self):
        required = self.now + (350+85+7)*60 + 30*s.DAY
        self.env["R28_STORAGE_UNTIL"] = str(required)
        self.assertEqual(self.admit(stage="lease", lead=350*60), "admitted")
        self.env["R28_STORAGE_UNTIL"] = str(required-1)
        with self.assertRaisesRegex(ValueError,"expires"):
            self.admit(stage="lease", lead=350*60)
        self.assertEqual(self.admit(), "admitted")

    def test_verify_only_lease_and_issuance_at_last_release_slots(self):
        env = self.env | {"R28_STORAGE_VERIFY_ONLY":"true"}
        self.assertEqual(s.lease_size(env),16*1024)
        self.assertEqual(s.lease_size(self.env),s.MAX_RELAY_ZIP)
        self.env["R28_STORAGE_CEILING"]=str(s.CONTROL_RESERVE + 16*1024)
        self.assertEqual(self.admit(s.lease_size(env),stage="lease",lead=350*60),"admitted")
        with self.assertRaises(s.StorageFull):
            self.admit(s.lease_size(self.env),stage="lease",lead=350*60)
        s.draft_room({"assets":[{}]*990}, self.env, claim=True)
        with self.assertRaisesRegex(ValueError,"Release asset slots"):
            s.draft_room({"assets":[{}]*991},self.env,claim=True)
        s.draft_room({"assets":[{}]*992},self.env,claim=False)
        s.draft_room({"assets":[{}]*1000},env,claim=False)

    def test_full_private_release_reuses_exact_witness_and_skips_new_write(self):
        import sys
        from unittest.mock import Mock
        with patch.object(sys,"path",[str(Path(s.__file__).resolve().parents[1]/"control"), *sys.path]):
            import admission as gate
        name="r28-81-a1-owner-terminal.json"
        value={"version":1,"terminal":81}
        data=gate.encode(value)
        api=Mock()
        row={"id":123,"name":name}
        others=[{"id":i+2000,"name":f"other-{i}.json"} for i in range(1000)]
        api.draft.return_value={"assets":others[:999]+[row]}
        api.asset_info.return_value=row
        api.download.side_effect=lambda aid,size,sha,out:out.write(data)
        self.assertEqual(gate.admit("compute",value,api,name=name),123)
        api.draft.return_value={"assets":others}
        with self.assertRaisesRegex(ValueError,"no remaining asset slot"):
            gate.admit("compute",value,api,name=name)
        api.request.assert_not_called()

    def test_actual_receive_time_covers_all_retention_and_sender_timeout(self):
        self.env["R28_STORAGE_UNTIL"] = str(self.now + s.DAY + 7*60 - 1)
        with self.assertRaisesRegex(ValueError, "expires"):
            self.admit()
        self.env["R28_STORAGE_UNTIL"] = str(self.now + s.DAY + 7*60)
        self.assertEqual(self.admit(),"admitted")

    def test_witness_reserves_30_days_and_rejects_oversized_or_uncertain_upload(self):
        minimum = self.now + 30*s.DAY + 10*60
        budget = s.CONTROL_RESERVE + 16*1024
        self.env.update(R28_STORAGE_UNTIL=str(minimum), R28_STORAGE_CEILING=str(budget))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"witness.json"
            path.write_bytes(b"x"*8192)
            self.assertEqual(s.admit_witness(self.p.get,self.env,path,now=self.now),"admitted")
            for change in (dict(R28_STORAGE_UNTIL=str(minimum-1)),
                           dict(R28_STORAGE_CEILING=str(budget-1)), dict(R28_STORAGE_CEILING="")):
                with patch.dict(self.env,change), self.assertRaises(ValueError):
                    s.admit_witness(self.p.get,self.env,path,now=self.now)
            self.p.runs = [dict(id=82)]
            with self.assertRaisesRegex(ValueError,"Another"):
                s.admit_witness(self.p.get,self.env,path,now=self.now)
            self.p.runs = []
            path.write_bytes(b"x"*8193)
            with self.assertRaisesRegex(ValueError, "oversized"):
                s.admit_witness(self.p.get,self.env,path,now=self.now)
            other=path.with_name("unrelated.json")
            path.rename(other)
            path.symlink_to(other)
            with self.assertRaisesRegex(ValueError, "oversized"):
                s.admit_witness(self.p.get,self.env,path,now=self.now)

    def test_rescue_recovers_only_storage_policy_from_original_immutable_ack(self):
        start = "2026-11-25T01:03:00Z"
        common = dict(campaign="bare-personal-204-r28", branch="bare-coexist-v2.0.4",
                      head="2"*40, collector_registration_id="Automation_"+"b"*32,
                      owner_destination_id="libfile_private_owner", registration_nonce="a"*32, recipient="test",
                      storage_policy=s.POLICY, artifact_ceiling_bytes=12345, storage_valid_until="2027-01-01T00:00:00Z")
        ack = dict(common, schema=1, state="collector-read-back-owner-reservation",
                   observed_at="2026-11-25T00:55:00Z", valid_until="2026-11-30T00:00:00Z",
                   poll_seconds=3600, pickup_retry_seconds=900)
        data = json.dumps(ack).encode()
        digest = hashlib.sha256(data).hexdigest()
        ticket = dict(common, collector_ack_asset_id=102, collector_ack_sha=digest, expires_at=ack["valid_until"])
        row = dict(id=102, name="bare-personal-204-r28-collector-ack-"+"a"*32+".json",
                   created_at="2026-11-25T00:56:00Z", size=len(data))
        class Draft:
            def asset_info(self, release, name, size, sha, aid):
                if (name, size, aid) != (row["name"],len(data),102):
                    raise ValueError("Wrong asset")
            def download(self, aid, size, sha, out):
                out.write(data)
        api = Draft()
        self.assertEqual(s.private_witness_policy(api,{"assets":[row]},ticket,start),s.policy(ticket,ack))
        for bad in (ticket | {"collector_ack_sha":"0"*64}, ticket | {"artifact_ceiling_bytes":12346},
                    ticket | {"collector_ack_asset_id":900}):
            with self.assertRaises(ValueError):
                s.private_witness_policy(api,{"assets":[row]},bad,start)
        with self.assertRaisesRegex(ValueError,"before the original run"):
            s.private_witness_policy(api,{"assets":[row]},ticket,"2026-11-25T00:54:00Z")

    def test_wrong_scope_and_unsettled_repository_stop(self):
        for field, value in (("id",11),("fork",True),("private",True),("visibility","private")):
            with patch.dict(self.p.repo, {field:value}), self.assertRaises(ValueError):
                self.admit()
        with patch.dict(self.env, RUNNER_ENVIRONMENT="self-hosted"), self.assertRaises(ValueError):
            self.admit()
        self.p.runs = [dict(id=81)]
        self.assertEqual(self.admit(),"admitted")
        self.p.runs = [dict(id=82)]
        with self.assertRaisesRegex(ValueError,"Another"):
            self.admit()
        self.p.runs = []
        row = dict(id=1,size_in_bytes=24,name="old",expired=False,expires_at="2030-01-10T00:00:00Z")
        for bad in (row | {"size_in_bytes":-1},row | {"expired":"false"},row | {"expires_at":None}):
            self.p.rows = [bad]
            with self.assertRaises(ValueError):
                self.admit()
        seq = [dict(total_count=1,artifacts=[row]), dict(total_count=0,artifacts=[])]
        with self.assertRaisesRegex(ValueError,"settling"):
            s.receipt_rows(lambda p:seq.pop(0))
        with self.assertRaisesRegex(ValueError,"Incomplete"):
            s.receipt_rows(lambda p:dict(total_count=100,artifacts=[]))

    def test_actual_five_cache_sizes_leave_fallback_and_128_mib(self):
        sizes = (2742685925,1495649356,2440554209,2318534667,849253635)
        self.p.cache = [dict(id=cid,key="k",ref="refs/heads/x",version="v",size_in_bytes=n)
                        for cid,n in zip(s.AUDITED_CACHES,sizes)]
        peak = s.cache_fallback(self.p.get,self.env,451*s.MIB)
        self.assertEqual(10*1024**3 - peak, 281517792)
        self.p.cache_limit = 9
        with self.assertRaises(s.StorageFull):
            s.cache_fallback(self.p.get,self.env,451*s.MIB)
        self.p.cache_limit = 20
        with self.assertRaisesRegex(ValueError,"paid capacity"):
            s.cache_fallback(self.p.get,self.env,1)
        self.p.cache_limit = 10
        self.p.usage = 10*1024**3-s.CACHE_FLOOR-2*s.MIB-1
        self.assertEqual(s.cache_fallback(self.p.get,self.env,1),10*1024**3)
        with self.assertRaises(s.StorageFull):
            s.cache_fallback(self.p.get,self.env,2)
        self.p.cache.append(self.p.cache[0])
        with self.assertRaisesRegex(ValueError,"Ambiguous"):
            s.cache_fallback(self.p.get,self.env,1)
