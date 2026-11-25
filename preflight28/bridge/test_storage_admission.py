import contextlib
import io
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
        s.draft_room({"assets":[{}]*991}, self.env, claim=True)
        with self.assertRaisesRegex(ValueError,"Release asset slots"):
            s.draft_room({"assets":[{}]*992},self.env,claim=True)
        s.draft_room({"assets":[{}]*992},self.env,claim=False)
        s.draft_room({"assets":[{}]*1000},env,claim=False)

    def test_actual_receive_time_covers_all_retention_and_sender_timeout(self):
        self.env["R28_STORAGE_UNTIL"] = str(self.now + s.DAY + 7*60 - 1)
        with self.assertRaisesRegex(ValueError, "expires"):
            self.admit()
        self.env["R28_STORAGE_UNTIL"] = str(self.now + s.DAY + 7*60)
        self.assertEqual(self.admit(),"admitted")

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
