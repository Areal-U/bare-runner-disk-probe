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
            runs = self.runs if "status=in_progress&" in path else []
            return dict(total_count=len(runs), workflow_runs=runs)
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
        common = dict(campaign="bare-personal-204-r30", branch="bare-coexist-v2.0.4",
                      head="2"*40, collector_registration_id="Automation_"+"b"*32,
                      owner_destination_id="libfile_private_owner", registration_nonce="a"*32, recipient="test",
                      storage_policy=s.POLICY, artifact_ceiling_bytes=12345, storage_valid_until="2027-01-01T00:00:00Z")
        ack = dict(common, schema=1, state="collector-read-back-owner-reservation",
                   observed_at="2026-11-25T00:55:00Z", valid_until="2026-11-30T00:00:00Z",
                   poll_seconds=3600, pickup_retry_seconds=900)
        data = json.dumps(ack).encode()
        digest = hashlib.sha256(data).hexdigest()
        ticket = dict(common, collector_ack_asset_id=102, collector_ack_sha=digest, expires_at=ack["valid_until"])
        row = dict(id=102, name="bare-personal-204-r30-collector-ack-"+"a"*32+".json",
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

    def test_run_inventory_recheck_requires_two_matching_complete_views(self):
        calls = []
        def scripted(*views):
            def get(path):
                state = path.split("status=")[1].split("&")[0]
                scan = len(calls) // len(s.ACTIVE_STATES)
                self.assertEqual(state, s.ACTIVE_STATES[len(calls) % len(s.ACTIVE_STATES)])
                calls.append(state)
                return views[scan].get(state, dict(total_count=0, workflow_runs=[]))
            return get

        own = {"in_progress": dict(total_count=1, workflow_runs=[dict(id=81, status="in_progress")])}
        foreign = {"pending": dict(total_count=4, workflow_runs=[{}, {"id": 82}])}
        discrepant = {"queued": dict(total_count=1, workflow_runs=[])}
        malformed = {"queued": dict(total_count=0)}
        duplicate = own | {"queued": dict(total_count=1, workflow_runs=[dict(id=81)])}
        with patch.object(s.time, "sleep") as pause, contextlib.redirect_stdout(io.StringIO()):
            s.check_active_runs(scripted(own), self.env)
            self.assertEqual(len(calls), 5)
            pause.assert_not_called()
            for views, error, expected_calls in (
                ((discrepant, own, own), None, 15),
                ((malformed, own, own), None, 15),
                ((duplicate, own, own), None, 15),
                ((discrepant, own, {}), "rechecks differ", 15),
                ((malformed, malformed), "recheck incomplete: state=queued", 10),
                ((discrepant, discrepant), "count=1 rows=0", 10),
                ((foreign,), "Another run 82 in state=pending count=4 rows=2", 4),
                ((discrepant, own, foreign), "Another run 82 in state=pending", 14)):
                calls.clear()
                with self.subTest(error=error):
                    if error:
                        with self.assertRaisesRegex(s.StorageUnconfirmed, error):
                            s.check_active_runs(scripted(*views), self.env)
                    else:
                        s.check_active_runs(scripted(*views), self.env)
                    self.assertEqual(len(calls), expected_calls)

    def test_run_inventory_recheck_deadline_interrupts_a_blocked_read(self):
        import select
        first = 0
        def get(_):
            nonlocal first
            first += 1
            if first > len(s.ACTIVE_STATES):
                select.select([], [], [], 2)
            return dict(total_count=1, workflow_runs=[])

        set_timer = s.signal.setitimer
        def short_timer(which, seconds):
            self.assertIn(seconds, (30, 0))
            return set_timer(which, min(seconds, 0.02))
        with patch.object(s.signal, "setitimer", side_effect=short_timer), patch.object(s.time, "sleep"):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(s.StorageUnconfirmed, "exceeded 30 seconds"):
                s.check_active_runs(get, self.env)
        self.assertEqual(first, 6)
        self.assertEqual(s.signal.getitimer(s.signal.ITIMER_REAL), (0, 0))

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


class ArtifactPaginationTests(unittest.TestCase):
    @staticmethod
    def row(aid, **updates):
        return {"id": aid, "size_in_bytes": aid, "name": str(aid), "expired": False,
                "expires_at": "2030-01-01T00:00:00Z", "digest": f"sha256:{aid:064x}"} | updates

    def read(self, layouts, run_id=None):
        from urllib.parse import parse_qs, urlsplit
        def get(path):
            query = parse_qs(urlsplit(path).query)
            width, page = int(query["per_page"][0]), int(query["page"][0])
            expected, pages = layouts[width]
            total, rows = pages[page - 1]
            self.assertEqual(len(pages), expected)
            return {"total_count": total, "artifacts": rows}
        with patch.object(s, "ARTIFACT_PAGE_SIZES", tuple(layouts)), contextlib.redirect_stdout(io.StringIO()):
            return s.receipt_rows(get, run_id=run_id)

    def test_lagging_count_needs_two_independent_complete_views(self):
        a, b, c = map(self.row, (1, 2, 3))
        layouts = {100: (1, [(5, [a,b,c])]), 2: (2, [(3, [a,b]), (3,[c])]), 3: (2, [(3,[a,b,c]),(3,[])])}
        self.assertEqual(set(self.read(layouts)), {1,2,3})
        with self.assertRaisesRegex(s.StorageUnconfirmed, "no two consecutive"):
            self.read(dict(list(layouts.items())[:2]))

    def test_metadata_of_any_visible_id_must_match_even_at_equal_size(self):
        a = self.row(1)
        layouts = {100:(1,[(3,[a])]), 50:(1,[(1,[a | {"digest": "other"}])])}
        with self.assertRaisesRegex(s.StorageUnconfirmed, "ID 1 changed metadata"):
            self.read(layouts)

    def test_missing_row_cannot_be_excused_by_two_lower_matching_totals(self):
        a,b = map(self.row,(1,2))
        layouts = {100:(1,[(3,[a,b])]),50:(1,[(1,[a])]),20:(1,[(1,[a])])}
        with self.assertRaisesRegex(s.StorageUnconfirmed, r"previously observed IDs: \[2\]"):
            self.read(layouts)

    def test_persistent_incomplete_duplicate_crosspage_and_moving_total_are_rejected(self):
        a,b,c = map(self.row,(1,2,3))
        for bad in [
            {100:(1,[(8,[a,b])]),50:(1,[(8,[a,b])])},
            {100:(1,[(2,[a,a])]),50:(1,[(2,[a,a])])},
            {2:(2,[(3,[a,b]),(3,[b])]),50:(1,[(2,[a,b])])},
            {2:(2,[(4,[a,b]),(3,[c])]),50:(1,[(3,[a,b,c])])},
        ]:
            with self.subTest(layouts=tuple(bad)), self.assertRaisesRegex(s.StorageUnconfirmed, "Incomplete"):
                self.read(bad)

    def test_two_complete_but_different_layouts_do_not_allow_a_write(self):
        a,b = map(self.row,(1,2))
        with self.assertRaisesRegex(s.StorageUnconfirmed, "differing IDs"):
            self.read({100:(1,[(1,[a])]),50:(1,[(2,[a,b])])})

    def test_deadline_interrupts_one_blocked_get(self):
        with patch.object(s, "INVENTORY_SECONDS", 0.025), self.assertRaisesRegex(s.StorageUnconfirmed, "deadline"):
            s.receipt_rows(lambda path: s.time.sleep(1))
        self.assertEqual(s.signal.getitimer(s.signal.ITIMER_REAL),(0,0))

    def test_owner_lease_expiry_is_rechecked_after_inventory(self):
        now = 1_800_000_000
        provider = Provider()
        settings = ENV | {"R28_STORAGE_UNTIL": str(now+s.DAY+7*60)}
        with patch.object(s.time, "time", side_effect=[now,now+1]), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(s.StorageUnconfirmed, "expired during"):
                s.admit(provider.get, settings, 1, 1, stage="outcome")

    def test_5000_receipts_including_the_exact_multiple_terminal_page(self):
        from urllib.parse import parse_qs, urlsplit
        rows = [self.row(idx+1) for idx in range(s.MAX_ARTIFACTS)]
        calls = []
        def get(path):
            q = parse_qs(urlsplit(path).query)
            width, page = int(q["per_page"][0]), int(q["page"][0])
            calls.append((width,page))
            return {"total_count": len(rows), "artifacts": rows[(page-1)*width:page*width]}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(len(s.receipt_rows(get)),5000)
        self.assertEqual([p for width,p in calls if width==100],list(range(1,52)))
        self.assertEqual([p for width,p in calls if width==99],list(range(1,52)))

    def test_foreign_run_arriving_during_inventory_blocks_write(self):
        provider = Provider()
        def get(path):
            if "/actions/artifacts?" in path:
                provider.runs = [{"id": 82, "status": "in_progress"}]
            return provider.get(path)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(s.StorageUnconfirmed,"Another run 82"):
            s.admit(get,ENV,1,1,stage="outcome",now=1_800_000_000)

    def test_only_corroborated_growth_owned_by_our_run_is_accepted(self):
        a = self.row(1)
        source = {"id":81,"repository_id":s.REPO_ID,"head_repository_id":s.REPO_ID}
        b = self.row(2, workflow_run=source)
        first = (1,[(1,[a])])
        full = (1,[(2,[a,b])])
        incomplete = (1,[(4,[a,b])])
        self.assertEqual(set(self.read({100:first,99:full,50:full},81)),{1,2})
        for layouts in [{100:first,99:full}, {100:first,99:full,50:first},
                        {100:first,99:full,50:incomplete,20:full}]:
            with self.subTest(layouts=tuple(layouts)), self.assertRaises(s.StorageUnconfirmed):
                self.read(layouts,81)
        for foreign in (source | {"id":82}, source | {"repository_id":2},
                        source | {"head_repository_id":2}, None):
            new = self.row(2, workflow_run=foreign)
            view = (1,[(2,[a,new])])
            with self.subTest(foreign=foreign), self.assertRaisesRegex(s.StorageUnconfirmed, "unbound additions"):
                self.read({100:first,99:(1,[(3,[a,new])]),50:view,20:view},81)
