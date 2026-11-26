"""Only the fixed origin, run, slot, manifest, recipient dispatch and readback type can cross heads."""
import json
from pathlib import Path
import tempfile
import unittest

import r30_parent as p


class FixedParentTests(unittest.TestCase):
    def test_production_and_trial_are_distinct_and_cannot_accept_another_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'event.json')
            env = {
                "GITHUB_REPOSITORY": "Areal-U/bare-runner-disk-probe", "GITHUB_ACTOR": "Areal-U",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a"*40,
                "GITHUB_RUN_ID": "67000000000", "GITHUB_EVENT_PATH": str(path), "R28_HEAD_SHA": "a"*40,
                "R28_SLOT": "2", "R28_PARENT_RUN": str(p.RUN), "R28_PARENT_BACKEND": "draft",
                "R28_EXPECTED_PARENT_KEY": p.KEY, "R28_PARENT_SHA": p.SHA, "R28_PARENT_IDENTITY": p.IDENTITY,
                "R28_PARENT_MANIFEST": str(p.MANIFEST), "R28_PARENT_MANIFEST_SHA": p.MANIFEST_SHA,
            }
            for ref, mode, readonly in [(p.PRODUCTION_REF, "build-apk", "false"),
                                        (p.TRIAL_REF, "verify-r30-s1", "true")]:
                event = {"repository":{"id":1450926240}, "sender":{"id":292261483}, "inputs":{"mode":mode}}
                path.write_text(json.dumps(event))
                configured = dict(env, GITHUB_REF=ref, R28_PARENT_READBACK_ONLY=readonly)
                self.assertTrue(p.authorized(configured))
                for field in ('R28_SLOT', 'R28_PARENT_RUN', 'R28_PARENT_IDENTITY', 'R28_PARENT_SHA',
                              'R28_PARENT_MANIFEST', 'R28_PARENT_MANIFEST_SHA', 'R28_EXPECTED_PARENT_KEY',
                              'R28_HEAD_SHA', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_ACTOR'):
                    with self.subTest(mode=mode, field=field):
                        self.assertFalse(p.authorized({**configured, field: "other"}))
                for field, value in [('GITHUB_RUN_ID',str(p.RUN)), ('R28_PARENT_READBACK_ONLY',
                                      "false" if readonly == "true" else "true")]:
                    self.assertFalse(p.authorized({**configured,field:value}))
                event['sender']['id'] = 1
                path.write_text(json.dumps(event))
                self.assertFalse(p.authorized(configured))
