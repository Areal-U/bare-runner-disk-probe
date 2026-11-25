import os
import unittest
from unittest.mock import patch
import anon_peer as a


class Tests(unittest.TestCase):
    def setUp(self):
        self.c={"run":a.SOURCE_RUN+1,"attempt":2,"head":"a"*40,"source_run":a.SOURCE_RUN,
                "source_head":a.SOURCE_HEAD,"release":a.RELEASE}
        self.env=patch.dict(os.environ,GITHUB_REPOSITORY=a.REPO,GITHUB_JOB="receive",
                           GITHUB_RUN_ID=str(self.c["run"]),GITHUB_RUN_ATTEMPT="2",TRIAL_SHA="a"*40,
                           GH_TOKEN="not-for-anonymous-use")
        self.env.start();self.addCleanup(self.env.stop)

    def probe(self,rows):
        calls=[]
        class Connection:
            def __init__(conn,host,timeout):self.assertEqual((host,timeout),(a.API,10))
            def request(conn,method,path,headers):
                self.assertEqual(method,"GET");self.assertEqual(set(headers),{"User-Agent","Accept","X-GitHub-Api-Version"})
                self.assertEqual(headers["Accept"],"application/octet-stream")
                calls.append(path)
            def getresponse(conn):
                status,dest=rows.pop(0)
                return type("Response",(),{"status":status,"getheader":lambda s,k:dest})()
            def close(conn):pass
        with patch.object(a.http.client,"HTTPSConnection",Connection),patch.object(a.time,"time",return_value=1000):
            result=a.sample(self.c)
        self.assertEqual(calls,[f"/repos/{a.REPO}/releases/assets/{i}" for i in a.ASSETS])
        return result

    def test_genuine_scope_and_freshness(self):
        result=self.probe([(404,None),(404,None)])
        for asset in a.ASSETS:
            self.assertTrue(a.valid(result,asset,self.c,now=1000+a.MAX_AGE))
            self.assertFalse(a.valid(result,asset,self.c,now=1001+a.MAX_AGE))
            self.assertFalse(a.valid(result,asset,self.c,now=999))
            self.assertFalse(a.valid(result,asset,{**self.c,"attempt":3},now=1000))
        self.assertFalse(a.valid({**result,"scope":{**result["scope"],"attempt":2.0}},a.ASSETS[0],self.c,now=1000))
        self.assertFalse(a.valid({**result,"ids":[a.ASSETS[0]]*2},a.ASSETS[0],self.c,now=1000))

    def test_rate_denial_never_substitutes(self):
        result=self.probe([(403,None),(404,None)])
        self.assertFalse(a.valid(result,a.ASSETS[0],self.c,now=1000))
        self.assertTrue(a.valid(result,a.ASSETS[1],self.c,now=1000))
        result=self.probe([(429,None),(500,None)])
        self.assertEqual(result["ids"],[])

    def test_redirect_and_visible_bytes_stop(self):
        for status,where in ((302,"https://example.invalid"),(404,""),(200,None)):
            with self.assertRaisesRegex(ValueError,"content or a redirect"):
                self.probe([(status,where)])
        with patch.dict(os.environ,GITHUB_JOB="issue"):
            with self.assertRaisesRegex(ValueError,"ordinary receiver"):
                a.sample(self.c)


if __name__=="__main__":unittest.main()
