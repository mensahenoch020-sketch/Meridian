
import unittest, tempfile, threading, os, json
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import server, banking, test_api

class FeatureTests(unittest.TestCase):
    request=test_api.BankingTests.request
    account=test_api.BankingTests.account
    balance=test_api.BankingTests.balance
    @classmethod
    def setUpClass(cls):
        cls.old_path=server.DB_PATH
        cls.tmp=tempfile.TemporaryDirectory()
        server.DB_PATH=os.path.join(cls.tmp.name,"features.db")
        server.init_db()
        cls.http=server.ThreadingHTTPServer(("127.0.0.1",0),server.Handler)
        cls.port=cls.http.server_address[1]
        threading.Thread(target=cls.http.serve_forever,daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.tmp.cleanup()
        server.DB_PATH=cls.old_path
    def action(self,cookie,path,body,status=200):
        code,result,_=self.request("/api/hub/"+path,body,cookie)
        self.assertEqual(code,status,result)
        return result
    def hub(self,cookie): return self.request("/api/hub",cookie=cookie)[1]
    def test_spaces_conserve_funds_and_require_ownership(self):
        _,c,_=self.account();_,other,_=self.account()
        self.action(c,"spaces/create",{"name":"Travel","target":50000})
        s=self.hub(c)["spaces"][0]
        self.action(other,"spaces/move",{"id":s["id"],"amount":10000,"direction":"in"},400)
        self.action(c,"spaces/move",{"id":s["id"],"amount":50000,"direction":"in"})
        h=self.hub(c)
        self.assertEqual(self.balance(c)["usd"],950000)
        self.assertEqual(h["spaces"][0]["balance"],50000)
        self.assertEqual(h["safe"]["held"],50000)
        self.assertTrue(any(e["title"]=="Savings goal reached" for e in h["timeline"]))
        self.action(c,"spaces/delete",{"id":s["id"]},400)
        self.action(c,"spaces/move",{"id":s["id"],"amount":50001,"direction":"out"},400)
        self.action(c,"spaces/move",{"id":s["id"],"amount":50000,"direction":"out"})
        self.action(c,"spaces/delete",{"id":s["id"]})
        self.assertEqual(self.balance(c)["usd"],1000000)
    def test_plan_customization_and_persistence(self):
        _,c,uid=self.account()
        date=(datetime.now(timezone.utc).date()+timedelta(days=5)).isoformat()
        self.action(c,"expenses/create",{"name":"Rent","amount":100000,"due":date})
        self.assertEqual(self.hub(c)["safe"]["amount"],900000)
        d={"usd_name":"Daily","btc_name":"Future","theme":"forest","card_order":"BTC"}
        self.action(c,"customize",d)
        self.action(c,"customize",dict(d,theme="bad"),400)
        server.init_db()
        h=self.hub(c);self.assertEqual(h["customization"]["usd_name"],"Daily")
        self.assertEqual(h["customization"]["theme"],"forest")
        self.action(c,"expenses/delete",{"id":h["expenses"][0]["id"]})
        self.assertEqual(self.hub(c)["safe"]["amount"],1000000)
    def test_payment_requests_are_authorized_and_pay_once(self):
        a,ca,_=self.account();b,cb,_=self.account();_,outsider,_=self.account()
        self.action(ca,"requests/create",{"email":b,"amount":12500,"note":"Dinner"})
        r=self.hub(ca)["requests"][0]
        self.assertEqual(len(self.hub(outsider)["requests"]),0)
        self.action(outsider,"requests/respond",{"id":r["id"],"decision":"pay"},400)
        self.action(ca,"requests/respond",{"id":r["id"],"decision":"pay"},400)
        def pay(_): return self.request("/api/hub/requests/respond",{"id":r["id"],"decision":"pay"},cb)[0]
        with ThreadPoolExecutor(max_workers=2) as pool: self.assertEqual(sorted(pool.map(pay,range(2))),[200,400])
        self.assertEqual(self.balance(ca)["usd"],1012500)
        self.assertEqual(self.balance(cb)["usd"],987500)
        paid=self.hub(ca)["requests"][0]
        self.assertEqual(paid["status"],"paid")
        self.assertEqual(self.request("/api/receipts/"+paid["reference"],cookie=ca)[0],200)
        self.action(ca,"requests/create",{"email":b,"amount":1,"note":"Decline me"})
        r=self.hub(cb)["requests"][0]
        self.action(cb,"requests/respond",{"id":r["id"],"decision":"decline"})
    def test_virtual_credit_lifecycle_and_insights(self):
        _,c,_=self.account()
        self.action(c,"cards/issue",{})
        self.action(c,"cards/issue",{},400)
        self.action(c,"cards/spend",{"amount":400000,"merchant":"Too much"},400)
        self.action(c,"cards/spend",{"amount":10000,"merchant":"Lunch","category":"Food"})
        self.assertEqual(self.balance(c)["usd"],1000000)
        h=self.hub(c);self.assertEqual(h["card"]["balance"],10000)
        self.assertEqual(h["safe"]["card_minimum"],2500)
        self.assertEqual(h["insights"]["categories"]["Food"],10000)
        self.action(c,"cards/freeze",{"frozen":True})
        self.action(c,"cards/spend",{"amount":1,"merchant":"Blocked"},400)
        self.action(c,"cards/repay",{"amount":10001},400)
        self.action(c,"cards/repay",{"amount":10000})
        self.assertEqual(self.balance(c)["usd"],990000)
        self.assertEqual(self.hub(c)["card"]["balance"],0)
        self.assertEqual(self.hub(c)["insights"]["total"],10000)
        self.action(c,"cards/freeze",{"frozen":False})
        self.action(c,"cards/spend",{"amount":100,"merchant":"Bus","category":"Travel"})
        row=self.hub(c)["insights"]["spending"][0]
        self.action(c,"categorize",{"reference":row["id"],"category":"Essentials"})
        _,other,_=self.account()
        self.action(other,"categorize",{"reference":row["id"],"category":"Other"},400)
        self.assertEqual(self.hub(c)["insights"]["categories"]["Essentials"],100)
    def test_two_factor_and_recovery_keys(self):
        email,c,uid=self.account()
        key=self.action(c,"security/recovery",{"password":"StrongDemoPassword123!"})["recovery_key"]
        setup=self.action(c,"security/setup",{"password":"StrongDemoPassword123!"})
        code=banking.totp(setup["secret"],int(banking.time.time())//30)
        enabled=self.action(c,"security/enable",{"code":code})
        backups=enabled["backup_codes"]
        self.assertEqual(len(backups),8)
        self.assertEqual(self.request("/api/login",{"email":email,"password":"StrongDemoPassword123!"})[0],400)
        self.assertEqual(self.request("/api/login",{"email":email,"password":"StrongDemoPassword123!","code":backups[0]})[0],200)
        self.assertEqual(self.request("/api/login",{"email":email,"password":"StrongDemoPassword123!","code":backups[0]})[0],400)
        self.assertNotIn("secret",self.hub(c)["security"])
        self.assertEqual(self.request("/api/recover",{"email":email,"recovery_key":"wrong","new_password":"RecoveredPassword123!"})[0],400)
        result=self.request("/api/recover",{"email":email,"recovery_key":key,"new_password":"RecoveredPassword123!","code":backups[1]})
        self.assertEqual(result[0],200,result)
        self.assertEqual(self.request("/api/me",cookie=c)[0],401)
        self.assertEqual(self.request("/api/recover",{"email":email,"recovery_key":key,"new_password":"AnotherPassword123!","code":backups[2]})[0],400)
        status,_,new=self.request("/api/login",{"email":email,"password":"RecoveredPassword123!","code":backups[2]})
        self.assertEqual(status,200)
        self.action(new,"security/disable",{"password":"RecoveredPassword123!","code":backups[3]})
        self.assertFalse(self.hub(new)["security"]["enabled"])
        with server.connect() as db:
            self.assertIsNone(db.execute("SELECT recovery_hash FROM security WHERE user_id=?",(uid,)).fetchone()[0])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM backup_codes WHERE user_id=?",(uid,)).fetchone()[0],0)
    def test_totp_reference_vector_and_replay_protection(self):
        self.assertEqual(banking.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",1),"287082")
        _,c,uid=self.account()
        setup=self.action(c,"security/setup",{"password":"StrongDemoPassword123!"})
        counter=int(banking.time.time())//30
        self.action(c,"security/enable",{"code":banking.totp(setup["secret"],counter)})
        with server.connect() as db:
            self.assertFalse(banking.check_factor(db,uid,banking.totp(setup["secret"],counter)))
            with patch("banking.time.time",return_value=(counter+1)*30):
                self.assertTrue(banking.check_factor(db,uid,banking.totp(setup["secret"],counter+1)))
                self.assertFalse(banking.check_factor(db,uid,banking.totp(setup["secret"],counter+1)))
    def test_unauthenticated_hub_and_invalid_amounts(self):
        self.assertEqual(self.request("/api/hub")[0],401)
        self.assertEqual(self.request("/api/hub/cards/issue",{})[0],401)
        _,c,_=self.account()
        for value in (-1,True,1.5,0):
            self.action(c,"spaces/create",{"name":"Invalid","target":value},400)
