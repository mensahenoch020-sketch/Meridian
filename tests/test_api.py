import unittest, tempfile, threading, json, http.client, os
import server

class BankingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        server.DB_PATH=os.path.join(cls.temp.name,"test.db")
        server.init_db()
        cls.http=server.ThreadingHTTPServer(("127.0.0.1",0),server.Handler)
        cls.port=cls.http.server_address[1]
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.temp.cleanup()

    def request(self,path,data=None,cookie=None,origin=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.port)
        headers={"Content-Type":"application/json"}
        if cookie: headers["Cookie"]=cookie
        if origin: headers["Origin"]=origin
        conn.request("POST" if data is not None else "GET",path,json.dumps(data) if data is not None else None,headers)
        r=conn.getresponse()
        raw=r.read()
        result=json.loads(raw) if "application/json" in r.getheader("Content-Type","") else raw.decode()
        out=(r.status,result,r.getheader("Set-Cookie"))
        conn.close()
        return out

    def account(self):
        import secrets
        email=secrets.token_hex(8)+"@test.demo"
        status,data,cookie=self.request("/api/register",{"name":"Test Person","email":email,"password":"StrongDemoPassword123!"})
        self.assertEqual(status,200,data)
        return email,cookie,data["user"]["id"]

    def balance(self,cookie):
        status,data,_=self.request("/api/me",cookie=cookie)
        self.assertEqual(status,200)
        return data["user"]

    def test_transfer_and_persistence(self):
        a,ca,_=self.account()
        b,cb,_=self.account()
        status,data,_=self.request("/api/transfer",{"email":b,"amount":12345},ca)
        self.assertEqual(status,200,data)
        self.assertEqual(self.balance(ca)["usd"],987655)
        self.assertEqual(self.balance(cb)["usd"],1012345)
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT usd FROM users WHERE email=?",(a,)).fetchone()["usd"],987655)
        for cookie in (ca,cb):
            self.assertEqual(len(self.request("/api/transactions",cookie=cookie)[1]["transactions"]),1)

    def test_invalid_transfers_do_not_change_balances(self):
        a,ca,_=self.account()
        b,cb,_=self.account()
        for body in [{"email":b,"amount":1000001},{"email":b,"amount":-1},{"email":b,"amount":1.5},{"email":b,"amount":True},{"email":a,"amount":1},{"email":"missing@demo.test","amount":1}]:
            self.assertEqual(self.request("/api/transfer",body,ca)[0],400)
        self.assertEqual(self.balance(ca)["usd"],1000000)
        self.assertEqual(self.balance(cb)["usd"],1000000)

    def test_trade_roundtrip(self):
        _,cookie,_=self.account()
        self.assertEqual(self.request("/api/trade",{"side":"buy","sats":1000000},cookie)[0],200)
        self.assertEqual(self.balance(cookie)["btc"],1000000)
        self.assertEqual(self.balance(cookie)["usd"],932500)
        self.assertEqual(self.request("/api/trade",{"side":"sell","sats":1000000},cookie)[0],200)
        self.assertEqual(self.balance(cookie)["btc"],0)
        self.assertEqual(self.balance(cookie)["usd"],1000000)
        self.assertEqual(self.request("/api/trade",{"side":"sell","sats":1000000},cookie)[0],400)
        self.assertEqual(self.request("/api/trade",{"side":"buy","sats":100000000},cookie)[0],400)

    def test_admin_and_freeze(self):
        email,cookie,uid=self.account()
        self.assertEqual(self.request("/api/admin",cookie=cookie)[0],403)
        self.assertEqual(self.request("/api/admin/freeze",{"id":uid,"frozen":True},cookie)[0],403)
        status,_,admin=self.request("/api/login",{"email":"admin@meridian.demo","password":os.environ.get("ADMIN_PASSWORD","MeridianAdmin123!")})
        self.assertEqual(status,200)
        self.assertEqual(self.request("/api/admin/freeze",{"id":uid,"frozen":True},admin)[0],200)
        self.assertEqual(self.request("/api/me",cookie=cookie)[0],401)
        self.assertEqual(self.request("/api/login",{"email":email,"password":"StrongDemoPassword123!"})[0],401)
        self.assertEqual(self.request("/api/admin/freeze",{"id":uid,"frozen":False},admin)[0],200)
        self.assertEqual(self.request("/api/login",{"email":email,"password":"StrongDemoPassword123!"})[0],200)

    def test_auth_origin_logout_and_static(self):
        self.assertEqual(self.request("/api/me")[0],401)
        _,cookie,_=self.account()
        self.assertEqual(self.request("/api/logout",{},cookie,origin="https://evil.example")[0],403)
        self.assertEqual(self.request("/api/logout",{},cookie)[0],200)
        self.assertEqual(self.request("/api/me",cookie=cookie)[0],401)
        self.assertEqual(self.request("/health")[0],200)
        self.assertEqual(self.request("/")[0],200)
        self.assertEqual(self.request("/app.js")[0],200)
        self.assertEqual(self.request("/../../server.py")[0],404)

    def test_admin_balance_adjustment_and_validation(self):
        _,cookie,uid=self.account()
        body={"id":uid,"asset":"USD","amount":2500000,"reason":"Opening balance correction"}
        self.assertEqual(self.request("/api/admin/balance",body,cookie)[0],403)
        self.assertEqual(self.request("/api/admin/balance",body)[0],401)
        status,_,admin=self.request("/api/login",{"email":"admin@meridian.demo","password":os.environ.get("ADMIN_PASSWORD","MeridianAdmin123!")})
        self.assertEqual(status,200)
        self.assertEqual(self.request("/api/admin/balance",body,admin)[0],200)
        self.assertEqual(self.balance(cookie)["usd"],2500000)
        tx=self.request("/api/transactions",cookie=cookie)[1]["transactions"][0]
        self.assertEqual(tx["kind"],"Balance adjustment")
        self.assertEqual(tx["amount"],1500000)
        self.assertEqual(tx["note"],body["reason"])
        for patch in [{"amount":-1},{"amount":True},{"amount":1.5},{"amount":100000000001},{"reason":"x"},{"asset":"ETH"},{"id":999999},{"amount":2500000}]:
            invalid=dict(body,**patch)
            self.assertEqual(self.request("/api/admin/balance",invalid,admin)[0],400,invalid)
        self.assertEqual(self.balance(cookie)["usd"],2500000)
        self.assertEqual(self.request("/api/admin/balance",dict(body,asset="BTC",amount=123456789),admin)[0],200)
        self.assertEqual(self.balance(cookie)["btc"],123456789)
        self.assertEqual(self.request("/api/admin/balance",dict(body,amount=0),admin)[0],200)
        self.assertEqual(self.balance(cookie)["usd"],0)
        audit=self.request("/api/admin",cookie=admin)[1]["audit"]
        changes=[json.loads(a["action"]) for a in audit if a["action"].startswith("{")]
        self.assertEqual(len([a for a in changes if a["customer_id"]==uid]),3)
        self.assertEqual(changes[0]["previous"],2500000)
        self.assertEqual(changes[0]["balance"],0)
        admin_id=self.balance(admin)["id"]
        self.assertEqual(self.request("/api/admin/balance",dict(body,id=admin_id),admin)[0],400)

    def test_proxy_rate_limits_are_isolated_and_success_resets(self):
        email,cookie,_=self.account()
        for _ in range(20):
            self.assertEqual(self.request("/api/login",{"email":email,"password":"wrong"})[0],401)
        self.assertEqual(self.request("/api/login",{"email":email,"password":"StrongDemoPassword123!"})[0],429)
        other,_,_=self.account()
        self.assertEqual(self.request("/api/login",{"email":other,"password":"StrongDemoPassword123!"})[0],200)
        with server.connect() as db:
            key=server.hashlib.sha256(("127.0.0.1|"+other).encode()).hexdigest()
            self.assertIsNone(db.execute("SELECT * FROM attempts WHERE ip=?",(key,)).fetchone())

    def test_configured_public_origin_through_proxy(self):
        from unittest.mock import patch
        with patch.dict(os.environ,{"PUBLIC_ORIGIN":"https://bank.example.com"}):
            status,_,cookie=self.request("/api/login",{"email":"sam@meridian.demo","password":"MeridianDemo123!"},origin="https://bank.example.com")
            self.assertEqual(status,200)
            self.assertEqual(self.request("/api/logout",{},cookie,origin="https://bank.example.com.evil.test")[0],403)
            self.assertEqual(self.request("/api/logout",{},cookie,origin="https://bank.example.com")[0],200)
        with patch.dict(os.environ,{"RAILWAY_PUBLIC_DOMAIN":"bank.up.railway.app"}):
            self.assertEqual(self.request("/api/login",{"email":"sam@meridian.demo","password":"MeridianDemo123!"},origin="https://bank.up.railway.app")[0],200)

    def test_seed_login_and_configured_admin_recovery(self):
        from unittest.mock import patch
        self.assertEqual(self.request("/api/login",{"email":"alex@meridian.demo","password":"MeridianDemo123!"})[0],200)
        original=os.environ.get("ADMIN_PASSWORD","MeridianAdmin123!")
        status,_,old_cookie=self.request("/api/login",{"email":"admin@meridian.demo","password":original})
        self.assertEqual(status,200)
        before=self.balance(old_cookie)["usd"]
        try:
            with patch.dict(os.environ,{"ADMIN_PASSWORD":"RecoveredAdminPassword123!"}):
                server.init_db()
                self.assertEqual(self.request("/api/me",cookie=old_cookie)[0],401)
                status,_,new_cookie=self.request("/api/login",{"email":"admin@meridian.demo","password":"RecoveredAdminPassword123!"})
                self.assertEqual(status,200)
                self.assertEqual(self.balance(new_cookie)["usd"],before)
                self.assertEqual(self.request("/api/login",{"email":"alex@meridian.demo","password":"MeridianDemo123!"})[0],200)
        finally:
            with patch.dict(os.environ,{"ADMIN_PASSWORD":original}): server.init_db()

    def test_invalid_admin_configuration_does_not_crash_or_reset_credentials(self):
        from unittest.mock import patch
        original=os.environ.get("ADMIN_PASSWORD","MeridianAdmin123!")
        status,_,cookie=self.request("/api/login",{"email":"admin@meridian.demo","password":original})
        self.assertEqual(status,200)
        before=self.balance(cookie)
        for invalid in ("short","","x"*129):
            with patch.dict(os.environ,{"ADMIN_PASSWORD":invalid}):
                with self.assertLogs(level="WARNING") as logs:
                    server.init_db()
                self.assertIn("ADMIN_PASSWORD ignored",logs.output[0])
                self.assertEqual(self.balance(cookie),before)
                with server.connect() as db:
                    row=db.execute("SELECT * FROM users WHERE email='admin@meridian.demo'").fetchone()
                    self.assertEqual(row["password"],server.password_hash(original,row["salt"]))

    def test_fresh_database_with_invalid_admin_password_can_be_recovered(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(server,"DB_PATH",os.path.join(tmp,"fresh.db")):
                with patch.dict(os.environ,{"ADMIN_PASSWORD":"short"}):
                    with self.assertLogs(level="WARNING"): server.init_db()
                with server.connect() as db:
                    row=db.execute("SELECT * FROM users WHERE role='admin'").fetchone()
                    for password in ("short","MeridianAdmin123!"):
                        self.assertNotEqual(row["password"],server.password_hash(password,row["salt"]))
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0],3)
                with patch.dict(os.environ,{"ADMIN_PASSWORD":"RecoveredAdminPassword123!"}): server.init_db()
                with server.connect() as db:
                    row=db.execute("SELECT * FROM users WHERE role='admin'").fetchone()
                    self.assertEqual(row["password"],server.password_hash("RecoveredAdminPassword123!",row["salt"]))

    def test_signup_validation_messages(self):
        for data,expected in [
            ({"name":"","email":"valid@example.com","password":"LongPassword123!"},"full name"),
            ({"name":"Person","email":"invalid","password":"LongPassword123!"},"email"),
            ({"name":"Person","email":"valid@example.com","password":"short"},"12–128")]:
            status,result,_=self.request("/api/register",data)
            self.assertEqual(status,400)
            self.assertIn(expected,result["error"])

    def test_concurrent_transfers_cannot_overdraw(self):
        from concurrent.futures import ThreadPoolExecutor
        _,cookie,_=self.account()
        target,other,_=self.account()
        def transfer(_): return self.request("/api/transfer",{"email":target,"amount":750000},cookie)[0]
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(transfer,range(2))),[200,400])
        self.assertEqual(self.balance(cookie)["usd"],250000)
        self.assertEqual(self.balance(other)["usd"],1750000)

if __name__=="__main__": unittest.main()
