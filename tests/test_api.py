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
