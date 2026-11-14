import os, json, sqlite3, secrets, hashlib, time, csv, io
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

DB_PATH = os.environ.get("DB_PATH", "data/meridian.db")
PRICE = 6750000  # USD cents per BTC
PUBLIC = Path(__file__).parent / "public"

def connect():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', frozen INTEGER NOT NULL DEFAULT 0, usd INTEGER NOT NULL DEFAULT 1000000 CHECK(usd>=0), btc INTEGER NOT NULL DEFAULT 0 CHECK(btc>=0));
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS ledger(id TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),kind TEXT,amount INTEGER,asset TEXT,note TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor INTEGER,action TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS attempts(ip TEXT PRIMARY KEY,count INTEGER,started INTEGER);
        """)
        for name,email,role,pw in [
            ("Alex Morgan","alex@meridian.demo","customer","MeridianDemo123!"),
            ("Sam Rivera","sam@meridian.demo","customer","MeridianDemo123!"),
            ("Administrator","admin@meridian.demo","admin",os.environ.get("ADMIN_PASSWORD","MeridianAdmin123!"))]:
            salt=secrets.token_hex(16)
            db.execute("INSERT OR IGNORE INTO users(name,email,salt,password,role) VALUES(?,?,?,?,?)",(name,email,salt,password_hash(pw,salt),role))

def entry(db,uid,kind,amount,asset,note):
    ref=secrets.token_hex(8)
    db.execute("INSERT INTO ledger(id,user_id,kind,amount,asset,note) VALUES(?,?,?,?,?,?)",(ref,uid,kind,amount,asset,note))
    return ref

def safe_user(row):
    return {k:row[k] for k in ("id","name","email","role","frozen","usd","btc")}

class Handler(BaseHTTPRequestHandler):
    def send(self,status,data,headers=None):
        raw=json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def current(self,db):
        cookies=dict(p.strip().split("=",1) for p in self.headers.get("Cookie","").split(";") if "=" in p)
        token=cookies.get("session","")
        return db.execute("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=? AND s.expires>? AND u.frozen=0",(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()

    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/health":
            with connect() as db:
                db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
            return self.send(200,{"ok":True})
        if path.startswith("/api/"):
            with connect() as db:
                u=self.current(db)
                if not u: return self.send(401,{"error":"Please sign in to continue."})
                if path=="/api/me": return self.send(200,{"user":safe_user(u),"price":PRICE})
                if path=="/api/transactions":
                    rows=db.execute("SELECT * FROM ledger WHERE user_id=? ORDER BY rowid DESC LIMIT 500",(u["id"],)).fetchall()
                    return self.send(200,{"transactions":[dict(r) for r in rows]})
                if path=="/api/admin":
                    if u["role"]!="admin": return self.send(403,{"error":"Administrator access required."})
                    return self.send(200,{"users":[safe_user(r) for r in db.execute("SELECT * FROM users")],"transactions":[dict(r) for r in db.execute("SELECT * FROM ledger ORDER BY rowid DESC LIMIT 200")],"audit":[dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")]})
                return self.send(404,{"error":"Not found"})
        names={"/":"index.html","/app.js":"app.js","/style.css":"style.css"}
        if path not in names: return self.send(404,{"error":"Not found"})
        raw=(PUBLIC/names[path]).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",{"html":"text/html; charset=utf-8","js":"text/javascript; charset=utf-8","css":"text/css; charset=utf-8"}[names[path].split(".")[-1]])
        self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.headers.get("Origin") and urlparse(self.headers["Origin"]).netloc != self.headers.get("Host"):
            return self.send(403,{"error":"Invalid request origin."})
        if self.headers.get("Content-Type","").split(";")[0]!="application/json":
            return self.send(415,{"error":"JSON required."})
        try:
            size=int(self.headers.get("Content-Length","0"))
            if size<0 or size>16384: raise ValueError("Request too large.")
            body=json.loads(self.rfile.read(size))
            if not isinstance(body,dict): raise ValueError("Invalid request.")
            with connect() as db:
                db.execute("BEGIN IMMEDIATE")
                path=urlparse(self.path).path
                if path in ("/api/login","/api/register"):
                    ip=self.client_address[0]
                    now=int(time.time())
                    db.execute("DELETE FROM attempts WHERE started<?",(now-300,))
                    attempt=db.execute("SELECT count FROM attempts WHERE ip=?",(ip,)).fetchone()
                    if attempt and attempt["count"]>=20: return self.send(429,{"error":"Too many attempts. Try again in five minutes."})
                    db.execute("INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET count=count+1",(ip,now))
                    db.commit()
                    db.execute("BEGIN IMMEDIATE")
                    email=str(body.get("email","")).strip().lower()
                    pw=str(body.get("password",""))
                    if path=="/api/register":
                        name=str(body.get("name","")).strip()
                        if not name or len(name)>80 or len(email)>254 or "@" not in email or not 12<=len(pw)<=128:
                            raise ValueError("Enter a name, valid email, and password of 12–128 characters.")
                        salt=secrets.token_hex(16)
                        try: db.execute("INSERT INTO users(name,email,salt,password) VALUES(?,?,?,?)",(name,email,salt,password_hash(pw,salt)))
                        except sqlite3.IntegrityError: raise ValueError("An account already uses this email.")
                    u=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
                    if not u or len(pw)>128 or not secrets.compare_digest(u["password"],password_hash(pw,u["salt"])) or u["frozen"]:
                        return self.send(401,{"error":"Incorrect credentials or account unavailable."})
                    token=secrets.token_urlsafe(32)
                    db.execute("DELETE FROM sessions WHERE expires<?",(now,))
                    db.execute("INSERT INTO sessions VALUES(?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),u["id"],now+43200))
                    db.commit()
                    cookie="session="+token+"; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
                    if os.environ.get("COOKIE_SECURE")=="1": cookie+="; Secure"
                    return self.send(200,{"user":safe_user(u)},{"Set-Cookie":cookie})
                u=self.current(db)
                if not u: return self.send(401,{"error":"Please sign in to continue."})
                if path=="/api/logout":
                    cookies=dict(p.strip().split("=",1) for p in self.headers.get("Cookie","").split(";") if "=" in p)
                    db.execute("DELETE FROM sessions WHERE token=?",(hashlib.sha256(cookies.get("session","").encode()).hexdigest(),))
                    db.commit()
                    return self.send(200,{"ok":True},{"Set-Cookie":"session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
                if path=="/api/transfer":
                    amount=body.get("amount")
                    if type(amount)!=int or not 1<=amount<=100000000: raise ValueError("Enter a valid amount in cents.")
                    target=db.execute("SELECT * FROM users WHERE email=?",(str(body.get("email","")).strip().lower(),)).fetchone()
                    if not target or target["frozen"] or target["id"]==u["id"]: raise ValueError("Choose another active Meridian account.")
                    if amount>u["usd"]: raise ValueError("Insufficient demo USD balance.")
                    note=str(body.get("note",""))[:140]
                    db.execute("UPDATE users SET usd=usd-? WHERE id=?",(amount,u["id"]))
                    db.execute("UPDATE users SET usd=usd+? WHERE id=?",(amount,target["id"]))
                    ref=entry(db,u["id"],"Transfer",-amount,"USD","To "+target["email"]+" · "+note)
                    entry(db,target["id"],"Transfer",amount,"USD","From "+u["email"]+" · "+note)
                elif path=="/api/trade":
                    sats=body.get("sats")
                    side=body.get("side")
                    if type(sats)!=int or not 1<=sats<=10000000000 or side not in ("buy","sell"): raise ValueError("Enter a valid BTC amount and side.")
                    # Round cost up for buys and proceeds down for sells; no free rounding arbitrage.
                    cost=(sats*PRICE+99999999)//100000000 if side=="buy" else sats*PRICE//100000000
                    if cost<1: raise ValueError("Trade must be worth at least $0.01.")
                    if side=="buy" and cost>u["usd"] or side=="sell" and sats>u["btc"]: raise ValueError("Insufficient balance.")
                    sign=1 if side=="buy" else -1
                    db.execute("UPDATE users SET usd=usd-?,btc=btc+? WHERE id=?",(sign*cost,sign*sats,u["id"]))
                    ref=entry(db,u["id"],"BTC "+side,-sign*cost,"USD","Simulated trade at $67,500/BTC")
                    entry(db,u["id"],"BTC "+side,sign*sats,"BTC","Simulated trade")
                elif path=="/api/admin/freeze":
                    if u["role"]!="admin": return self.send(403,{"error":"Administrator access required."})
                    uid=body.get("id")
                    frozen=body.get("frozen")
                    if type(uid)!=int or type(frozen)!=bool: raise ValueError("Invalid account status.")
                    target=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                    if not target or target["role"]=="admin": raise ValueError("Select a customer account.")
                    db.execute("UPDATE users SET frozen=? WHERE id=?",(int(frozen),uid))
                    if frozen: db.execute("DELETE FROM sessions WHERE user_id=?",(uid,))
                    db.execute("INSERT INTO audit(actor,action) VALUES(?,?)",(u["id"],("Freeze " if frozen else "Unfreeze ")+str(uid)))
                    ref="Account updated"
                else: return self.send(404,{"error":"Not found"})
                db.commit()
                self.send(200,{"ok":True,"reference":ref})
        except (ValueError,TypeError) as e:
            self.send(400,{"error":str(e)})
        except Exception:
            self.log_error("Request failed")
            self.send(500,{"error":"Unable to complete request. Please try again."})

if __name__=="__main__":
    init_db()
    print("Meridian Bank at http://localhost:"+os.environ.get("PORT","8000"),flush=True)
    ThreadingHTTPServer((os.environ.get("HOST","127.0.0.1"),int(os.environ.get("PORT","8000"))),Handler).serve_forever()
