"""Meridian planning, simulated credit, requests and account security."""
import sqlite3, secrets, hashlib, hmac, base64, struct, time, json
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

CATEGORIES=("Essentials","Food","Travel","Shopping","Entertainment","Transfers","Other")
def schema(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS spaces(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),name TEXT NOT NULL,target INTEGER NOT NULL CHECK(target>0),balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0),created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),name TEXT NOT NULL,amount INTEGER NOT NULL CHECK(amount>0),due TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS payment_requests(id TEXT PRIMARY KEY,requester INTEGER REFERENCES users(id),payer INTEGER REFERENCES users(id),amount INTEGER NOT NULL CHECK(amount>0),note TEXT,status TEXT NOT NULL DEFAULT 'pending',reference TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS cards(user_id INTEGER PRIMARY KEY REFERENCES users(id),credit_limit INTEGER NOT NULL DEFAULT 300000,balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0),frozen INTEGER NOT NULL DEFAULT 0,created TEXT DEFAULT CURRENT_TIMESTAMP,CHECK(balance<=credit_limit));
    CREATE TABLE IF NOT EXISTS customizations(user_id INTEGER PRIMARY KEY REFERENCES users(id),usd_name TEXT NOT NULL DEFAULT 'Meridian Personal',btc_name TEXT NOT NULL DEFAULT 'Bitcoin wallet',theme TEXT NOT NULL DEFAULT 'burgundy',card_order TEXT NOT NULL DEFAULT 'USD');
    CREATE TABLE IF NOT EXISTS categories(reference TEXT PRIMARY KEY REFERENCES ledger(id),category TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),title TEXT,detail TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS security(user_id INTEGER PRIMARY KEY REFERENCES users(id),recovery_hash TEXT,secret TEXT,pending_secret TEXT,pending_expires INTEGER NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 0,last_counter INTEGER NOT NULL DEFAULT -1);
    CREATE TABLE IF NOT EXISTS backup_codes(user_id INTEGER REFERENCES users(id),code_hash TEXT PRIMARY KEY);
    """)
def event(db,uid,title,detail):
    db.execute("INSERT INTO events(id,user_id,title,detail) VALUES(?,?,?,?)",(secrets.token_hex(12),uid,title,detail))
def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def integer(v,zero=False):
    if type(v)!=int or not (0 if zero else 1)<=v<=10000000000: raise ValueError("Enter a valid amount in cents.")
    return v
def text(v,label,limit=80):
    s=str(v or "").strip()
    if not s or len(s)>limit: raise ValueError(label+" is required (maximum "+str(limit)+" characters).")
    return s
def owned(db,table,uid,identifier):
    if type(identifier)!=int: raise ValueError("Select a valid item.")
    row=db.execute("SELECT * FROM "+table+" WHERE id=? AND user_id=?",(identifier,uid)).fetchone()
    if not row: raise ValueError("Item not found.")
    return row
def totp(secret,counter):
    key=base64.b32decode(secret+"="*((8-len(secret)%8)%8))
    raw=hmac.new(key,struct.pack(">Q",counter),hashlib.sha1).digest()
    offset=raw[-1]&15
    return str((struct.unpack(">I",raw[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
def check_factor(db,uid,code,consume=True):
    sec=db.execute("SELECT * FROM security WHERE user_id=?",(uid,)).fetchone()
    if not sec or not sec["enabled"]: return True
    code=str(code or "").strip()
    counter=int(time.time())//30
    if len(code)==6 and code.isdigit():
        for step in (-1,0,1):
            c=counter+step
            if c>sec["last_counter"] and hmac.compare_digest(totp(sec["secret"],c),code):
                if consume: db.execute("UPDATE security SET last_counter=? WHERE user_id=?",(c,uid))
                return True
    found=db.execute("SELECT 1 FROM backup_codes WHERE user_id=? AND code_hash=?",(uid,digest(code))).fetchone()
    if found:
        if consume: db.execute("DELETE FROM backup_codes WHERE user_id=? AND code_hash=?",(uid,digest(code)))
        return True
    return False
def require_password(u,body,hash_password):
    pw=str(body.get("password",""))
    if len(pw)>128 or not hmac.compare_digest(hash_password(pw,u["salt"]),u["password"]): raise ValueError("Your current password is incorrect.")
def recovery(db,body,hash_password):
    email=str(body.get("email","")).strip().lower()
    key=digest(str(body.get("recovery_key","")).strip())
    row=db.execute("SELECT u.*,s.recovery_hash FROM users u JOIN security s ON s.user_id=u.id WHERE u.email=?",(email,)).fetchone()
    if not row or row["role"]=="admin" or row["frozen"] or not row["recovery_hash"] or not hmac.compare_digest(key,row["recovery_hash"]):
        raise ValueError("Recovery details could not be verified.")
    if not check_factor(db,row["id"],body.get("code")): raise ValueError("Enter a fresh authenticator code or an unused backup code.")
    pw=str(body.get("new_password",""))
    if not 12<=len(pw)<=128: raise ValueError("Use a password of 12–128 characters.")
    salt=secrets.token_hex(16)
    db.execute("UPDATE users SET salt=?,password=? WHERE id=?",(salt,hash_password(pw,salt),row["id"]))
    db.execute("DELETE FROM sessions WHERE user_id=?",(row["id"],))
    db.execute("UPDATE security SET recovery_hash=NULL WHERE user_id=?",(row["id"],))
    event(db,row["id"],"Password recovered","All sessions were signed out. Generate a new recovery key in Security.")
    return {"ok":True}
def transfer(db,sender,target,amount,note,entry):
    if sender["frozen"] or target["frozen"] or sender["id"]==target["id"]: raise ValueError("Choose another active account.")
    if sender["usd"]<amount: raise ValueError("Insufficient USD balance.")
    db.execute("UPDATE users SET usd=usd-? WHERE id=?",(amount,sender["id"]))
    db.execute("UPDATE users SET usd=usd+? WHERE id=?",(amount,target["id"]))
    ref=entry(db,sender["id"],"Transfer",-amount,"USD","To "+target["email"]+" · "+note)
    incoming=entry(db,target["id"],"Transfer",amount,"USD","From "+sender["email"]+" · "+note)
    db.execute("INSERT INTO receipts(reference,recipient_reference,sender_id,recipient_id,sender_name,recipient_name,sender_email,recipient_email,amount,note) VALUES(?,?,?,?,?,?,?,?,?,?)",(ref,incoming,sender["id"],target["id"],sender["name"],target["name"],sender["email"],target["email"],amount,note))
    return ref
def state(db,u):
    uid=u["id"]
    spaces=[dict(r) for r in db.execute("SELECT * FROM spaces WHERE user_id=? ORDER BY id",(uid,))]
    expenses=[dict(r) for r in db.execute("SELECT * FROM expenses WHERE user_id=? ORDER BY due,id",(uid,))]
    card=db.execute("SELECT * FROM cards WHERE user_id=?",(uid,)).fetchone()
    minimum=min(card["balance"],max(2500,(card["balance"]*3+99)//100)) if card and card["balance"] else 0
    today=datetime.now(timezone.utc).date()
    end=today+timedelta(days=30)
    reserved=sum(e["amount"] for e in expenses if today.isoformat()<=e["due"]<=end.isoformat())
    requests=[dict(r) for r in db.execute("SELECT r.*,a.name requester_name,a.email requester_email,b.name payer_name,b.email payer_email FROM payment_requests r JOIN users a ON a.id=r.requester JOIN users b ON b.id=r.payer WHERE r.requester=? OR r.payer=? ORDER BY r.rowid DESC LIMIT 200",(uid,uid))]
    settings=db.execute("SELECT * FROM customizations WHERE user_id=?",(uid,)).fetchone()
    customization=dict(settings) if settings else {"usd_name":"Meridian Personal","btc_name":"Bitcoin wallet","theme":"burgundy","card_order":"USD"}
    ledger=[dict(r) for r in db.execute("SELECT l.*,COALESCE(c.category,CASE WHEN l.kind='Transfer' THEN 'Transfers' ELSE 'Other' END) category FROM ledger l LEFT JOIN categories c ON c.reference=l.id WHERE l.user_id=? ORDER BY l.rowid DESC LIMIT 2000",(uid,))]
    spending=[r for r in ledger if r["amount"]<0 and r["kind"] in ("Transfer","Card purchase")]
    month=today.isoformat()[:7]
    totals={}
    monthly={}
    for row in spending:
        m=row["created"][:7]
        monthly[m]=monthly.get(m,0)-row["amount"]
        if m==month: totals[row["category"]]=totals.get(row["category"],0)-row["amount"]
    history=[{"id":r["id"],"title":r["kind"],"detail":r["note"],"amount":r["amount"],"asset":r["asset"],"created":r["created"]} for r in ledger]
    history += [dict(r) for r in db.execute("SELECT * FROM events WHERE user_id=? ORDER BY rowid DESC LIMIT 500",(uid,))]
    history.sort(key=lambda r:r["created"],reverse=True)
    sec=db.execute("SELECT * FROM security WHERE user_id=?",(uid,)).fetchone()
    return {"spaces":spaces,"expenses":expenses,"card":dict(card) if card else None,"safe":{"available":u["usd"],"reserved":reserved,"card_minimum":minimum,"amount":max(0,u["usd"]-reserved-minimum),"held":sum(s["balance"] for s in spaces),"through":end.isoformat()},"requests":requests,"customization":customization,"insights":{"month":month,"total":sum(totals.values()),"categories":totals,"monthly":monthly,"spending":spending[:100],"coverage":len(ledger),"limit":2000},"timeline":history[:500],"security":{"enabled":bool(sec and sec["enabled"]),"has_recovery":bool(sec and sec["recovery_hash"]),"backup_count":db.execute("SELECT COUNT(*) FROM backup_codes WHERE user_id=?",(uid,)).fetchone()[0]}}
def action(db,u,name,b,entry,hash_password):
    uid=u["id"]
    if name=="spaces/create":
        if db.execute("SELECT COUNT(*) FROM spaces WHERE user_id=?",(uid,)).fetchone()[0]>=20: raise ValueError("You can create up to 20 Money Spaces.")
        label=text(b.get("name"),"Space name",40);target=integer(b.get("target"))
        db.execute("INSERT INTO spaces(user_id,name,target) VALUES(?,?,?)",(uid,label,target))
        event(db,uid,"Money Space created",label)
    elif name=="spaces/move":
        s=owned(db,"spaces",uid,b.get("id"));amount=integer(b.get("amount"));direction=b.get("direction")
        if direction not in ("in","out"): raise ValueError("Choose add or withdraw.")
        if direction=="in":
            if u["usd"]<amount: raise ValueError("Insufficient USD balance.")
            db.execute("UPDATE users SET usd=usd-? WHERE id=?",(amount,uid))
            db.execute("UPDATE spaces SET balance=balance+? WHERE id=?",(amount,s["id"]))
            entry(db,uid,"Space allocation",-amount,"USD",s["name"])
            if s["balance"]<s["target"]<=s["balance"]+amount: event(db,uid,"Savings goal reached",s["name"])
        else:
            if s["balance"]<amount: raise ValueError("Insufficient space balance.")
            db.execute("UPDATE spaces SET balance=balance-? WHERE id=?",(amount,s["id"]))
            db.execute("UPDATE users SET usd=usd+? WHERE id=?",(amount,uid))
            entry(db,uid,"Space withdrawal",amount,"USD",s["name"])
    elif name=="spaces/delete":
        s=owned(db,"spaces",uid,b.get("id"))
        if s["balance"]: raise ValueError("Withdraw this space's balance before deleting it.")
        db.execute("DELETE FROM spaces WHERE id=?",(s["id"],))
        event(db,uid,"Money Space closed",s["name"])
    elif name=="expenses/create":
        label=text(b.get("name"),"Expense name",60);amount=integer(b.get("amount"))
        try: due=datetime.strptime(str(b.get("due","")),"%Y-%m-%d").date()
        except ValueError: raise ValueError("Enter a valid due date.")
        if due<datetime.now(timezone.utc).date(): raise ValueError("Choose today or a future due date.")
        db.execute("INSERT INTO expenses(user_id,name,amount,due) VALUES(?,?,?,?)",(uid,label,amount,due.isoformat()))
        event(db,uid,"Expense planned",label+" · due "+due.isoformat())
    elif name=="expenses/delete":
        row=owned(db,"expenses",uid,b.get("id"));db.execute("DELETE FROM expenses WHERE id=?",(row["id"],))
    elif name=="requests/create":
        target=db.execute("SELECT * FROM users WHERE email=?",(str(b.get("email","")).strip().lower(),)).fetchone()
        if not target or target["frozen"] or target["id"]==uid: raise ValueError("Choose another active Meridian account.")
        amount=integer(b.get("amount"));note=text(b.get("note"),"Request note",140)
        if db.execute("SELECT COUNT(*) FROM payment_requests WHERE requester=? AND status='pending'",(uid,)).fetchone()[0]>=50: raise ValueError("You have too many pending requests.")
        ref=secrets.token_hex(12)
        db.execute("INSERT INTO payment_requests(id,requester,payer,amount,note) VALUES(?,?,?,?,?)",(ref,uid,target["id"],amount,note))
        event(db,uid,"Payment requested",note);event(db,target["id"],"Payment request received",u["name"]+" · "+note)
    elif name=="requests/respond":
        r=db.execute("SELECT * FROM payment_requests WHERE id=?",(str(b.get("id","")),)).fetchone()
        decision=b.get("decision")
        if not r or r["status"]!="pending": raise ValueError("This request is no longer pending.")
        if decision=="cancel":
            if r["requester"]!=uid: raise ValueError("Only the requester can cancel.")
        elif decision in ("pay","decline"):
            if r["payer"]!=uid: raise ValueError("Only the payer can respond.")
        else: raise ValueError("Choose pay, decline, or cancel.")
        ref=None
        if decision=="pay":
            target=db.execute("SELECT * FROM users WHERE id=?",(r["requester"],)).fetchone()
            ref=transfer(db,u,target,r["amount"],r["note"],entry)
        status={"pay":"paid","decline":"declined","cancel":"cancelled"}[decision]
        db.execute("UPDATE payment_requests SET status=?,reference=? WHERE id=?",(status,ref,r["id"]))
        event(db,r["requester"],"Request "+status,r["note"]);event(db,r["payer"],"Request "+status,r["note"])
        return {"ok":True,"reference":ref}
    elif name=="customize":
        usd=text(b.get("usd_name"),"USD account name",35);btc=text(b.get("btc_name"),"BTC account name",35)
        theme=b.get("theme");order=b.get("card_order")
        if theme not in ("burgundy","forest","midnight") or order not in ("USD","BTC"): raise ValueError("Choose a supported theme and account order.")
        db.execute("INSERT INTO customizations(user_id,usd_name,btc_name,theme,card_order) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET usd_name=excluded.usd_name,btc_name=excluded.btc_name,theme=excluded.theme,card_order=excluded.card_order",(uid,usd,btc,theme,order))
        event(db,uid,"Dashboard personalized","Account names, order, and theme updated.")
    elif name=="categorize":
        category=b.get("category");ref=str(b.get("reference",""))
        row=db.execute("SELECT * FROM ledger WHERE id=? AND user_id=? AND amount<0 AND kind IN ('Transfer','Card purchase')",(ref,uid)).fetchone()
        if not row or category not in CATEGORIES: raise ValueError("Choose your own spending entry and a valid category.")
        db.execute("INSERT INTO categories VALUES(?,?) ON CONFLICT(reference) DO UPDATE SET category=excluded.category",(ref,category))
    elif name=="cards/issue":
        if u["role"]!="customer": raise ValueError("Cards are available to customer accounts.")
        if db.execute("SELECT 1 FROM cards WHERE user_id=?",(uid,)).fetchone(): raise ValueError("Your virtual card is already open.")
        db.execute("INSERT INTO cards(user_id) VALUES(?)",(uid,))
        event(db,uid,"Virtual credit card opened","Simulated $3,000 limit. No card network or external payments.")
    elif name in ("cards/freeze","cards/spend","cards/repay"):
        card=db.execute("SELECT * FROM cards WHERE user_id=?",(uid,)).fetchone()
        if not card: raise ValueError("Open a virtual credit card first.")
        if name=="cards/freeze":
            frozen=b.get("frozen")
            if type(frozen)!=bool: raise ValueError("Choose a valid card status.")
            db.execute("UPDATE cards SET frozen=? WHERE user_id=?",(int(frozen),uid))
            event(db,uid,"Card frozen" if frozen else "Card unfrozen","Virtual credit card status updated.")
        else:
            amount=integer(b.get("amount"))
            if name=="cards/spend":
                if card["frozen"]: raise ValueError("Unfreeze your card before making a simulated purchase.")
                if amount>card["credit_limit"]-card["balance"]: raise ValueError("Purchase exceeds available credit.")
                merchant=text(b.get("merchant"),"Merchant",80)
                category=b.get("category","Other")
                if category not in CATEGORIES: raise ValueError("Choose a valid category.")
                db.execute("UPDATE cards SET balance=balance+? WHERE user_id=?",(amount,uid))
                ref=entry(db,uid,"Card purchase",-amount,"CREDIT",merchant)
                db.execute("INSERT INTO categories VALUES(?,?)",(ref,category))
            else:
                if amount>u["usd"] or amount>card["balance"]: raise ValueError("Payment exceeds your USD balance or card debt.")
                db.execute("UPDATE users SET usd=usd-? WHERE id=?",(amount,uid))
                db.execute("UPDATE cards SET balance=balance-? WHERE user_id=?",(amount,uid))
                entry(db,uid,"Card repayment",-amount,"USD","Virtual credit card payment")
                entry(db,uid,"Card repayment",amount,"CREDIT","Debt reduced")
    elif name=="security/recovery":
        require_password(u,b,hash_password)
        if not check_factor(db,uid,b.get("code")): raise ValueError("Enter a fresh authenticator or backup code.")
        key=secrets.token_urlsafe(32)
        db.execute("INSERT INTO security(user_id,recovery_hash) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET recovery_hash=excluded.recovery_hash",(uid,digest(key)))
        event(db,uid,"Recovery key generated","Previous recovery keys are no longer valid.")
        return {"ok":True,"recovery_key":key}
    elif name=="security/setup":
        require_password(u,b,hash_password)
        sec=db.execute("SELECT * FROM security WHERE user_id=?",(uid,)).fetchone()
        if sec and sec["enabled"]: raise ValueError("Two-factor authentication is already enabled.")
        secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        db.execute("INSERT INTO security(user_id,pending_secret,pending_expires) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET pending_secret=excluded.pending_secret,pending_expires=excluded.pending_expires",(uid,secret,int(time.time())+600))
        return {"ok":True,"secret":secret,"uri":"otpauth://totp/"+quote("Meridian:"+u["email"])+"?secret="+secret+"&issuer=Meridian&digits=6&period=30"}
    elif name=="security/enable":
        sec=db.execute("SELECT * FROM security WHERE user_id=?",(uid,)).fetchone()
        code=str(b.get("code","")).strip()
        counter=int(time.time())//30
        if not sec or sec["enabled"] or not sec["pending_secret"] or sec["pending_expires"]<time.time() or not any(hmac.compare_digest(totp(sec["pending_secret"],counter+d),code) for d in (-1,0,1)):
            raise ValueError("Enter a valid code for the current setup. Setup expires after 10 minutes.")
        codes=[secrets.token_hex(6) for _ in range(8)]
        db.execute("UPDATE security SET secret=pending_secret,pending_secret=NULL,pending_expires=0,enabled=1,last_counter=? WHERE user_id=?",(counter,uid))
        db.execute("DELETE FROM backup_codes WHERE user_id=?",(uid,))
        db.executemany("INSERT INTO backup_codes VALUES(?,?)",[(uid,digest(code)) for code in codes])
        event(db,uid,"Two-factor authentication enabled","Authenticator and backup codes protect sign-in.")
        return {"ok":True,"backup_codes":codes}
    elif name=="security/disable":
        require_password(u,b,hash_password)
        if not check_factor(db,uid,b.get("code")): raise ValueError("Enter a fresh authenticator or backup code.")
        db.execute("UPDATE security SET enabled=0,secret=NULL,pending_secret=NULL,last_counter=-1 WHERE user_id=?",(uid,))
        db.execute("DELETE FROM backup_codes WHERE user_id=?",(uid,))
        event(db,uid,"Two-factor authentication disabled","Authenticator requirement removed.")
    else: raise ValueError("Unknown action.")
    return {"ok":True}
