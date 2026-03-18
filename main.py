"""
Task Manager REST API - FastAPI + SQLite + JWT Auth
Author: Joseph Davis
"""
import hashlib, hmac, json, secrets, sqlite3, time
from datetime import datetime
from enum import Enum
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

app = FastAPI(title="Task Manager API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer()
JWT_SECRET = secrets.token_hex(32)
DB = "tasks.db"

def get_db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON"); return conn

def init_db():
    c = get_db()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT DEFAULT '',
            status TEXT DEFAULT 'todo', priority TEXT DEFAULT 'medium',
            due_date TEXT, tags TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id));
    """); c.commit(); c.close()
init_db()

class TaskStatus(str, Enum): TODO="todo"; IN_PROGRESS="in_progress"; DONE="done"
class TaskPriority(str, Enum): LOW="low"; MEDIUM="medium"; HIGH="high"; URGENT="urgent"
class UserCreate(BaseModel): username: str = Field(..., min_length=3); password: str = Field(..., min_length=6)
class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = ""; priority: TaskPriority = TaskPriority.MEDIUM
    due_date: Optional[str] = None; tags: list[str] = []
class TaskUpdate(BaseModel):
    title: Optional[str] = None; description: Optional[str] = None
    status: Optional[TaskStatus] = None; priority: Optional[TaskPriority] = None
    due_date: Optional[str] = None; tags: Optional[list[str]] = None

def hash_pw(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"
def verify_pw(pw, stored):
    salt, hx = stored.split(":")
    return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",pw.encode(),salt.encode(),100000).hex(), hx)

import base64
def create_jwt(uid, uname):
    def b64u(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    h, p = b64u({"alg":"HS256","typ":"JWT"}), b64u({"sub":uid,"username":uname,"exp":int(time.time())+86400})
    sig = base64.urlsafe_b64encode(hmac.new(JWT_SECRET.encode(),f"{h}.{p}".encode(),hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"

def decode_jwt(token):
    parts = token.split(".")
    if len(parts)!=3: raise HTTPException(401,"Invalid token")
    pad = lambda s: s+"="*(4-len(s)%4)
    payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    if payload.get("exp",0)<time.time(): raise HTTPException(401,"Expired")
    expected = base64.urlsafe_b64encode(hmac.new(JWT_SECRET.encode(),f"{parts[0]}.{parts[1]}".encode(),hashlib.sha256).digest()).rstrip(b"=").decode()
    if not hmac.compare_digest(expected, parts[2]): raise HTTPException(401,"Bad sig")
    return payload

def get_user(creds: HTTPAuthorizationCredentials = Depends(security)): return decode_jwt(creds.credentials)

@app.post("/auth/register", status_code=201)
def register(u: UserCreate):
    c = get_db()
    try:
        c.execute("INSERT INTO users (username,password_hash) VALUES (?,?)", (u.username, hash_pw(u.password)))
        c.commit(); r = c.execute("SELECT id,username,created_at FROM users WHERE username=?", (u.username,)).fetchone()
        return dict(r)
    except sqlite3.IntegrityError: raise HTTPException(409,"Username taken")
    finally: c.close()

@app.post("/auth/login")
def login(u: UserCreate):
    c = get_db(); r = c.execute("SELECT id,username,password_hash FROM users WHERE username=?", (u.username,)).fetchone(); c.close()
    if not r or not verify_pw(u.password, r["password_hash"]): raise HTTPException(401,"Invalid credentials")
    return {"access_token": create_jwt(r["id"], r["username"]), "token_type": "bearer"}

@app.post("/tasks", status_code=201)
def create_task(t: TaskCreate, user=Depends(get_user)):
    c = get_db()
    cur = c.execute("INSERT INTO tasks (user_id,title,description,priority,due_date,tags) VALUES (?,?,?,?,?,?)",
        (user["sub"],t.title,t.description,t.priority.value,t.due_date,json.dumps(t.tags)))
    c.commit(); r = c.execute("SELECT * FROM tasks WHERE id=?", (cur.lastrowid,)).fetchone(); c.close()
    d = dict(r); d["tags"] = json.loads(d["tags"]); return d

@app.get("/tasks")
def list_tasks(user=Depends(get_user), status:Optional[TaskStatus]=None, priority:Optional[TaskPriority]=None,
              search:Optional[str]=None, page:int=Query(1,ge=1), per_page:int=Query(20,ge=1,le=100)):
    c = get_db(); conds, params = ["user_id=?"], [user["sub"]]
    if status: conds.append("status=?"); params.append(status.value)
    if priority: conds.append("priority=?"); params.append(priority.value)
    if search: conds.append("(title LIKE ? OR description LIKE ?)"); params.extend([f"%{search}%"]*2)
    w = " AND ".join(conds)
    total = c.execute(f"SELECT COUNT(*) FROM tasks WHERE {w}", params).fetchone()[0]
    rows = c.execute(f"SELECT * FROM tasks WHERE {w} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params+[per_page,(page-1)*per_page]).fetchall(); c.close()
    tasks = [dict(r) | {"tags": json.loads(dict(r)["tags"])} for r in rows]
    return {"tasks":tasks, "total":total, "page":page, "per_page":per_page}

@app.get("/tasks/{tid}")
def get_task(tid:int, user=Depends(get_user)):
    c = get_db(); r = c.execute("SELECT * FROM tasks WHERE id=? AND user_id=?", (tid,user["sub"])).fetchone(); c.close()
    if not r: raise HTTPException(404,"Not found")
    d = dict(r); d["tags"] = json.loads(d["tags"]); return d

@app.patch("/tasks/{tid}")
def update_task(tid:int, upd:TaskUpdate, user=Depends(get_user)):
    c = get_db()
    if not c.execute("SELECT 1 FROM tasks WHERE id=? AND user_id=?", (tid,user["sub"])).fetchone():
        c.close(); raise HTTPException(404,"Not found")
    updates = {}
    if upd.title is not None: updates["title"] = upd.title
    if upd.description is not None: updates["description"] = upd.description
    if upd.status is not None: updates["status"] = upd.status.value
    if upd.priority is not None: updates["priority"] = upd.priority.value
    if upd.due_date is not None: updates["due_date"] = upd.due_date
    if upd.tags is not None: updates["tags"] = json.dumps(upd.tags)
    if updates:
        updates["updated_at"] = datetime.now().isoformat()
        s = ", ".join(f"{k}=?" for k in updates)
        c.execute(f"UPDATE tasks SET {s} WHERE id=?", list(updates.values())+[tid]); c.commit()
    r = c.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone(); c.close()
    d = dict(r); d["tags"] = json.loads(d["tags"]); return d

@app.delete("/tasks/{tid}", status_code=204)
def delete_task(tid:int, user=Depends(get_user)):
    c = get_db(); res = c.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (tid,user["sub"])); c.commit(); c.close()
    if res.rowcount==0: raise HTTPException(404,"Not found")

@app.get("/tasks/stats/summary")
def stats(user=Depends(get_user)):
    c = get_db()
    by_status = {r[0]:r[1] for r in c.execute("SELECT status,COUNT(*) FROM tasks WHERE user_id=? GROUP BY status",(user["sub"],))}
    by_priority = {r[0]:r[1] for r in c.execute("SELECT priority,COUNT(*) FROM tasks WHERE user_id=? GROUP BY priority",(user["sub"],))}
    overdue = c.execute("SELECT COUNT(*) FROM tasks WHERE user_id=? AND due_date<? AND status!='done'",
        (user["sub"],datetime.now().date().isoformat())).fetchone()[0]; c.close()
    return {"by_status":by_status,"by_priority":by_priority,"overdue":overdue}

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return '<html><body style="font-family:sans-serif;background:#0a0a0a;color:#e0e0e0;padding:60px">' + \\
        '<h1>Task Manager API</h1><p>Docs: <a href="/docs">/docs</a></p>' + \\
        '<p>Endpoints: POST /auth/register, POST /auth/login, CRUD /tasks, GET /tasks/stats/summary</p></body></html>'

if __name__ == "__main__":
    import uvicorn; uvicorn.run(app, host="0.0.0.0", port=8000)
