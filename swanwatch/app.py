import base64, hashlib, hmac, json, os, re, secrets, socket, sqlite3, subprocess, tarfile, time, urllib.request
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY','change-me')
APP_NAME=os.environ.get('APP_NAME','SwanWatch')
TOTP_SECRET=os.environ.get('TOTP_SECRET','').replace(' ','').upper()
NTFY_URL=os.environ.get('NTFY_URL','').strip()
ALERT_EVENTS={x.strip() for x in os.environ.get('ALERT_EVENTS','connect,disconnect,failed-login,service').split(',') if x.strip()}
MANAGED_CONTAINERS=[x.strip() for x in os.environ.get('MANAGED_CONTAINERS','').split(',') if x.strip()]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
CONTAINER=os.environ.get('STRONGSWAN_CONTAINER','strongswan')
USER=os.environ.get('DASHBOARD_USER','admin'); PASSWORD=os.environ.get('DASHBOARD_PASSWORD','change-me')
PLEX_HOST=os.environ.get('PLEX_HOST','host.docker.internal'); PLEX_PORT=int(os.environ.get('PLEX_PORT','32400'))
DB_PATH=Path(os.environ.get('DB_PATH','/data/dashboard.db')); BACKUP_DIR=Path(os.environ.get('BACKUP_DIR','/data/backups'))
CONFIG_ROOT=Path(os.environ.get('CONFIG_ROOT','/config-source')); STARTED_AT=time.time()
MANAGED_USERS_FILE=Path(os.environ.get('MANAGED_USERS_FILE','/managed-users/dashboard-users.conf'))
MANAGED_USERS_FILE.parent.mkdir(parents=True,exist_ok=True)
DB_PATH.parent.mkdir(parents=True,exist_ok=True); BACKUP_DIR.mkdir(parents=True,exist_ok=True)

def db():
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row
    conn.execute('CREATE TABLE IF NOT EXISTS snapshots(ts INTEGER PRIMARY KEY, users INTEGER, bytes_in INTEGER, bytes_out INTEGER)')
    conn.execute('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, message TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS active_sessions(sa_id TEXT PRIMARY KEY, username TEXT, public_ip TEXT, vpn_ip TEXT, first_seen INTEGER, last_seen INTEGER)')
    conn.execute('CREATE TABLE IF NOT EXISTS user_stats(username TEXT PRIMARY KEY, last_seen INTEGER, last_public_ip TEXT, connections INTEGER DEFAULT 0)')
    return conn

def run(args,timeout=12):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
        return p.returncode,p.stdout.strip(),p.stderr.strip()
    except Exception as e:return 1,'',str(e)


def totp_code(secret, at=None):
    if not secret:return None
    try:key=base64.b32decode(secret + '='*((8-len(secret)%8)%8),casefold=True)
    except Exception:return None
    counter=int((at or time.time())//30).to_bytes(8,'big')
    digest=hmac.new(key,counter,hashlib.sha1).digest();off=digest[-1]&15
    return str((int.from_bytes(digest[off:off+4],'big')&0x7fffffff)%1000000).zfill(6)

def verify_totp(code):
    if not TOTP_SECRET:return True
    code=re.sub(r'\D','',str(code or ''))
    return any(hmac.compare_digest(code,totp_code(TOTP_SECRET,time.time()+step*30) or '') for step in (-1,0,1))

def notify(kind,message):
    if not NTFY_URL or kind not in ALERT_EVENTS:return
    try:
        req=urllib.request.Request(NTFY_URL,data=message.encode(),headers={'Title':APP_NAME,'Tags':'shield'})
        urllib.request.urlopen(req,timeout=4).read()
    except Exception:pass

def add_event(kind,message,send_alert=False):
    with db() as c:c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(int(time.time()),kind,message))
    if send_alert:notify(kind,message)

def sync_sessions(sessions):
    now=int(time.time()); current={}
    for item in sessions:
        sid=f"{item.get('connection','')}:{item.get('id','')}"; current[sid]=item
    with db() as c:
        previous={r['sa_id']:dict(r) for r in c.execute('SELECT * FROM active_sessions')}
        for sid,item in current.items():
            if sid not in previous:
                msg=f"{item['username']} connected from {item['public_ip']}"
                c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(now,'connect',msg));notify('connect',msg)
                c.execute('INSERT OR REPLACE INTO active_sessions VALUES(?,?,?,?,?,?)',(sid,item['username'],item['public_ip'],item['vpn_ip'],now,now))
                c.execute('INSERT INTO user_stats(username,last_seen,last_public_ip,connections) VALUES(?,?,?,1) ON CONFLICT(username) DO UPDATE SET last_seen=excluded.last_seen,last_public_ip=excluded.last_public_ip,connections=connections+1',(item['username'],now,item['public_ip']))
            else:c.execute('UPDATE active_sessions SET last_seen=? WHERE sa_id=?',(now,sid))
        for sid,row in previous.items():
            if sid not in current:
                msg=f"{row['username']} disconnected";c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(now,'disconnect',msg));notify('disconnect',msg);c.execute('DELETE FROM active_sessions WHERE sa_id=?',(sid,))

def auth(fn):
    @wraps(fn)
    def w(*a,**k):
        if not session.get('authenticated'):
            if request.path.startswith('/api/'):
                return jsonify({'error':'Authentication required'}), 401
            return redirect(url_for('login'))
        return fn(*a,**k)
    return w

def token():
    if 'csrf_token' not in session: session['csrf_token']=secrets.token_urlsafe(32)
    return session['csrf_token']
app.jinja_env.globals['csrf_token']=token

def csrf():
    if not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),session.get('csrf_token','')): abort(403)

def duration(v):
    try:s=max(0,int(float(v)))
    except:return 'Unknown'
    d,s=divmod(s,86400);h,s=divmod(s,3600);m,s=divmod(s,60)
    return ' '.join(x for x in (f'{d}d' if d else '',f'{h}h' if h else '',f'{m}m' if m else '') if x) or f'{s}s'

def bval(s):
    m=re.search(r'([0-9]+) bytes',s);return int(m.group(1)) if m else 0

def parse_sas(out):
    items=[]; cur=None
    for raw in out.splitlines():
        line=raw.rstrip(); h=re.match(r'^([^\s:][^:]*):\s+#(\d+),\s+([^,]+)',line)
        if h:
            if cur:items.append(cur)
            cur={'connection':h.group(1).strip(),'id':h.group(2),'state':h.group(3).strip(),'username':'Unknown','public_ip':'Unknown','vpn_ip':'Unknown','connected':'Unknown','connected_seconds':0,'bytes_in':0,'bytes_out':0};continue
        if not cur:continue
        s=line.strip(); m=re.search(r'established\s+(\d+)s ago',s)
        if m:cur['connected_seconds']=int(m.group(1));cur['connected']=duration(m.group(1))
        if s.startswith('remote '):
            m=re.search(r'\[([^\]]+)\]',s)
            if m:cur['username']=m.group(1)
            m=re.match(r'remote\s+([^\s\[]+)',s)
            if m and '/' not in m.group(1):cur['public_ip']=m.group(1)
            m=re.search(r'remote\s+([0-9a-fA-F:.]+/\d+)',s)
            if m:cur['vpn_ip']=m.group(1)
        if s.startswith('in '):cur['bytes_in']+=bval(s)
        elif s.startswith('out '):cur['bytes_out']+=bval(s)
    if cur:items.append(cur)
    return items

def inspect(name):
    fmt='{{.State.Status}}|{{.State.StartedAt}}|{{.RestartCount}}|{{.Config.Image}}'
    rc,o,e=run(['docker','inspect','-f',fmt,name])
    if rc:return {'status':'unavailable','image':'Unknown','restart_count':0,'error':e or 'Unavailable'}
    p=o.split('|',3);return {'status':p[0],'started_at':p[1] if len(p)>1 else None,'restart_count':int(p[2]) if len(p)>2 and p[2].isdigit() else 0,'image':p[3] if len(p)>3 else 'Unknown','error':None}

def host_health():
    result={'cpu_load':None,'memory_percent':None,'memory_used':None,'memory_total':None,'disk_percent':None,'disk_used':None,'disk_total':None,'uptime':None}
    try:
        result['cpu_load']=round(float(Path('/host/proc/loadavg').read_text().split()[0]),2)
        result['uptime']=int(float(Path('/host/proc/uptime').read_text().split()[0]))
        mem={}
        for line in Path('/host/proc/meminfo').read_text().splitlines():
            k,v=line.split(':',1);mem[k]=int(v.strip().split()[0])*1024
        total=mem['MemTotal'];avail=mem.get('MemAvailable',mem.get('MemFree',0));used=total-avail
        result.update(memory_total=total,memory_used=used,memory_percent=round(used*100/total,1))
        st=os.statvfs('/host/root');total=st.f_blocks*st.f_frsize;free=st.f_bavail*st.f_frsize;used=total-free
        result.update(disk_total=total,disk_used=used,disk_percent=round(used*100/total,1))
    except Exception:pass
    return result

def plex_health():
    started=time.time()
    try:
        with socket.create_connection((PLEX_HOST,PLEX_PORT),timeout=2):pass
        return {'status':'online','latency_ms':round((time.time()-started)*1000)}
    except Exception as e:return {'status':'offline','latency_ms':None,'error':str(e)}

def cert_info():
    cmd="f=$(find /etc/swanctl/x509 -type f 2>/dev/null | head -n1); [ -n \"$f\" ] && openssl x509 -in \"$f\" -noout -subject -issuer -enddate"
    rc,o,e=run(['docker','exec',CONTAINER,'sh','-lc',cmd])
    data={'subject':'Unknown','issuer':'Unknown','expires':None,'days_remaining':None,'error':None}
    if rc or not o:data['error']=e or 'Certificate not found';return data
    for line in o.splitlines():
        if line.startswith('subject='):data['subject']=line.split('=',1)[1].strip()
        elif line.startswith('issuer='):data['issuer']=line.split('=',1)[1].strip()
        elif line.startswith('notAfter='):
            val=line.split('=',1)[1].strip();data['expires']=val
            try:
                dt=datetime.strptime(val,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                data['days_remaining']=max(0,(dt-datetime.now(timezone.utc)).days)
            except Exception:pass
    return data

def record_snapshot(sessions):
    now=int(time.time()); tin=sum(x['bytes_in'] for x in sessions);tout=sum(x['bytes_out'] for x in sessions)
    with db() as c:
        prev=c.execute('SELECT users FROM snapshots ORDER BY ts DESC LIMIT 1').fetchone()
        c.execute('INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?)',(now,len(sessions),tin,tout))
        c.execute('DELETE FROM snapshots WHERE ts < ?',(now-7*86400,))
        if prev and prev['users']!=len(sessions):
            c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(now,'session',f'Active VPN sessions changed from {prev["users"]} to {len(sessions)}'))


def managed_users():
    if not MANAGED_USERS_FILE.exists():
        return []
    text=MANAGED_USERS_FILE.read_text(encoding='utf-8',errors='replace')
    users=[]
    pattern=r'eap-dashboard-([A-Za-z0-9_.-]+)\s*\{\s*id\s*=\s*"([^"\n]+)"\s*secret\s*=\s*"([^"\n]*)"\s*\}'
    for m in re.finditer(pattern,text,re.S):
        users.append({'key':m.group(1),'username':m.group(2)})
    return sorted(users,key=lambda x:x['username'].lower())

def quote_conf(value):
    return value.replace('\\','\\\\').replace('"','\\"')

def write_managed_users(records):
    lines=['# Managed by MyPCHelp strongSwan Dashboard.','# Do not edit while the dashboard is running.','secrets {']
    for item in sorted(records,key=lambda x:x['username'].lower()):
        lines += [f'    eap-dashboard-{item["key"]} {{',f'        id = "{quote_conf(item["username"])}"',f'        secret = "{quote_conf(item["secret"])}"','    }','']
    lines += ['}','']
    temp=MANAGED_USERS_FILE.with_suffix('.tmp')
    temp.write_text('\n'.join(lines),encoding='utf-8')
    os.chmod(temp,0o600)
    os.replace(temp,MANAGED_USERS_FILE)

def read_managed_records():
    if not MANAGED_USERS_FILE.exists(): return []
    text=MANAGED_USERS_FILE.read_text(encoding='utf-8',errors='replace')
    records=[]
    pattern=r'eap-dashboard-([A-Za-z0-9_.-]+)\s*\{\s*id\s*=\s*"([^"\n]+)"\s*secret\s*=\s*"([^"\n]*)"\s*\}'
    for m in re.finditer(pattern,text,re.S):
        records.append({'key':m.group(1),'username':m.group(2),'secret':m.group(3)})
    return records

def reload_credentials():
    return run(['docker','exec',CONTAINER,'swanctl','--load-creds','--clear','--noprompt'],20)

def backup_files():
    return sorted(({'name':p.name,'size':p.stat().st_size,'created':int(p.stat().st_mtime)} for p in BACKUP_DIR.glob('strongswan-backup-*.tar.gz')),key=lambda x:x['created'],reverse=True)

@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';r.headers['Referrer-Policy']='same-origin';r.headers['Cache-Control']='no-store';return r
@app.route('/login',methods=['GET','POST'])
def login():
    err=None
    if request.method=='POST':
        if hmac.compare_digest(request.form.get('username',''),USER) and hmac.compare_digest(request.form.get('password',''),PASSWORD) and verify_totp(request.form.get('totp','')):
            session.clear();session['authenticated']=True;token();return redirect(url_for('index'))
        add_event('failed-login',f"Failed dashboard login from {request.remote_addr}",True)
        err='Invalid credentials or verification code'
    return render_template('login.html',error=err,totp_required=bool(TOTP_SECRET),app_name=APP_NAME)
@app.route('/logout')
def logout():session.clear();return redirect(url_for('login'))
@app.route('/')
@auth
def index():return render_template('index.html',app_name=APP_NAME)
@app.route('/api/status')
@auth
def status():
    c=inspect(CONTAINER);rc,o,e=run(['docker','exec',CONTAINER,'swanctl','--list-sas']);sas=parse_sas(o) if rc==0 else [];record_snapshot(sas);sync_sessions(sas)
    return jsonify({'container':c,'sessions':sas,'active_users':len(sas),'total_in':sum(x['bytes_in'] for x in sas),'total_out':sum(x['bytes_out'] for x in sas),'longest_connection':max((x['connected_seconds'] for x in sas),default=0),'dashboard_uptime':int(time.time()-STARTED_AT),'host':host_health(),'plex':plex_health(),'certificate':cert_info(),'backups':backup_files()[:5],'error':None if rc==0 else e,'timestamp':int(time.time()),'app_name':APP_NAME,'features':{'totp':bool(TOTP_SECRET),'notifications':bool(NTFY_URL),'managed_containers':bool(MANAGED_CONTAINERS)}})
@app.route('/api/history')
@auth
def history():
    since=int(time.time())-86400
    with db() as c:
        pts=[dict(x) for x in c.execute('SELECT * FROM snapshots WHERE ts>=? ORDER BY ts',(since,))]
        events=[dict(x) for x in c.execute('SELECT * FROM events ORDER BY ts DESC LIMIT 30')]
    return jsonify({'points':pts,'events':events})
@app.route('/api/logs')
@auth
def logs():
    lines=min(max(int(request.args.get('lines','200')),20),500);rc,o,e=run(['docker','logs','--timestamps','--tail',str(lines),CONTAINER]);return jsonify({'logs':o if rc==0 else e,'error':None if rc==0 else e})
@app.route('/api/restart-vpn',methods=['POST'])
@auth
def restart_vpn():
    csrf();rc,o,e=run(['docker','restart',CONTAINER],30)
    with db() as c:c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(int(time.time()),'admin','strongSwan restart requested'))
    return (jsonify({'ok':True,'container':o}),200) if rc==0 else (jsonify({'ok':False,'error':e}),500)
@app.route('/api/backup',methods=['POST'])
@auth
def create_backup():
    csrf()
    if not CONFIG_ROOT.exists():return jsonify({'ok':False,'error':'Configuration source is not mounted'}),500
    name=f"strongswan-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz";dest=BACKUP_DIR/name
    try:
        with tarfile.open(dest,'w:gz') as tar:
            for p in CONFIG_ROOT.iterdir():
                if p.name in {'strongswan-dashboard','strongswan-dashboard-old'}:continue
                tar.add(p,arcname=p.name,recursive=True)
        with db() as c:c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(int(time.time()),'backup',f'Created {name}'))
        return jsonify({'ok':True,'name':name})
    except Exception as e:return jsonify({'ok':False,'error':str(e)}),500
@app.route('/backups/<path:name>')
@auth
def download_backup(name):
    if not re.fullmatch(r'strongswan-backup-[0-9-]+\.tar\.gz',name):abort(404)
    return send_from_directory(BACKUP_DIR,name,as_attachment=True)

@app.route('/api/users')
@auth
def users_list():
    
    users=managed_users()
    with db() as c: stats={r['username']:dict(r) for r in c.execute('SELECT * FROM user_stats')}
    for u in users:u.update(stats.get(u['username'],{}))
    return jsonify({'users':users,'file':str(MANAGED_USERS_FILE)})

@app.route('/api/users',methods=['POST'])
@auth
def users_add():
    csrf(); data=request.get_json(silent=True) or {}
    username=str(data.get('username','')).strip()
    supplied=str(data.get('password',''))
    if not re.fullmatch(r'[A-Za-z0-9._@-]{3,64}',username):
        return jsonify({'ok':False,'error':'Username must be 3-64 characters using letters, numbers, dot, underscore, @ or hyphen'}),400
    records=read_managed_records()
    if any(x['username'].lower()==username.lower() for x in records):
        return jsonify({'ok':False,'error':'That managed user already exists'}),409
    password=supplied if supplied else secrets.token_urlsafe(18)
    if len(password)<12 or any(c in password for c in '\r\n"'):
        return jsonify({'ok':False,'error':'Password must be at least 12 characters and cannot contain quotes or line breaks'}),400
    key=re.sub(r'[^A-Za-z0-9_.-]','-',username).strip('-') or secrets.token_hex(4)
    base=key; n=2
    while any(x['key']==key for x in records): key=f'{base}-{n}'; n+=1
    records.append({'key':key,'username':username,'secret':password})
    try:
        write_managed_users(records); rc,o,e=reload_credentials()
        if rc: raise RuntimeError(e or o or 'strongSwan rejected the credentials file')
        with db() as c:c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(int(time.time()),'admin',f'Added VPN user {username}'))
        return jsonify({'ok':True,'username':username,'password':password})
    except Exception as exc:
        return jsonify({'ok':False,'error':str(exc)}),500

@app.route('/api/users/<path:username>',methods=['DELETE'])
@auth
def users_delete(username):
    csrf(); records=read_managed_records(); kept=[x for x in records if x['username']!=username]
    if len(kept)==len(records): return jsonify({'ok':False,'error':'Managed user not found'}),404
    try:
        write_managed_users(kept); rc,o,e=reload_credentials()
        if rc: raise RuntimeError(e or o or 'Credential reload failed')
        with db() as c:c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(int(time.time()),'admin',f'Removed VPN user {username}'))
        return jsonify({'ok':True})
    except Exception as exc:return jsonify({'ok':False,'error':str(exc)}),500

@app.route('/api/users/<path:username>/reset',methods=['POST'])
@auth
def users_reset(username):
    csrf(); records=read_managed_records(); target=next((x for x in records if x['username']==username),None)
    if not target:return jsonify({'ok':False,'error':'Managed user not found'}),404
    password=secrets.token_urlsafe(18);target['secret']=password
    try:
        write_managed_users(records);rc,o,e=reload_credentials()
        if rc:raise RuntimeError(e or o or 'Credential reload failed')
        with db() as c:c.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)',(int(time.time()),'admin',f'Reset password for VPN user {username}'))
        return jsonify({'ok':True,'username':username,'password':password})
    except Exception as exc:return jsonify({'ok':False,'error':str(exc)}),500


@app.route('/api/sessions/<int:sa_id>/disconnect',methods=['POST'])
@auth
def disconnect_session(sa_id):
    csrf();rc,o,e=run(['docker','exec',CONTAINER,'swanctl','--terminate','--ike-id',str(sa_id)],20)
    if rc:return jsonify({'ok':False,'error':e or o or 'Disconnect failed'}),500
    add_event('admin',f'Disconnected IKE SA #{sa_id}')
    return jsonify({'ok':True})

@app.route('/api/users/<path:username>/profile')
@auth
def user_profile(username):
    if not any(x['username']==username for x in managed_users()):abort(404)
    host=os.environ.get('VPN_HOST','vpn.example.com')
    profile={'name':username,'server':host,'type':'IKEv2 EAP','username':username,'ca_note':'Install the VPN root CA separately','password_included':False}
    payload=json.dumps(profile,indent=2).encode()
    return send_file(__import__('io').BytesIO(payload),mimetype='application/json',as_attachment=True,download_name=f'{username}-vpn-profile.json')

@app.route('/api/containers')
@auth
def containers_status():
    return jsonify({'containers':[dict(name=n,**inspect(n)) for n in MANAGED_CONTAINERS]})

@app.route('/api/containers/<path:name>/restart',methods=['POST'])
@auth
def container_restart(name):
    csrf()
    if name not in MANAGED_CONTAINERS:return jsonify({'ok':False,'error':'Container is not allow-listed'}),403
    rc,o,e=run(['docker','restart',name],45)
    if rc:return jsonify({'ok':False,'error':e or o}),500
    add_event('admin',f'Restarted container {name}')
    return jsonify({'ok':True})

@app.route('/api/alerts/test',methods=['POST'])
@auth
def alert_test():
    csrf();notify('service',f'{APP_NAME} notification test');return jsonify({'ok':True,'enabled':bool(NTFY_URL)})

@app.route('/health')
def health():return jsonify({'status':'ok'})
