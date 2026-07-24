"""
ui.py — the operator console: a tabbed CHAT app for talking to the manager and the agents.

AUTH MODEL (why there is no key to paste):
  The browser derives TWO values from the account password with PBKDF2-SHA256 + a public per-account
  salt, using different info strings:
      auth token   = PBKDF2(pw, salt, "ao-auth")   -> sent to the server to log in
      signing key  = PBKDF2(pw, salt, "ao-sign")   -> NEVER sent; signs commands in this browser
  The server stores only a salted hash of the auth token, so it can verify a login but cannot derive
  the signing key — it therefore still cannot forge a command. Log in with username + password on any
  device; the signing key is re-derived locally. The 4-digit PIN stays as a per-command second factor.

LAYOUT: one TAB per conversation (manager + each engagement), full-width chat, composer at the bottom
like a messaging app. Settings (mode / shutdown) and the security monitor live behind buttons so they
do not eat the page. Stacks cleanly on mobile.

!! EDITING THIS FILE !!  PAGE is a normal triple-quoted string, so backslash escapes are consumed by
PYTHON first. To emit a JS  \\n  you must write  \\\\n  here. Getting this wrong once put a literal
newline inside a JS string and killed the entire script silently.
"""
from __future__ import annotations

from .hub import GLOBAL_CHANNEL, GLOBAL_LABEL

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>AI Orchestrator</title>
<style>
:root{
  --bg:#121212; --card:#1e1e1e; --card2:#242424; --line:#333;
  --teal:#4dd0e1; --amber:#ffab40; --text:#fff; --muted:#b0bec5;
  --danger:#ff5252; --ok:#66bb6a; --violet:#b388ff; --blue:#64b5f6; --r:10px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%;background:var(--bg);color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:16px}
.wrap{max-width:1100px;margin:0 auto;padding:10px;height:100%;display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--card);
  border:1px solid var(--line);border-radius:var(--r);margin-bottom:10px;flex:0 0 auto;flex-wrap:wrap}
header h1{margin:0;font-size:1rem;color:var(--amber);flex:1}
header .who{font-size:.78rem;color:var(--muted)}
.iconbtn{width:auto;margin:0;padding:7px 11px;background:var(--card2);color:var(--text);
  border:1px solid var(--line);border-radius:6px;cursor:pointer;font-size:.82rem}
.iconbtn.alert{border-color:var(--danger);color:var(--danger)}
.tabs{display:flex;gap:6px;overflow-x:auto;flex:0 0 auto;padding-bottom:0}
.tab{white-space:nowrap;padding:9px 14px;border-radius:8px 8px 0 0;background:var(--card2);
  border:1px solid var(--line);border-bottom:0;color:var(--muted);cursor:pointer;font-size:.85rem}
.tab.on{background:var(--card);color:var(--text);border-color:var(--teal)}
.tab .dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px}
.chatcard{flex:1 1 auto;display:flex;flex-direction:column;min-height:0;background:var(--card);
  border:1px solid var(--line);border-radius:0 var(--r) var(--r) var(--r);padding:12px}
#chat{flex:1 1 auto;overflow-y:auto;min-height:0;padding-right:4px}
.msg-row{display:flex;margin-bottom:10px}
.bub{max-width:82%;padding:9px 12px;border-radius:12px;background:var(--card2);
  border-left:3px solid var(--line);font-size:.9rem;line-height:1.45;word-break:break-word}
.txt{white-space:pre-wrap}
.msg-row.mine{justify-content:flex-end}
.msg-row.mine .bub{background:#1b3a2a;border-left:0;border-right:3px solid var(--ok)}
.meta{display:flex;gap:8px;align-items:center;font-size:.68rem;margin-bottom:4px}
.who{font-weight:700;letter-spacing:.3px}
.ts{color:var(--muted)}
.s-you .who{color:var(--ok)}
.s-manager{border-left-color:var(--teal)}   .s-manager .who{color:var(--teal)}
.s-tester{border-left-color:var(--violet)}  .s-tester .who{color:var(--violet)}
.s-orch{border-left-color:var(--blue)}      .s-orch .who{color:var(--blue)}
.s-other{border-left-color:var(--amber)}    .s-other .who{color:var(--amber)}
.crit{box-shadow:inset 0 0 0 1px var(--danger);background:rgba(255,82,82,.08)}
.flag{font-size:.6rem;font-weight:700;padding:1px 6px;border-radius:4px;background:var(--danger);
  color:#fff;text-transform:uppercase;letter-spacing:.5px}
.collapsed .txt{max-height:6em;overflow:hidden;-webkit-mask-image:linear-gradient(#000 60%,transparent)}
.tog{background:none;border:0;color:var(--muted);font-size:.68rem;cursor:pointer;padding:3px 0 0;
  width:auto;margin:0;text-decoration:underline}
.empty{color:var(--muted);text-align:center;padding:40px 10px;font-size:.9rem}
.composer{flex:0 0 auto;border-top:1px solid var(--line);padding-top:10px;margin-top:10px}
.composer textarea{width:100%;min-height:64px;max-height:180px;resize:vertical;padding:10px;
  background:#1a1a1a;color:var(--text);border:1px solid var(--line);border-radius:8px;
  font-family:inherit;font-size:.95rem}
.crow{display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap}
.crow input[type=password]{width:92px;padding:9px;background:#1a1a1a;color:var(--text);
  border:1px solid var(--line);border-radius:6px;text-align:center;letter-spacing:3px}
.crow button{width:auto;margin:0;padding:10px 18px;border:0;border-radius:6px;font-weight:600;
  cursor:pointer;background:var(--teal);color:#06272b;font-size:.9rem}
.crow button.alt{background:var(--card2);color:var(--text);border:1px solid var(--line)}
.chk{display:flex;align-items:center;gap:6px;font-size:.74rem;color:var(--muted);cursor:pointer}
.chk input{width:auto;margin:0}
.status{font-size:.8rem;margin-top:7px;min-height:1.1em}
.err{color:var(--danger)} .ok{color:var(--ok)} .muted{color:var(--muted)}
.drawer{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;
  margin-bottom:10px;flex:0 0 auto}
.drawer h2{margin:0 0 10px;font-size:.75rem;text-transform:uppercase;letter-spacing:1.1px;color:var(--teal)}
.modes{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.modes button{padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--card2);
  color:var(--text);cursor:pointer;font-size:.82rem;width:auto;margin:0}
.modes button.on{background:var(--amber);color:#2b1a00;border-color:var(--amber)}
.dangerbtn{width:100%;margin-top:12px;padding:11px;border:0;border-radius:6px;background:var(--danger);
  color:#fff;font-weight:600;cursor:pointer}
.note{font-size:.72rem;color:var(--muted);margin-top:8px;line-height:1.45}
.sec-row{font-size:.78rem;padding:6px 8px;border-left:2px solid var(--danger);background:var(--card2);
  border-radius:0 4px 4px 0;margin-bottom:6px;word-break:break-word}
.hide{display:none!important}
.authbox{max-width:400px;margin:6vh auto;background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);padding:20px}
.authbox label{display:block;font-size:.76rem;color:var(--muted);margin:12px 0 5px}
.authbox input{width:100%;padding:11px;background:#1a1a1a;color:var(--text);border:1px solid var(--line);
  border-radius:6px;font-size:1rem}
.authbox button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:6px;background:var(--teal);
  color:#06272b;font-weight:600;cursor:pointer;font-size:1rem}
@media (max-width:760px){ .wrap{padding:8px} .bub{max-width:92%} .crow input[type=password]{width:80px} }
</style></head><body>
<div class="wrap">

<div id="authView">
  <div class="authbox">
    <h1 style="margin:0 0 4px;font-size:1.1rem;color:var(--amber)">AI Orchestrator</h1>
    <div id="authTitle" class="note" style="margin:0 0 10px">Sign in</div>
    <div id="regHint" class="note hide">No account exists yet — create one. Your password never leaves
      this browser; it derives your signing key locally.</div>
    <label>Username</label><input id="u" autocomplete="username">
    <label>Password</label><input id="p" type="password" autocomplete="current-password">
    <div id="p2wrap" class="hide"><label>Confirm password</label>
      <input id="p2" type="password" autocomplete="new-password"></div>
    <button id="authBtn" onclick="doAuth()">Sign in</button>
    <div id="authMsg" class="status"></div>
  </div>
</div>

<div id="appView" class="hide" style="flex-direction:column;height:100%">
  <header>
    <h1>AI Orchestrator</h1>
    <span class="who" id="whoami"></span>
    <button class="iconbtn" id="secBtn" onclick="toggle('secDrawer');loadSecurity()">Security</button>
    <button class="iconbtn" onclick="toggle('setDrawer')">Settings</button>
    <button class="iconbtn" onclick="logout()">Sign out</button>
  </header>

  <div id="setDrawer" class="drawer hide">
    <h2>Mode <span id="modeNow" class="muted" style="text-transform:none;letter-spacing:0"></span></h2>
    <div class="modes">
      <button id="m1" onclick="setMode(1)">1 - Minimal</button>
      <button id="m2" onclick="setMode(2)">2 - Local</button>
      <button id="m3" onclick="setMode(3)">3 - Full</button>
    </div>
    <div class="note">1 - agents independent, only critical shared. 2 - full agent cross-talk, web not
      involved. 3 - everything also syncs here. Applies to the ACTIVE tab's channel.</div>
    <button class="dangerbtn" onclick="shutdown()">Remote shutdown</button>
    <div class="note">Disabled unless allow_privileged is true AND dry_run is false in the config.</div>
    <div id="setMsg" class="status"></div>
  </div>

  <div id="secDrawer" class="drawer hide">
    <h2>Unverified activity</h2>
    <div id="secSummary" class="note">checking...</div>
    <div id="secList" style="margin-top:10px;max-height:220px;overflow-y:auto"></div>
    <div class="note">A rejected command means something sent a request this orchestrator could not
      verify - a mistyped PIN, or someone probing. Repeated rejections you did not cause are a warning.</div>
  </div>

  <div class="tabs" id="tabs"></div>

  <div class="chatcard">
    <div id="chat"><div class="empty">Loading...</div></div>
    <div class="composer">
      <textarea id="cmd" placeholder="Message... (kept here until it sends successfully)"></textarea>
      <div class="crow">
        <input id="pin" type="password" inputmode="numeric" maxlength="4" placeholder="PIN">
        <button onclick="send()">Send</button>
        <button class="alt" onclick="clearBox()">Clear</button>
        <label class="chk"><input type="checkbox" id="keepPin"> keep PIN</label>
        <label class="chk"><input type="checkbox" id="autoRef" checked> auto-refresh</label>
      </div>
      <div id="sendMsg" class="status"></div>
    </div>
  </div>
</div>
</div>

<script>
var $=function(id){return document.getElementById(id)};
var GLOBAL="__GLOBAL__", GLABEL="__GLABEL__";
var TOKEN=localStorage.getItem('ao_tok')||'', KEY=localStorage.getItem('ao_key')||'',
    USER=localStorage.getItem('ao_user')||'', CHANNELS=[], ACTIVE=GLOBAL, timer=null;
var NL=String.fromCharCode(10);

var enc=new TextEncoder();
function b2h(b){return Array.prototype.map.call(new Uint8Array(b),function(x){return x.toString(16).padStart(2,'0')}).join('')}
function h2b(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a}
async function derive(pw,saltHex,info){
  var base=await crypto.subtle.importKey('raw',enc.encode(pw+'|'+info),'PBKDF2',false,['deriveBits']);
  var bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:h2b(saltHex),iterations:200000,hash:'SHA-256'},base,256);
  return b2h(bits);
}
function canonical(o){
  if(Array.isArray(o))return '['+o.map(canonical).join(',')+']';
  if(o&&typeof o==='object')return '{'+Object.keys(o).sort().map(function(k){return JSON.stringify(k)+':'+canonical(o[k])}).join(',')+'}';
  return JSON.stringify(o);
}
async function hmac(keyHex,msg){
  var k=await crypto.subtle.importKey('raw',h2b(keyHex),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return b2h(await crypto.subtle.sign('HMAC',k,enc.encode(msg)));
}
async function api(path,opt){
  opt=opt||{}; opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});
  if(TOKEN)opt.headers['X-Session']=TOKEN;
  try{ var r=await fetch(path,opt); var j={}; try{j=await r.json()}catch(e){}
       return {ok:r.ok,status:r.status,j:j}; }
  catch(e){ return {ok:false,status:0,j:{error:'server unreachable'}}; }
}
function toggle(id){ $(id).classList.toggle('hide') }
function clearBox(){ $('cmd').value=''; $('sendMsg').textContent='' }

async function boot(){
  var r=await api('/api/account');
  if(!r.ok && r.status===0){
    $('authView').classList.remove('hide');
    $('authTitle').textContent='Cannot reach the server';
    var m=$('authMsg'); m.className='status err';
    m.textContent='The web app is not responding. Start it from the menu (option 2), then reload.';
    $('authBtn').disabled=true; return;
  }
  var j=r.j||{};
  if(!j.exists){
    $('authTitle').textContent='Create your account';
    $('regHint').classList.remove('hide'); $('p2wrap').classList.remove('hide');
    $('authBtn').textContent='Create account'; $('authBtn').dataset.reg='1';
  }
  if(TOKEN&&KEY){ var s=await api('/api/session'); if(s.j&&s.j.valid){ showApp(); return; } }
  $('authView').classList.remove('hide');
}
async function doAuth(){
  var u=$('u').value.trim(), pw=$('p').value, reg=$('authBtn').dataset.reg==='1';
  var m=$('authMsg'); m.className='status'; m.textContent='working...';
  if(!u||!pw){m.className='status err';m.textContent='username and password required';return}
  try{
    if(reg){
      if(pw!==$('p2').value){m.className='status err';m.textContent='passwords do not match';return}
      if(pw.length<8){m.className='status err';m.textContent='use at least 8 characters';return}
      var salt=b2h(crypto.getRandomValues(new Uint8Array(16)));
      var auth=await derive(pw,salt,'ao-auth'), key=await derive(pw,salt,'ao-sign');
      var r=await api('/api/register',{method:'POST',body:JSON.stringify({username:u,auth_token:auth,kdf_salt:salt})});
      if(!r.j.ok){m.className='status err';m.textContent=r.j.error||'registration failed';return}
      TOKEN=r.j.token; KEY=key; USER=u; persist(); showApp(); return;
    }
    var s=await api('/api/salt?u='+encodeURIComponent(u));
    if(!s.j.kdf_salt){m.className='status err';m.textContent='unknown user';return}
    var auth2=await derive(pw,s.j.kdf_salt,'ao-auth'), key2=await derive(pw,s.j.kdf_salt,'ao-sign');
    var r2=await api('/api/login',{method:'POST',body:JSON.stringify({username:u,auth_token:auth2})});
    if(!r2.j.token){m.className='status err';m.textContent='wrong username or password';return}
    TOKEN=r2.j.token; KEY=key2; USER=u; persist(); showApp();
  }catch(e){m.className='status err';m.textContent='error: '+e.message}
}
function persist(){localStorage.setItem('ao_tok',TOKEN);localStorage.setItem('ao_key',KEY);localStorage.setItem('ao_user',USER)}
function logout(){localStorage.removeItem('ao_tok');localStorage.removeItem('ao_key');location.reload()}
function showApp(){
  $('authView').classList.add('hide');
  $('appView').classList.remove('hide'); $('appView').style.display='flex';
  $('whoami').textContent=USER; loadChannels(); startAuto(); loadSecurity();
}

function label(c){
  if(c===GLOBAL) return GLABEL;
  var p=c.split('/'); return p[p.length-1]+' - tester';
}
async function loadChannels(){
  var res=await api('/api/engagements'); var j=res.j||{};
  CHANNELS=(j.engagements||[]).slice();
  if(CHANNELS.indexOf(GLOBAL)<0)CHANNELS.unshift(GLOBAL);
  var box=$('tabs'); box.innerHTML='';
  CHANNELS.forEach(function(c){
    var b=document.createElement('div');
    b.className='tab'+(c===ACTIVE?' on':'');
    var col=(c===GLOBAL)?'var(--teal)':'var(--violet)';
    b.innerHTML='<span class="dot" style="background:'+col+'"></span>'+label(c);
    b.onclick=function(){ ACTIVE=c; renderTabs(); loadChat(); loadMode(); };
    box.appendChild(b);
  });
  loadChat(); loadMode();
}
function renderTabs(){
  var kids=$('tabs').children;
  for(var i=0;i<kids.length;i++){
    kids[i].className='tab'+(CHANNELS[i]===ACTIVE?' on':'');
  }
}
function esc(s){return (s||'').replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
function senderClass(s){
  if(s==='orchestrator')return 's-orch';
  if(s==='manager')return 's-manager';
  if(s==='tester')return 's-tester';
  return 's-other';
}
async function loadChat(){
  var res=await api('/api/chat?channel='+encodeURIComponent(ACTIVE)); var j=res.j||{};
  var box=$('chat'); var rows=j.messages||[];
  if(!rows.length){box.innerHTML='<div class="empty">No messages on this channel yet.<br>Type below to start.</div>';return}
  var near=box.scrollTop+box.clientHeight>=box.scrollHeight-60;
  box.innerHTML=rows.map(function(r){
    var s=r.sender||'?';
    var mine=(s==='orchestrator'&&r.kind==='command')||s==='operator';
    var who=mine?'You':s;
    var cls=mine?'s-you':senderClass(s);
    var crit=(r.kind==='critical')?' crit':'';
    var flag=(r.kind==='critical')?'<span class="flag">critical</span>':'';
    var when=r.ts?new Date(r.ts).toLocaleTimeString():'';
    var body=esc(r.body||'');
    var long=body.length>500||body.split(NL).length>8;
    var tog=long?'<button class="tog" onclick="this.parentNode.classList.toggle(\\'collapsed\\')">expand / collapse</button>':'';
    return '<div class="msg-row'+(mine?' mine':'')+'"><div class="bub '+cls+crit+'">'+
      '<div class="meta"><span class="who">'+esc(who)+'</span>'+flag+
      '<span class="ts">'+when+'</span></div><div class="txt">'+body+'</div>'+tog+'</div></div>';
  }).join('');
  if(near)box.scrollTop=box.scrollHeight;
}
function startAuto(){ if(timer)clearInterval(timer);
  timer=setInterval(function(){ if($('autoRef').checked){loadChat();loadSecurity();} },5000); }

async function loadSecurity(){
  var res=await api('/api/security'); var j=res.j; if(!j)return;
  var n=j.last_hour||0, tot=j.total||0;
  $('secSummary').innerHTML='<b>'+n+'</b> rejected in the last hour, '+tot+' total. '+
    (n>3?'<span class="err">Unusual - check these.</span>':'Normal if you mistyped a PIN.');
  $('secBtn').className='iconbtn'+(n>3?' alert':'');
  var list=(j.recent||[]).slice().reverse().map(function(r){
    return '<div class="sec-row">'+new Date((r.ts||0)*1000).toLocaleTimeString()+' - '+esc(r.body||'')+'</div>';
  }).join('');
  $('secList').innerHTML=list||'<div class="note">Nothing rejected. Good.</div>';
}

function clearPin(){ if(!$('keepPin').checked) $('pin').value='' }
async function signed(type,extra){
  var pin=$('pin').value;
  if(!KEY)return {err:'signing key missing - sign out and back in'};
  if(!/^[0-9]{4}$/.test(pin))return {err:'enter your 4-digit PIN'};
  var payload=Object.assign({type:type},extra||{});
  var nonce=b2h(crypto.getRandomValues(new Uint8Array(16)));
  var ts=Math.floor(Date.now()/1000);
  var sig=await hmac(KEY,pin+NL+nonce+NL+ts+NL+canonical(payload));
  var r=await api('/api/queue',{method:'POST',body:JSON.stringify({envelope:{payload:payload,nonce:nonce,ts:ts,sig:sig}})});
  if(r.ok&&r.j&&r.j.id)return {ok:1,id:r.j.id};
  return {err:(r.j&&r.j.error)||('queue failed (HTTP '+r.status+')')};
}
async function send(){
  var m=$('sendMsg'); m.className='status'; m.textContent='signing...';
  var body=$('cmd').value.trim();
  if(!body){m.className='status err';m.textContent='type a message';return}
  var agent=(ACTIVE===GLOBAL)?'manager':'tester';
  var r=await signed('agent.command',{engagement:ACTIVE,agent:agent,command:body});
  if(r.err){m.className='status err';m.textContent='REJECTED: '+r.err;clearPin();return}
  m.className='status muted'; m.textContent='queued - waiting for verification...'; clearPin();
  var t0=Date.now();
  var poll=async function(){
    var s=await api('/api/queue/status?id='+encodeURIComponent(r.id));
    var o=s.j&&s.j.outcome;
    if(o){
      if(o.ok){ m.className='status ok'; m.textContent='VERIFIED and delivered'; $('cmd').value=''; }
      else { m.className='status err';
             m.textContent='REJECTED: '+(o.reason||'verification failed')+' - message kept, fix the PIN and resend'; }
      loadChat(); loadSecurity(); return;
    }
    if(Date.now()-t0>20000){ m.className='status err';
      m.textContent='no verdict after 20s - is the orchestrator running? (menu option 3)'; return; }
    setTimeout(poll,1000);
  };
  setTimeout(poll,900);
}
function markMode(n){
  ['m1','m2','m3'].forEach(function(id,i){ $(id).className=(i+1===n)?'on':'' });
  var names={1:'1 - Minimal',2:'2 - Local',3:'3 - Full'};
  $('modeNow').textContent = n?('- active: '+names[n]):'';
}
async function loadMode(){
  var res=await api('/api/mode?engagement='+encodeURIComponent(ACTIVE));
  if(res.j&&res.j.mode)markMode(res.j.mode);
}
async function setMode(n){
  var m=$('setMsg'); m.className='status'; m.textContent='...';
  var r=await signed('set_mode',{engagement:ACTIVE,mode:n});
  if(r.err){m.className='status err';m.textContent='REJECTED: '+r.err;return}
  m.className='status ok';m.textContent='mode '+n+' requested for '+label(ACTIVE);
  markMode(n); clearPin();
}
async function shutdown(){
  if(!confirm('Request remote shutdown of the orchestrator host?'))return;
  var m=$('setMsg'); m.className='status'; m.textContent='...';
  var r=await signed('system.shutdown',{});
  m.className='status '+(r.err?'err':'ok');
  m.textContent=r.err?('REJECTED: '+r.err):'shutdown requested (guards may block it)';
  clearPin();
}
boot();
</script></body></html>
"""


def page() -> str:
    return PAGE.replace("__GLOBAL__", GLOBAL_CHANNEL).replace("__GLABEL__", GLOBAL_LABEL)


HTML = page()   # back-compat for anything importing a module-level string
