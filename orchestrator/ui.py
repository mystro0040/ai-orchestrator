"""ui.py — the mobile-responsive web UI (single inline page, zero external assets).

Security: the device SECRET is entered once and kept in the phone's localStorage; the PIN is entered per
command. The browser computes the HMAC signature CLIENT-SIDE (Web Crypto) and posts only the signed
envelope — the server never receives the PIN or the secret, so it cannot forge commands. The canonical
JSON here MUST match signing._canonical (sorted keys, no spaces)."""


def page() -> str:
    return """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Orchestrator</title>
<style>
 :root{color-scheme:dark light}
 *{box-sizing:border-box} body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
 header{padding:14px 16px;background:#161a22;font-weight:600;font-size:18px;border-bottom:1px solid #262b36}
 main{padding:16px;max-width:640px;margin:0 auto}
 .card{background:#161a22;border:1px solid #262b36;border-radius:12px;padding:14px;margin-bottom:14px}
 label{display:block;font-size:12px;color:#9aa4b2;margin:8px 0 4px}
 input,select,textarea,button{width:100%;padding:12px;border-radius:10px;border:1px solid #333b49;background:#0f1115;color:#e6e6e6;font-size:16px}
 button{background:#2d6cdf;border:none;font-weight:600;margin-top:12px;cursor:pointer}
 button.alt{background:#39424f} button.danger{background:#b03b3b}
 .row{display:flex;gap:8px} .row>*{flex:1}
 .log{font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;max-height:40vh;overflow:auto}
 .muted{color:#9aa4b2;font-size:12px} .ok{color:#4caf50} .warn{color:#e0a800} .err{color:#e35}
 .hidden{display:none}
</style></head><body>
<header>🤖 AI Orchestrator</header>
<main>
 <div class="card" id="loginCard">
   <label>Access password</label><input id="pw" type="password" autocomplete="current-password">
   <button onclick="login()">Unlock</button>
   <div id="loginMsg" class="muted"></div>
 </div>

 <div id="app" class="hidden">
   <div class="card">
     <label>Device secret (stored on THIS phone only — set once)</label>
     <input id="secret" type="password" placeholder="hex secret from the orchestrator">
     <button class="alt" onclick="saveSecret()">Save secret locally</button>
     <div class="muted">The server never sees this. Used to sign commands in your browser.</div>
   </div>

   <div class="card">
     <label>Engagement</label>
     <select id="engagement" onchange="loadLogs()"></select>
     <label>Target agent</label>
     <select id="agent"><option>tester</option><option>manager</option></select>
     <label>Command</label><textarea id="cmd" rows="3" placeholder="e.g. status / resume recon"></textarea>
     <label>4-digit PIN</label><input id="pin" type="password" inputmode="numeric" maxlength="8" placeholder="PIN">
     <button onclick="send('agent.command')">Sign &amp; send command</button>
     <div class="row">
       <button class="alt" onclick="send('set_mode',{mode:1})">Mode 1</button>
       <button class="alt" onclick="send('set_mode',{mode:2})">Mode 2</button>
       <button class="alt" onclick="send('set_mode',{mode:3})">Mode 3</button>
     </div>
     <button class="danger" onclick="if(confirm('Shut down the local machine?'))send('system.shutdown')">⏻ Remote shutdown</button>
     <div id="sendMsg" class="muted"></div>
   </div>

   <div class="card">
     <div class="row"><label>Live logs</label><button class="alt" style="max-width:90px;margin:0" onclick="loadLogs()">Refresh</button></div>
     <div id="logs" class="log muted">—</div>
   </div>
 </div>
</main>
<script>
let TOKEN=null;
const $=id=>document.getElementById(id);
function canonical(o){ // sorted keys, no spaces — must match Python json.dumps(sort_keys,separators=(',',':'))
  if(Array.isArray(o))return '['+o.map(canonical).join(',')+']';
  if(o&&typeof o==='object')return '{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canonical(o[k])).join(',')+'}';
  return JSON.stringify(o);
}
async function hmac(secretHex,msg){
  const key=await crypto.subtle.importKey('raw',hexToBytes(secretHex),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function hexToBytes(h){const a=new Uint8Array(h.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}
function saveSecret(){localStorage.setItem('ao_secret',$('secret').value.trim());$('secret').value='';alert('Secret saved on this device.');}
async function login(){
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:$('pw').value})});
  if(r.ok){TOKEN=(await r.json()).token;$('loginCard').classList.add('hidden');$('app').classList.remove('hidden');loadEngagements();loadLogs();}
  else $('loginMsg').innerHTML='<span class="err">Wrong password</span>';
}
async function loadEngagements(){
  const r=await fetch('/api/engagements',{headers:{'X-Session':TOKEN}}); if(!r.ok)return;
  const engs=(await r.json()).engagements||[];
  $('engagement').innerHTML=engs.length?engs.map(e=>`<option>${e}</option>`).join(''):'<option value="">(none registered)</option>';
}
async function send(type,extra){
  const secret=localStorage.getItem('ao_secret'); const pin=$('pin').value;
  if(!secret){$('sendMsg').innerHTML='<span class="err">Set the device secret first</span>';return;}
  if(!pin){$('sendMsg').innerHTML='<span class="err">Enter your PIN</span>';return;}
  const payload=Object.assign({type},extra||{});
  if(type!=='system.shutdown'){payload.engagement=$('engagement').value;}
  if(type==='agent.command'){payload.agent=$('agent').value;payload.command=$('cmd').value;}
  const nonce=[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
  const ts=Math.floor(Date.now()/1000);
  const sig=await hmac(secret,pin+'\\n'+nonce+'\\n'+ts+'\\n'+canonical(payload));
  const env={payload,nonce,ts,sig};
  const r=await fetch('/api/queue',{method:'POST',headers:{'Content-Type':'application/json','X-Session':TOKEN},body:JSON.stringify({envelope:env})});
  $('sendMsg').innerHTML=r.ok?'<span class="ok">Queued (signed). The orchestrator will verify &amp; run it.</span>':'<span class="err">Send failed</span>';
  $('pin').value='';
}
async function loadLogs(){
  const eng=encodeURIComponent($('engagement')?$('engagement').value:'');
  const r=await fetch('/api/logs'+(eng?('?engagement='+eng):''),{headers:{'X-Session':TOKEN}}); if(!r.ok)return;
  const logs=(await r.json()).logs||[];
  $('logs').textContent=logs.map(l=>`[${l.engagement?l.engagement.split('/').pop()+' · ':''}${l.source}] ${l.body}`).join('\\n')||'(no logs yet)';
}
setInterval(()=>{if(TOKEN)loadLogs();},8000);
</script></body></html>"""
