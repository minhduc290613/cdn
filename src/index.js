const VERSION = "2.1.0";
const DEFAULT_TTL = 86400;
const MAX_TTL = 604800;
const ALLOWED_EXTENSIONS = new Set(["js","mjs","cjs","css","json","map","svg","png","jpg","jpeg","gif","webp","ico","woff","woff2","ttf","otf","wasm","txt","xml","html","md","webmanifest"]);
const BASE_CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
};
const json = (data, status=200, extra={}) => new Response(JSON.stringify(data, null, 2), {
  status, headers: {...BASE_CORS, "Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store", ...extra}
});
const html = (body, status=200, extra={}) => new Response(body, {
  status, headers: {...BASE_CORS, "Content-Type":"text/html; charset=utf-8", "Cache-Control":"no-store", ...extra}
});
const enc = new TextEncoder();
const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64url = s => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign","verify"]);
  return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}
async function passwordHash(password, saltBytes=null) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", salt, iterations:100000, hash:"SHA-256"}, key, 256);
  return {salt:b64url(salt), hash:b64url(bits)};
}
async function verifyPassword(password, salt, expected) {
  try { const result=await passwordHash(password,unb64url(salt)); return result.hash===expected; } catch { return false; }
}
async function getAdmin(env) {
  if (!env.db) throw new Error("Missing D1 binding 'db'. Configure it in Cloudflare Dashboard > Worker > Settings > Bindings.");
  return await env.db.prepare("SELECT username, password_hash, password_salt FROM admins WHERE id = 1").first();
}
function dbSetupError() {
  return html("<!doctype html><html lang=\"vi\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ProCDN - Cấu hình database</title><body style=\"font:16px system-ui;max-width:720px;margin:10vh auto;padding:24px;background:#080d18;color:#edf5ff\"><h1>Chưa khởi tạo database ProCDN</h1><p>Hãy chọn D1 database làm binding <code>db</code> trong Cloudflare Dashboard và chạy file <code>migrations/0001_init.sql</code> trên database đó.</p><p>Nếu bảng <code>admins</code> chưa tồn tại, hãy áp dụng migration rồi tải lại trang.</p></body></html>", 503);
}
async function sessionToken(env) {
  const payload = b64url(enc.encode(JSON.stringify({sub:"admin", exp:Date.now()+8*60*60*1000})));
  return payload+"."+await hmac(payload, env.SESSION_SECRET);
}
async function isAdmin(request, env) {
  const token = (request.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("procdn_session="))?.slice("procdn_session=".length);
  if (!token || !env.SESSION_SECRET) return false;
  const [payload, sig] = token.split(".");
  if (!payload || !sig || sig !== await hmac(payload, env.SESSION_SECRET)) return false;
  try { const data=JSON.parse(new TextDecoder().decode(unb64url(payload))); return data.sub==="admin" && data.exp>Date.now(); } catch { return false; }
}
async function requireAdmin(request, env) {
  if (!(await isAdmin(request, env))) return json({error:"Unauthorized"},401);
  return null;
}
async function kvGet(env,key,fallback=null) {
  if (!env.kv) return fallback;
  const v=await env.kv.get(key);
  if (v===null) return fallback;
  try{return JSON.parse(v)}catch{return fallback}
}
async function kvPut(env,key,value) {
  if (!env.kv) throw new Error("KV binding kv is not configured");
  await env.kv.put(key,JSON.stringify(value));
}
function safeName(s) { return typeof s==="string" && /^[a-zA-Z0-9_-]{1,48}$/.test(s); }
function safePart(s) { return !!s && s!=="." && s!==".." && /^[A-Za-z0-9._-]+$/.test(s); }
function extOf(path) { return (path.split(".").pop()||"").toLowerCase(); }
function mime(path) {
 const e=extOf(path), m={js:"text/javascript; charset=utf-8",mjs:"text/javascript; charset=utf-8",css:"text/css; charset=utf-8",json:"application/json; charset=utf-8",map:"application/json; charset=utf-8",svg:"image/svg+xml",png:"image/png",jpg:"image/jpeg",jpeg:"image/jpeg",gif:"image/gif",webp:"image/webp",ico:"image/x-icon",woff:"font/woff",woff2:"font/woff2",ttf:"font/ttf",otf:"font/otf",wasm:"application/wasm",txt:"text/plain; charset=utf-8",xml:"application/xml; charset=utf-8",html:"text/html; charset=utf-8",md:"text/markdown; charset=utf-8",webmanifest:"application/manifest+json"};
 return m[e]||"application/octet-stream";
}
async function increment(env,key) {
 if(!env.kv) return;
 try { const old=await env.kv.get(key); await env.kv.put(key,String((Number(old)||0)+1),{expirationTtl:60*60*24*45}); } catch {}
}
async function logEvent(env,event) {
 if(!env.kv) return;
 const key="log:"+Date.now()+":"+crypto.randomUUID();
 try { await env.kv.put(key,JSON.stringify(event),{expirationTtl:60*60*24*14}); } catch {}
}
async function cacheFetch(request, target, ttl, redirectMode="follow") {
 const cache= caches.default;
 const key=new Request(new URL(target).toString(),{method:"GET"});
 let cached=await cache.match(key);
 if(cached) {
   const h=new Headers(cached.headers); h.set("X-ProCDN-Cache","HIT"); h.set("Access-Control-Allow-Origin","*");
   return new Response(request.method==="HEAD"?null:cached.body,{status:cached.status,headers:h});
 }
 const upstream=await fetch(target,{redirect:redirectMode});
 if(!upstream.ok) return upstream;
 const h=new Headers(upstream.headers);
 h.set("Cache-Control",`public, max-age=${Math.min(ttl,MAX_TTL)}, s-maxage=${Math.min(ttl,MAX_TTL)}`);
 h.set("X-ProCDN-Cache","MISS");
 h.set("Access-Control-Allow-Origin","*");
 h.set("X-Content-Type-Options","nosniff");
 const response=new Response(upstream.body,{status:upstream.status,headers:h});
 const store=new Response(response.clone().body,{status:response.status,headers:new Headers(response.headers)});
 store.headers.delete("X-ProCDN-Cache");
 store.headers.delete("Set-Cookie");
 store.headers.set("Cache-Control",`public, max-age=${Math.min(ttl,MAX_TTL)}`);
 await cache.put(key,store);
 return new Response(request.method==="HEAD"?null:response.body,{status:response.status,headers:response.headers});
}
function loginPage(error="") {
 return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Đăng nhập · ProCDN</title><style>
 *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(ellipse at top,#12314a,#080d18 60%);font:16px system-ui;color:#edf5ff}.box{width:min(420px,92vw);padding:30px;border:1px solid #263750;border-radius:20px;background:#101a2b;box-shadow:0 20px 80px #0006}.logo{font-size:26px;font-weight:850}.logo span{color:#63e6ff}p{color:#9cb0c9}label{display:block;margin:16px 0 7px;font-weight:650}input{width:100%;padding:13px;border-radius:9px;border:1px solid #344963;background:#080f1c;color:white;font:inherit}button{margin-top:20px;width:100%;padding:13px;border:0;border-radius:9px;background:#63e6ff;color:#04111b;font:inherit;font-weight:800;cursor:pointer}.error{color:#ff9d9d}</style></head><body><form class="box" method="post" action="/api/login"><div class="logo">Pro<span>CDN</span></div><p>Đăng nhập khu vực quản trị CDN</p>${error?`<p class="error">${error}</p>`:""}<label for="username">Username</label><input id="username" name="username" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button>Đăng nhập</button></form></body></html>`;
}
function setupPage(error="") {
 return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Thiết lập · ProCDN</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(ellipse at top,#12314a,#080d18 60%);font:16px system-ui;color:#edf5ff}.box{width:min(460px,92vw);padding:30px;border:1px solid #263750;border-radius:20px;background:#101a2b}label{display:block;margin:16px 0 7px}input{width:100%;padding:13px;border-radius:9px;border:1px solid #344963;background:#080f1c;color:white;font:inherit}button{margin-top:20px;width:100%;padding:13px;border:0;border-radius:9px;background:#63e6ff;color:#04111b;font:inherit;font-weight:800}.error{color:#ff9d9d}p{color:#9cb0c9}</style></head><body><form class="box" method="post" action="/api/setup"><h1>Thiết lập ProCDN</h1><p>Tạo tài khoản quản trị đầu tiên. Chỉ thực hiện được một lần.</p>${error?`<p class="error">${error}</p>`:""}<label>Username</label><input name="username" minlength="3" maxlength="48" autocomplete="username" required><label>Password (ít nhất 12 ký tự)</label><input name="password" type="password" minlength="12" autocomplete="new-password" required><label>Nhập lại password</label><input name="confirm" type="password" minlength="12" autocomplete="new-password" required><button>Tạo tài khoản quản trị</button></form></body></html>`;
}
function dashboardPage() {
 return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ProCDN Admin</title><style>
 :root{color-scheme:dark;--bg:#080d18;--panel:#101a2b;--line:#263750;--text:#edf5ff;--muted:#9cb0c9;--cyan:#63e6ff;--green:#8ef0c0}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#12304a,transparent 35%),var(--bg);color:var(--text);font:15px/1.55 system-ui}.wrap{max-width:1120px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.logo{font-size:24px;font-weight:850}.logo span{color:var(--cyan)}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}.stat b{display:block;font-size:27px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}.tab,button{border:1px solid var(--line);background:#19283c;color:var(--text);border-radius:9px;padding:10px 13px;font:inherit;cursor:pointer}.tab.active,.primary{background:var(--cyan);color:#04111b;border-color:var(--cyan);font-weight:750}.view{display:none}.view.active{display:block}input,select{width:100%;padding:11px;border:1px solid #344963;border-radius:8px;background:#080f1c;color:var(--text);font:inherit}label{display:block;margin:12px 0 6px;font-weight:650}.formgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.formgrid .full{grid-column:1/-1}.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;margin-top:12px}th,td{text-align:left;padding:11px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);font-size:12px;text-transform:uppercase}.notice{padding:10px 12px;border:1px solid var(--line);border-radius:9px;margin:10px 0;color:var(--muted)}code{overflow-wrap:anywhere;color:#bdefff}.danger{border-color:#743b4b;color:#ffb9c5}.hidden{display:none!important}@media(max-width:760px){.grid{grid-template-columns:repeat(2,1fr)}.formgrid{grid-template-columns:1fr}.formgrid .full{grid-column:auto}}@media(max-width:420px){.grid{grid-template-columns:1fr}}
 </style></head><body><div class="wrap"><header class="top"><div><div class="logo">Pro<span>CDN</span> <small class="muted">/ Admin</small></div><div class="muted">Quản trị nguồn, cache, API key và thống kê</div></div><button id="logout">Đăng xuất</button></header>
 <div class="grid"><div class="stat"><span class="muted">Request tổng</span><b id="requests">—</b></div><div class="stat"><span class="muted">Cache HIT</span><b id="hits">—</b></div><div class="stat"><span class="muted">Cache MISS</span><b id="misses">—</b></div><div class="stat"><span class="muted">Nguồn đã cấu hình</span><b id="sourceCount">—</b></div></div>
 <div class="tabs"><button class="tab active" data-tab="overview">Tổng quan</button><button class="tab" data-tab="sources">Nguồn CDN</button><button class="tab" data-tab="keys">API keys</button><button class="tab" data-tab="settings">Cài đặt cache</button><button class="tab" data-tab="logs">Nhật ký lỗi</button></div>
 <section class="view active" id="overview"><div class="panel"><h2>URL CDN</h2><p class="muted">GitHub: <code>/gh/OWNER/REPO@VERSION/path/file.js</code></p><p class="muted">Nguồn quản trị: <code>/s/SLUG/path/file.js</code> (chỉ proxy host trong allowlist nguồn đã cấu hình).</p><div class="notice">Thống kê là bộ đếm xấp xỉ lưu trong KV; không thay thế hệ thống analytics chuyên dụng. Cần cấu hình binding KV tên kv trong Cloudflare Dashboard.</div></div></section>
 <section class="view" id="sources"><div class="panel"><h2>Thêm nguồn</h2><p class="muted">Thêm GitHub repository hoặc một host nguồn HTTPS công khai. Không nhập URL có thông tin đăng nhập.</p><form id="sourceForm"><div class="formgrid"><div><label>Slug (duy nhất)</label><input name="slug" placeholder="my-library" pattern="[A-Za-z0-9_-]{1,48}" required></div><div><label>Loại nguồn</label><select name="type"><option value="github">GitHub raw</option><option value="url">URL base công khai</option></select></div><div><label>GitHub owner (nếu chọn GitHub)</label><input name="owner" placeholder="owner"></div><div><label>Repository / ref (nếu chọn GitHub)</label><input name="repo" placeholder="repo@v1.0.0"></div><div class="full"><label>URL base (nếu chọn URL)</label><input name="baseUrl" placeholder="https://static.example.com/assets/"></div><div><label>Host allowlist cho URL source</label><input name="allowedHost" placeholder="static.example.com"></div><div><label>TTL (giây)</label><input name="ttl" type="number" min="0" max="604800" value="86400" required></div></div><div class="row"><button class="primary">Lưu nguồn</button></div></form><div id="sourceMessage" class="notice"></div><div class="tablewrap"><table><thead><tr><th>Slug</th><th>Loại</th><th>Đích</th><th>TTL</th><th>Hành động</th></tr></thead><tbody id="sourcesTable"></tbody></table></div></div></section>
 <section class="view" id="keys"><div class="panel"><h2>API keys</h2><p class="muted">Tạo key để client hoặc automation xác thực với API quản trị. Key đầy đủ chỉ hiện một lần.</p><form id="keyForm"><div class="formgrid"><div><label>Tên key</label><input name="label" required maxlength="60" placeholder="CI deployment"></div><div><label>Quyền</label><select name="scope"><option value="read">Read-only</option><option value="manage">Manage sources/cache</option></select></div></div><div class="row"><button class="primary">Tạo API key</button></div></form><div id="newKey" class="notice hidden"></div><div class="tablewrap"><table><thead><tr><th>Tên</th><th>Prefix</th><th>Quyền</th><th>Tạo lúc</th><th></th></tr></thead><tbody id="keysTable"></tbody></table></div></div></section>
 <section class="view" id="settings"><div class="panel"><h2>Cache mặc định</h2><form id="settingsForm"><label>TTL mặc định (giây, tối đa 604800)</label><input name="ttl" type="number" min="0" max="604800" value="86400" required><div class="row"><button class="primary">Lưu TTL</button><button type="button" id="purge" class="danger">Làm mới cache (purge theo key không thể tự động toàn cục)</button></div></form><div id="settingsMessage" class="notice"></div><p class="muted">TTL 0 tắt cache phía Worker cho request mới. Cache đã lưu trước đó có thể còn hiệu lực đến khi hết hạn; để xóa chính xác theo URL, dùng nút purge của từng nguồn/tài nguyên.</p></div></section>
 <section class="view" id="logs"><div class="panel"><h2>Nhật ký gần đây</h2><button id="refreshLogs">Làm mới nhật ký</button><div class="tablewrap"><table><thead><tr><th>Thời gian</th><th>Loại</th><th>Đường dẫn</th><th>Chi tiết</th></tr></thead><tbody id="logsTable"></tbody></table></div></div></section>
 </div>
 <script>
 const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
 async function api(path,opts={}){const r=await fetch('/api'+path,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||'Request failed');return d}
 function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
 $$('.tab').forEach(b=>b.onclick=()=>{$$('.tab').forEach(x=>x.classList.toggle('active',x===b));$$('.view').forEach(v=>v.classList.toggle('active',v.id===b.dataset.tab));});
 async function refresh(){try{const d=await api('/stats');$('#requests').textContent=d.requests;$('#hits').textContent=d.hits;$('#misses').textContent=d.misses;$('#sourceCount').textContent=d.sources;$('#settingsForm [name=ttl]').value=d.defaultTtl;}catch(e){alert(e.message)}await sources();await keys();}
 async function sources(){const d=await api('/sources');$('#sourcesTable').innerHTML=d.sources.map(s=>'<tr><td><code>'+esc(s.slug)+'</code></td><td>'+esc(s.type)+'</td><td>'+esc(s.type==='github'?s.owner+'/'+s.repo:s.baseUrl||s.allowedHost)+'</td><td>'+s.ttl+'s</td><td><button data-purge="'+esc(s.slug)+'">Purge</button> <button class="danger" data-delete="'+esc(s.slug)+'">Xóa</button></td></tr>').join('')||'<tr><td colspan="5">Chưa có nguồn.</td></tr>';$$('[data-delete]').forEach(b=>b.onclick=async()=>{if(confirm('Xóa nguồn '+b.dataset.delete+'?')){await api('/sources/'+b.dataset.delete,{method:'DELETE'});await refresh()}});$$('[data-purge]').forEach(b=>b.onclick=async()=>{await api('/purge',{method:'POST',body:JSON.stringify({slug:b.dataset.purge})});alert('Đã ghi nhận purge. Cache API không hỗ trợ xóa mọi key theo prefix; xem ghi chú triển khai.');});}
 async function keys(){const d=await api('/keys');$('#keysTable').innerHTML=d.keys.map(k=>'<tr><td>'+esc(k.label)+'</td><td><code>'+esc(k.prefix)+'</code></td><td>'+esc(k.scope)+'</td><td>'+new Date(k.createdAt).toLocaleString()+'</td><td><button class="danger" data-revoke="'+esc(k.id)+'">Thu hồi</button></td></tr>').join('')||'<tr><td colspan="5">Chưa có API key.</td></tr>';$$('[data-revoke]').forEach(b=>b.onclick=async()=>{if(confirm('Thu hồi API key này?')){await api('/keys/'+b.dataset.revoke,{method:'DELETE'});await keys()}});}
 $('#sourceForm').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));o.ttl=Number(o.ttl);try{await api('/sources',{method:'POST',body:JSON.stringify(o)});$('#sourceMessage').textContent='Đã lưu nguồn.';e.target.reset();await refresh()}catch(x){$('#sourceMessage').textContent=x.message}};
 $('#keyForm').onsubmit=async e=>{e.preventDefault();try{const d=await api('/keys',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});$('#newKey').classList.remove('hidden');$('#newKey').innerHTML='Hãy sao chép key ngay, sẽ không hiển thị lại: <code>'+esc(d.key)+'</code> <button id="copyKey">Sao chép</button>';$('#copyKey').onclick=()=>navigator.clipboard.writeText(d.key);e.target.reset();await keys()}catch(x){alert(x.message)}};
 $('#settingsForm').onsubmit=async e=>{e.preventDefault();try{await api('/settings',{method:'PUT',body:JSON.stringify({defaultTtl:Number(new FormData(e.target).get('ttl'))})});$('#settingsMessage').textContent='Đã lưu TTL mặc định.'}catch(x){$('#settingsMessage').textContent=x.message}};
 $('#purge').onclick=async()=>{await api('/purge',{method:'POST',body:'{}'});$('#settingsMessage').textContent='Đã ghi nhận yêu cầu. Dùng Purge Cache trong Cloudflare Dashboard để xóa toàn bộ cache zone nếu cần.'};
 async function logs(){const d=await api('/logs');$('#logsTable').innerHTML=d.logs.map(l=>'<tr><td>'+new Date(l.time).toLocaleString()+'</td><td>'+esc(l.type)+'</td><td><code>'+esc(l.path)+'</code></td><td>'+esc(l.detail||'')+'</td></tr>').join('')||'<tr><td colspan="4">Chưa có nhật ký.</td></tr>'}
 $('#refreshLogs').onclick=()=>logs();$('#logout').onclick=async()=>{await fetch('/api/logout',{method:'POST'});location.href='/login'};
 refresh();logs().catch(()=>{});
 </script></body></html>`;
}
function parseGitHubPath(pathname) {
 const route=pathname.slice(4), s1=route.indexOf("/"), s2=s1<0?-1:route.indexOf("/",s1+1);
 if(s1<=0||s2<=s1+1||s2===route.length-1) return null;
 const owner=route.slice(0,s1), repoRef=route.slice(s1+1,s2), filePath=route.slice(s2+1), at=repoRef.lastIndexOf("@");
 if(at<=0||at===repoRef.length-1) return null;
 const repo=repoRef.slice(0,at), ref=repoRef.slice(at+1);
 if(!safePart(owner)||!safePart(repo)||!ref.split("/").every(safePart)||!filePath.split("/").every(safePart)) return null;
 return {owner,repo,ref,filePath,target:`https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${filePath}`};
}
function ttlFromRequest(url, fallback) {
 const raw=url.searchParams.get("ttl");
 if(raw===null) return fallback;
 const n=Number(raw);
 return Number.isInteger(n)&&n>=0&&n<=MAX_TTL?n:fallback;
}
async function handleAsset(request, env, ctx, url) {
 const settings=await kvGet(env,"settings",{defaultTtl:DEFAULT_TTL});
 let target, ttl=ttlFromRequest(url,settings.defaultTtl??DEFAULT_TTL), originLabel, pathForMime=url.pathname, redirectMode="follow";
 if(url.pathname.startsWith("/gh/")) {
   const parsed=parseGitHubPath(url.pathname);
   if(!parsed) return json({error:"Invalid GitHub CDN path",usage:"/gh/OWNER/REPO@VERSION/path/file.js"},400);
   if(!ALLOWED_EXTENSIONS.has(extOf(parsed.filePath))) return json({error:"File extension not allowed"},415);
   target=parsed.target; originLabel="github";
 } else if(url.pathname.startsWith("/proxy/")) {
   // Automatic origin-host parsing is intentionally constrained by configured source allowlists.
   const bits=url.pathname.slice("/proxy/".length).split("/");
   const host=(bits.shift()||"").toLowerCase();
   const filePath=bits.join("/");
   if(!host || !filePath || !filePath.split("/").every(safePart)) return json({error:"Invalid proxy path",usage:"/proxy/example.org/assets/app.js"},400);
   if(!ALLOWED_EXTENSIONS.has(extOf(filePath))) return json({error:"File extension not allowed"},415);
   if(host.includes(":") || host.includes("@") || host.endsWith(".") || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$/.test(host)) return json({error:"Invalid origin hostname"},400);
   const configuredSources=await listSources(env);
   const allowed=configuredSources.some(source=>source.type==="url" && String(source.allowedHost||"").toLowerCase()===host && source.enabled!==false);
   if(!allowed) return json({error:"Origin domain is not allowlisted. Add a URL source with this exact allowed host in Admin > Sources first."},403);
   target=`https://${host}/${filePath.split("/").map(encodeURIComponent).join("/")}`;
   originLabel=host;
   // Do not follow redirects from auto-proxy origins; this prevents allowlist bypasses.
   redirectMode="manual";
 } else if(url.pathname.startsWith("/s/")) {
   const bits=url.pathname.slice(3).split("/");
   const slug=bits.shift(), filePath=bits.join("/");
   if(!safeName(slug)||!filePath||!filePath.split("/").every(safePart)) return json({error:"Invalid source path"},400);
   const source=await kvGet(env,"source:"+slug);
   if(!source) return json({error:"Unknown source"},404);
   ttl=ttlFromRequest(url,source.ttl??ttl);
   if(!ALLOWED_EXTENSIONS.has(extOf(filePath))) return json({error:"File extension not allowed"},415);
   if(source.type==="github") {
     const split=String(source.repo||"").lastIndexOf("@");
     if(split<=0) return json({error:"Invalid GitHub source; expected repo@ref"},500);
     const repoName=source.repo.slice(0,split), ref=source.repo.slice(split+1);
     if(!safePart(repoName)||!ref.split("/").every(safePart)) return json({error:"Invalid GitHub source configuration"},500);
     target=`https://raw.githubusercontent.com/${source.owner}/${repoName}/${ref}/${filePath}`;
   }
   else if(source.type==="url") {
     const base=new URL(source.baseUrl);
     const targetUrl=new URL(filePath,base.href.endsWith("/")?base.href:base.href+"/");
     if(targetUrl.protocol!=="https:"||targetUrl.hostname!==source.allowedHost||targetUrl.username||targetUrl.password) return json({error:"Target host is not allowed"},403);
     target=targetUrl.toString();
   } else return json({error:"Invalid source configuration"},500);
   originLabel=slug;
 } else return json({error:"Not found"},404);

 const requestKey=url.pathname+url.search;
 await increment(env,"metric:requests");
 try {
   const response=ttl===0?await fetch(target,{redirect:redirectMode}):await cacheFetch(request,target,ttl,redirectMode);
   const h=new Headers(response.headers);
   for(const [k,v] of Object.entries(BASE_CORS)) h.set(k,v);
   h.set("Content-Type",mime(pathForMime));
   h.set("X-ProCDN-Origin",originLabel);
   h.set("X-ProCDN-CDN-Host",url.hostname);
   h.set("X-ProCDN-Version",VERSION);
   const cacheStatus=response.headers.get("X-ProCDN-Cache")||"BYPASS";
   h.set("X-ProCDN-Cache",cacheStatus);
   if(cacheStatus==="HIT") await increment(env,"metric:hits"); else if(cacheStatus==="MISS") await increment(env,"metric:misses");
   ctx.waitUntil(logEvent(env,{time:Date.now(),type:response.ok?"asset":"error",path:url.pathname,detail:`${response.status} ${cacheStatus}`}));
   return new Response(request.method==="HEAD"?null:response.body,{status:response.status,headers:h});
 } catch(e) {
   ctx.waitUntil(logEvent(env,{time:Date.now(),type:"error",path:url.pathname,detail:String(e)}));
   return json({error:"Origin fetch failed"},502);
 }
}
async function apiHandler(request, env, ctx, url) {
 const p=url.pathname, method=request.method;
 if(p==="/api/setup" && method==="POST") {
   if(!env.db || !env.SESSION_SECRET) return dbSetupError();
   let admin; try { admin=await getAdmin(env); } catch { return dbSetupError(); }
   if(admin) return new Response(null,{status:302,headers:{...BASE_CORS,"Location":"/login","Cache-Control":"no-store"}});
   const form=await request.formData(), user=String(form.get("username")||"").trim(), pass=String(form.get("password")||""), confirm=String(form.get("confirm")||"");
   if(!/^[A-Za-z0-9_.-]{3,48}$/.test(user)||pass.length<12||pass!==confirm) return html(setupPage("Username không hợp lệ hoặc mật khẩu chưa khớp/đủ 12 ký tự."),400);
   const hashed=await passwordHash(pass);
   try {
     await env.db.prepare("INSERT INTO admins (id, username, password_hash, password_salt, created_at) VALUES (1, ?, ?, ?, ?)").bind(user,hashed.hash,hashed.salt,Date.now()).run();
   } catch { return html(setupPage("Không thể tạo tài khoản. Có thể một tài khoản đã được khởi tạo; hãy tải lại trang."),409); }
   const token=await sessionToken(env);
   return new Response(null,{status:302,headers:{...BASE_CORS,"Location":"/admin","Set-Cookie":`procdn_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,"Cache-Control":"no-store"}});
 }
 if(p==="/api/login" && method==="POST") {
   if(!env.db || !env.SESSION_SECRET) return dbSetupError();
   const form=await request.formData(), user=String(form.get("username")||""), pass=String(form.get("password")||"");
   let admin; try { admin=await getAdmin(env); } catch { return dbSetupError(); }
   if(!admin) return new Response(null,{status:302,headers:{...BASE_CORS,"Location":"/setup","Cache-Control":"no-store"}});
   if(user!==admin.username || !(await verifyPassword(pass,admin.password_salt,admin.password_hash))) return html(loginPage("Username hoặc password không đúng."),401);
   const token=await sessionToken(env);
   return new Response(null,{status:302,headers:{...BASE_CORS,"Location":"/admin","Set-Cookie":`procdn_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,"Cache-Control":"no-store"}});
 }
 if(p==="/api/logout"&&method==="POST") return new Response(null,{status:204,headers:{...BASE_CORS,"Set-Cookie":"procdn_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"}});
 const authKey=request.headers.get("X-API-Key")||request.headers.get("Authorization")?.replace(/^Bearer\s+/i,"");
 let apiKeyRecord=null;
 if(authKey && env.kv) {
   const digest=await crypto.subtle.digest("SHA-256",enc.encode(authKey));
   apiKeyRecord=await kvGet(env,"apikey:"+b64url(digest));
 }
 const admin=await isAdmin(request,env);
 if(!admin&&!apiKeyRecord) return json({error:"Unauthorized"},401);
 const manage=admin||apiKeyRecord?.scope==="manage";
 if(p==="/api/stats"&&method==="GET") {
   const [requests,hits,misses,settings,sources]=await Promise.all([kvGet(env,"metric:requests",0),kvGet(env,"metric:hits",0),kvGet(env,"metric:misses",0),kvGet(env,"settings",{defaultTtl:DEFAULT_TTL}),listSources(env)]);
   return json({requests:Number(requests)||0,hits:Number(hits)||0,misses:Number(misses)||0,sources:sources.length,defaultTtl:settings.defaultTtl??DEFAULT_TTL});
 }
 if(p==="/api/sources"&&method==="GET") return json({sources:await listSources(env)});
 if(p==="/api/sources"&&method==="POST") {
   if(!manage)return json({error:"Read-only API key"},403);
   const b=await request.json().catch(()=>null); if(!b||!safeName(b.slug))return json({error:"Invalid slug"},400);
   const ttl=Number(b.ttl);if(!Number.isInteger(ttl)||ttl<0||ttl>MAX_TTL)return json({error:"TTL must be 0..604800"},400);
   let source={slug:b.slug,type:b.type,ttl};
   if(b.type==="github") {
     if(!safePart(b.owner)||!/^([A-Za-z0-9_.-]+)@([A-Za-z0-9._/-]+)$/.test(b.repo||"")) return json({error:"GitHub source requires owner and repo@ref"},400);
     source.owner=b.owner;source.repo=b.repo;
   } else if(b.type==="url") {
     let base;try{base=new URL(b.baseUrl)}catch{return json({error:"Invalid base URL"},400)}
     const host=String(b.allowedHost||"").toLowerCase();
     if(base.protocol!=="https:"||base.username||base.password||base.hostname.toLowerCase()!==host||!host||host==="localhost")return json({error:"Base URL must be HTTPS and host must exactly match allowlist"},400);
     source.baseUrl=base.href;source.allowedHost=host;
   } else return json({error:"Source type must be github or url"},400);
   await kvPut(env,"source:"+b.slug,source);return json({ok:true,source});
 }
 if(p.startsWith("/api/sources/")&&method==="DELETE") {
   if(!manage)return json({error:"Read-only API key"},403);
   const slug=p.slice("/api/sources/".length);if(!safeName(slug))return json({error:"Invalid slug"},400);
   await env.kv.delete("source:"+slug);return json({ok:true});
 }
 if(p==="/api/settings"&&method==="PUT") {
   if(!manage)return json({error:"Read-only API key"},403);
   const b=await request.json().catch(()=>({})), ttl=Number(b.defaultTtl);
   if(!Number.isInteger(ttl)||ttl<0||ttl>MAX_TTL)return json({error:"TTL must be 0..604800"},400);
   await kvPut(env,"settings",{defaultTtl:ttl});return json({ok:true,defaultTtl:ttl});
 }
 if(p==="/api/purge"&&method==="POST") {
   if(!manage)return json({error:"Read-only API key"},403);
   const b=await request.json().catch(()=>({}));
   await logEvent(env,{time:Date.now(),type:"purge-request",path:b.slug?"/s/"+b.slug:"*",detail:"Purge requested; use Cloudflare dashboard for full-zone purge."});
   return json({ok:true,note:"Cache API does not support wildcard purge by prefix. Use Cloudflare Dashboard purge by URL or purge everything."});
 }
 if(p==="/api/keys"&&method==="GET") {
   const keys=await listKeys(env);return json({keys:keys.map(({id,label,scope,prefix,createdAt})=>({id,label,scope,prefix,createdAt}))});
 }
 if(p==="/api/keys"&&method==="POST") {
   if(!manage)return json({error:"Read-only API key"},403);
   const b=await request.json().catch(()=>({}));const label=String(b.label||"").trim().slice(0,60),scope=b.scope==="manage"?"manage":"read";
   if(!label)return json({error:"Label required"},400);
   const key="pcdn_"+crypto.randomUUID().replace(/-/g,"")+crypto.randomUUID().replace(/-/g,"");
   const digest=b64url(await crypto.subtle.digest("SHA-256",enc.encode(key))), id=crypto.randomUUID();
   const record={id,label,scope,prefix:key.slice(0,12),createdAt:Date.now(),hash:digest};
   await kvPut(env,"apikey:"+digest,record);
   await kvPut(env,"apikeymeta:"+id,{id,label,scope,prefix:record.prefix,createdAt:record.createdAt,digest});
   return json({ok:true,key,metadata:{id,label,scope,prefix:record.prefix,createdAt:record.createdAt}});
 }
 if(p.startsWith("/api/keys/")&&method==="DELETE") {
   if(!manage)return json({error:"Read-only API key"},403);
   const id=p.slice("/api/keys/".length);const meta=await kvGet(env,"apikeymeta:"+id);
   if(meta){await env.kv.delete("apikey:"+meta.digest);await env.kv.delete("apikeymeta:"+id)}
   return json({ok:true});
 }
 if(p==="/api/logs"&&method==="GET") return json({logs:await listLogs(env)});
 return json({error:"API route not found"},404);
}
async function listSources(env) {
 if(!env.kv)return [];
 const out=[],list=await env.kv.list({prefix:"source:",limit:100});
 for(const k of list.keys){const v=await kvGet(env,k.name);if(v)out.push(v)}
 return out.sort((a,b)=>a.slug.localeCompare(b.slug));
}
async function listKeys(env) {
 if(!env.kv)return [];
 const out=[],list=await env.kv.list({prefix:"apikeymeta:",limit:100});
 for(const k of list.keys){const v=await kvGet(env,k.name);if(v)out.push(v)}
 return out.sort((a,b)=>b.createdAt-a.createdAt);
}
async function listLogs(env) {
 if(!env.kv)return [];
 const keys=await env.kv.list({prefix:"log:",limit:100}),out=[];
 for(const k of keys.keys){const v=await kvGet(env,k.name);if(v)out.push(v)}
 return out.sort((a,b)=>b.time-a.time).slice(0,50);
}
export default {
 async fetch(request,env,ctx) {
  const url=new URL(request.url);
  if(request.method==="OPTIONS")return new Response(null,{headers:BASE_CORS});
  if(url.pathname==="/login"&&request.method==="GET") {
    if(!env.db || !env.SESSION_SECRET) return dbSetupError();
    try { if(!(await getAdmin(env))) return new Response(null,{status:302,headers:{...BASE_CORS,"Location":"/setup","Cache-Control":"no-store"}}); } catch { return dbSetupError(); }
    return html(loginPage());
  }
  if(url.pathname==="/setup"&&request.method==="GET") {
    if(!env.db || !env.SESSION_SECRET) return dbSetupError();
    try { if(await getAdmin(env)) return new Response(null,{status:302,headers:{...BASE_CORS,"Location":"/login","Cache-Control":"no-store"}}); } catch { return dbSetupError(); }
    return html(setupPage());
  }
  if(url.pathname==="/api/login"||url.pathname==="/api/logout"||url.pathname.startsWith("/api/")) {
    if(request.method==="GET"&&url.pathname==="/api/health")return json({name:"ProCDN",status:"ok",version:VERSION});
    return apiHandler(request,env,ctx,url);
  }
  if(url.pathname==="/admin"||url.pathname==="/admin/") {
    if(!(await isAdmin(request,env)))return new Response(null,{status:302,headers:{...BASE_CORS,"Location":"/login","Cache-Control":"no-store"}});
    return html(dashboardPage());
  }
  if(url.pathname==="/"||url.pathname==="/index.html")return new Response(`<html><head><meta http-equiv="refresh" content="0;url=/admin"></head><body><a href="/admin">Open ProCDN Admin</a></body></html>`,{headers:{...BASE_CORS,"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}});
  if(request.method!=="GET"&&request.method!=="HEAD")return json({error:"Method not allowed"},405);
  if(!env.kv)return json({error:"Missing KV binding 'kv'. Configure it in Cloudflare Dashboard > Worker > Settings > Bindings."},500);
  return handleAsset(request,env,ctx,url);
 }
};
