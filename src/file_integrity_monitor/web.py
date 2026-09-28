"""Loopback-only browser dashboard for the file integrity monitor."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
from typing import Any
import webbrowser

from .core import create_baseline, load_baseline, scan_against_baseline, write_json

MAX_REQUEST_BYTES = 64 * 1024


class DashboardController:
    """Keep browser-facing input validation separate from the HTTP handler."""

    def __init__(self) -> None:
        self.last_result: dict[str, Any] | None = None

    @staticmethod
    def _required_path(payload: dict[str, Any], name: str) -> Path:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name.replace('_', ' ')} is required")
        return Path(value.strip()).expanduser().resolve()

    @staticmethod
    def _excludes(payload: dict[str, Any]) -> list[str]:
        value = payload.get("excludes", [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError("excludes must be a list of patterns")
        return [item.strip() for item in value if item.strip()]

    def baseline(self, payload: dict[str, Any]) -> dict[str, Any]:
        root = self._required_path(payload, "root")
        destination = self._required_path(payload, "baseline_path")
        result = create_baseline(root, self._excludes(payload))
        saved = write_json(result, destination)
        response = {"kind": "baseline", "saved_to": str(saved), "result": result}
        self.last_result = response
        return response

    def scan(self, payload: dict[str, Any]) -> dict[str, Any]:
        baseline_path = self._required_path(payload, "baseline_path")
        report_path = self._required_path(payload, "report_path")
        baseline = load_baseline(baseline_path)
        root_value = payload.get("root")
        root = (
            Path(root_value).expanduser().resolve()
            if isinstance(root_value, str) and root_value.strip()
            else None
        )
        result = scan_against_baseline(baseline, root, self._excludes(payload))
        saved = write_json(result, report_path)
        response = {"kind": "scan", "saved_to": str(saved), "result": result}
        self.last_result = response
        return response


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Integrity Desk</title>
  <style>
    :root{color-scheme:dark;--bg:#0b0e13;--surface:#10151c;--line:#29313d;--ink:#eef2f6;--muted:#929eac;--accent:#7ab9ec;--good:#74d7a2;--warn:#e9ba62;--bad:#ed7c84;font:15px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink)}button,input,textarea{font:inherit}.shell{max-width:1160px;margin:auto;padding:36px 24px 48px}.top{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:30px;padding-bottom:24px;border-bottom:1px solid var(--line)}.eyebrow{color:var(--accent);font-size:.72rem;font-weight:800;letter-spacing:.16em;text-transform:uppercase}.top h1{font-size:clamp(2rem,4vw,3.1rem);letter-spacing:-.045em;line-height:1;margin:.45rem 0 .7rem}.top p{max-width:650px;color:var(--muted);margin:0}.badge{border-left:2px solid var(--accent);padding:2px 0 2px 12px;color:#bedcf3;white-space:nowrap}.grid{display:grid;grid-template-columns:minmax(300px,.72fr) minmax(0,1.28fr);gap:34px}.controls{padding-right:30px;border-right:1px solid var(--line);position:sticky;top:20px;align-self:start}.controls h2,.results h2{font-size:1rem;margin:0 0 18px}.field{display:grid;gap:7px;margin-bottom:15px}.field span{font-size:.7rem;color:var(--muted);font-weight:800;text-transform:uppercase;letter-spacing:.09em}input,textarea{width:100%;border:0;border-bottom:1px solid #3a4553;background:transparent;color:var(--ink);padding:10px 2px;outline:none}textarea{min-height:68px;resize:vertical}input:focus,textarea:focus{border-color:var(--accent)}.actions{display:flex;gap:9px;margin-top:20px}button{border:1px solid var(--accent);padding:10px 13px;font-weight:800;cursor:pointer;background:var(--accent);color:#07131d}button.secondary{background:transparent;color:var(--ink);border-color:#465261}button:disabled{opacity:.45;cursor:wait}.privacy{margin:20px 0 0;padding-top:16px;border-top:1px solid var(--line);font-size:.78rem;color:var(--muted)}.results{min-height:590px}.status{display:flex;justify-content:space-between;align-items:center;gap:14px;padding-bottom:17px;border-bottom:1px solid var(--line)}.status strong{font-size:1.15rem}.status small{color:var(--muted);display:block;margin-top:3px}.pill{padding:4px 0 4px 10px;font-size:.76rem;font-weight:800;border-left:2px solid var(--muted);color:#cbd5df}.pill.good{border-color:var(--good);color:var(--good)}.pill.warn{border-color:var(--warn);color:var(--warn)}.pill.bad{border-color:var(--bad);color:var(--bad)}.metrics{display:grid;grid-template-columns:repeat(5,1fr);margin:17px 0;border-block:1px solid var(--line)}.metric{padding:13px 10px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric b{display:block;font-size:1.35rem}.metric span{font-size:.67rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}.empty{display:grid;place-items:center;text-align:center;min-height:380px;color:var(--muted)}.empty div{max-width:390px}.empty b{display:block;color:var(--ink);font-size:1.1rem;margin-bottom:7px}.tabs{display:flex;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-bottom:4px}.tab{background:transparent;color:var(--muted);border:0;border-bottom:2px solid transparent;padding:9px 0}.tab.active{color:var(--ink);border-color:var(--accent)}.list{max-height:405px;overflow:auto}.row{display:grid;grid-template-columns:105px minmax(0,1fr);gap:12px;padding:13px 2px;border-bottom:1px solid #202732}.row .kind{font-size:.68rem;font-weight:900;text-transform:uppercase;letter-spacing:.08em;color:var(--accent)}.row code{white-space:normal;word-break:break-all;color:#dfe7ef}.row small{display:block;color:var(--muted);margin-top:4px}.notice{margin-top:12px;padding:11px 0;border-block:1px solid #5c4523;color:#ffd993}.hidden{display:none}@media(max-width:820px){.grid{grid-template-columns:1fr}.controls{position:static;border-right:0;border-bottom:1px solid var(--line);padding:0 0 26px}.metrics{grid-template-columns:repeat(2,1fr)}.top{display:block}.badge{display:inline-block;margin-top:16px}}@media(max-width:480px){.shell{padding:22px 14px}.actions{display:grid}.row{grid-template-columns:1fr}.metrics{grid-template-columns:1fr 1fr}}
  </style>
</head>
<body>
<main class="shell">
  <header class="top"><div><div class="eyebrow">Local security utility</div><h1>Integrity Desk</h1><p>Create a trusted SHA-256 record, compare it with the current folder, and review every change without reading raw JSON.</p></div><div class="badge">Loopback only · no uploads</div></header>
  <div class="grid">
    <section class="controls" aria-label="Scan controls">
      <h2>Monitor configuration</h2>
      <label class="field"><span>Folder to monitor</span><input id="root" placeholder="C:\Projects\important-files" autocomplete="off"></label>
      <label class="field"><span>Baseline file</span><input id="baseline" value="fim-baseline.json" autocomplete="off"></label>
      <label class="field"><span>Report file</span><input id="report" value="fim-report.json" autocomplete="off"></label>
      <label class="field"><span>Additional exclusions · one per line</span><textarea id="excludes" placeholder="node_modules/**&#10;*.log"></textarea></label>
      <div class="actions"><button id="create">Create baseline</button><button id="scan" class="secondary">Run integrity scan</button></div>
      <p class="privacy">Paths and evidence remain on this computer. Every write action requires a random token created for this dashboard session.</p>
    </section>
    <section class="results" aria-live="polite">
      <div id="empty" class="empty"><div><b>No evidence loaded yet</b>Create a baseline for a trusted folder, then scan it after a change. Results will be grouped as added, modified, deleted, moved, or errors.</div></div>
      <div id="content" class="hidden">
        <div class="status"><div><strong id="headline"></strong><small id="meta"></small></div><span id="state" class="pill"></span></div>
        <div id="metrics" class="metrics"></div>
        <div id="tabs" class="tabs"></div>
        <div id="list" class="list"></div>
        <div id="notice" class="notice hidden"></div>
      </div>
    </section>
  </div>
</main>
<script>
const token=__TOKEN__;
const $=id=>document.getElementById(id);
const fields=()=>({root:$('root').value.trim(),baseline_path:$('baseline').value.trim(),report_path:$('report').value.trim(),excludes:$('excludes').value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean)});
let last=null,active='summary';
const escapeHtml=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function run(endpoint,button){const controls=[$('create'),$('scan')];controls.forEach(b=>b.disabled=true);button.textContent='Working…';try{const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','X-FIM-Token':token},body:JSON.stringify(fields())});const data=await response.json();if(!response.ok)throw new Error(data.error||'Request failed');last=data;render(data)}catch(error){showError(error.message)}finally{controls.forEach(b=>b.disabled=false);$('create').textContent='Create baseline';$('scan').textContent='Run integrity scan'}}
function showError(message){$('empty').classList.add('hidden');$('content').classList.remove('hidden');$('headline').textContent='Action could not be completed';$('meta').textContent='Review the folder and file paths, then try again.';$('state').textContent='Needs attention';$('state').className='pill bad';$('metrics').innerHTML='';$('tabs').innerHTML='';$('list').innerHTML='';$('notice').textContent=message;$('notice').classList.remove('hidden')}
function render(data){$('empty').classList.add('hidden');$('content').classList.remove('hidden');$('notice').classList.add('hidden');const result=data.result,summary=result.summary,isScan=data.kind==='scan';$('headline').textContent=isScan?(summary.changed?'Changes detected':'No changes detected'):'Trusted baseline created';$('meta').textContent=`${result.root} · saved to ${data.saved_to}`;$('state').textContent=isScan?(summary.changed?`${summary.changed} changed`:'Clean'):`${summary.files} files`;$('state').className=`pill ${isScan?(summary.changed?'warn':'good'):(summary.errors?'warn':'good')}`;const values=isScan?[['Scanned',summary.scanned_files],['Added',summary.added],['Modified',summary.modified],['Deleted',summary.deleted],['Moved',summary.moved]]:[['Files',summary.files],['Bytes',summary.bytes.toLocaleString()],['Errors',summary.errors],['Seconds',summary.duration_seconds],['Algorithm','SHA-256']];$('metrics').innerHTML=values.map(([label,value])=>`<div class="metric"><b>${escapeHtml(value)}</b><span>${escapeHtml(label)}</span></div>`).join('');last=data;active=isScan?'summary':'files';renderTabs()}
function groups(){if(!last)return{};const result=last.result;if(last.kind==='baseline')return{files:Object.entries(result.entries).map(([path,item])=>({kind:'Tracked',path,detail:`${item.size.toLocaleString()} bytes · ${item.sha256}`})),errors:result.errors};const c=result.changes;return{summary:[...c.added.map(x=>({kind:'Added',path:x.path,detail:`${x.size.toLocaleString()} bytes · ${x.sha256}`})),...c.modified.map(x=>({kind:'Modified',path:x.path,detail:`${x.before_size.toLocaleString()} → ${x.after_size.toLocaleString()} bytes`})),...c.deleted.map(x=>({kind:'Deleted',path:x.path,detail:`${x.size.toLocaleString()} bytes · ${x.sha256}`})),...c.moved.map(x=>({kind:'Moved',path:`${x.from} → ${x.to}`,detail:`${x.size.toLocaleString()} bytes · ${x.sha256}`}))],added:c.added.map(x=>({kind:'Added',path:x.path,detail:x.sha256})),modified:c.modified.map(x=>({kind:'Modified',path:x.path,detail:`${x.before_sha256} → ${x.after_sha256}`})),deleted:c.deleted.map(x=>({kind:'Deleted',path:x.path,detail:x.sha256})),moved:c.moved.map(x=>({kind:'Moved',path:`${x.from} → ${x.to}`,detail:x.sha256})),errors:result.errors}}
function renderTabs(){const data=groups(),keys=Object.keys(data);if(!keys.includes(active))active=keys[0];$('tabs').innerHTML=keys.map(key=>`<button class="tab ${key===active?'active':''}" data-key="${key}">${key[0].toUpperCase()+key.slice(1)} · ${(data[key]||[]).length}</button>`).join('');$('tabs').querySelectorAll('button').forEach(button=>button.onclick=()=>{active=button.dataset.key;renderTabs()});const items=data[active]||[];$('list').innerHTML=items.length?items.map(item=>`<div class="row"><div class="kind">${escapeHtml(item.kind||'Error')}</div><div><code>${escapeHtml(item.path||item.error)}</code>${item.detail?`<small>${escapeHtml(item.detail)}</small>`:''}</div></div>`).join(''):'<div class="empty"><div><b>Nothing in this category</b>No matching evidence was recorded.</div></div>'}
$('create').onclick=()=>run('/api/baseline',$('create'));
$('scan').onclick=()=>run('/api/scan',$('scan'));
fetch('/api/status').then(r=>r.json()).then(data=>{if(data.last){last=data.last;render(last)}}).catch(()=>{});
</script>
</body>
</html>"""


def _handler(controller: DashboardController, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "IntegrityDesk/1.0"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _headers(self, status: int, content_type: str = "application/json; charset=utf-8") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()

        def _json(self, status: int, payload: object) -> None:
            body = json.dumps(payload).encode("utf-8")
            self._headers(status)
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/":
                page = HTML.replace("__TOKEN__", json.dumps(token)).encode("utf-8")
                self._headers(200, "text/html; charset=utf-8")
                self.wfile.write(page)
            elif self.path == "/api/status":
                self._json(200, {"last": controller.last_result})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not secrets.compare_digest(self.headers.get("X-FIM-Token", ""), token):
                self._json(403, {"error": "invalid request token"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._json(400, {"error": "invalid request length"})
                return
            if length < 0 or length > MAX_REQUEST_BYTES:
                self._json(413, {"error": "request is too large"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("request body must be an object")
                if self.path == "/api/baseline":
                    result = controller.baseline(payload)
                elif self.path == "/api/scan":
                    result = controller.scan(payload)
                else:
                    self._json(404, {"error": "not found"})
                    return
            except (OSError, ValueError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
                return
            self._json(200, result)

    return Handler


def run_dashboard(host: str = "127.0.0.1", port: int = 8765, *, open_browser: bool = True) -> None:
    """Run the local dashboard until interrupted."""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("the dashboard may only bind to a loopback address")
    controller = DashboardController()
    token = secrets.token_urlsafe(32)
    with ThreadingHTTPServer((host, port), _handler(controller, token)) as server:
        address = f"http://127.0.0.1:{server.server_address[1]}"
        print(f"Integrity Desk is available at {address}")
        print("Press Ctrl+C to stop it.")
        if open_browser:
            webbrowser.open(address)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            print("Stopping Integrity Desk")
