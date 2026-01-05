#!/usr/bin/env python3
# flask_server.py — AirLock: Crypto API + DB-backed telemetry + dashboard
# Map (left) + Battery Distribution bar chart (left) + NEW Scatter (Speed vs Altitude) under it
# Line charts (right) + KPIs + Now cards + Alerts + Export

from flask import Flask, request, jsonify, Response, redirect, make_response
from cryptography.fernet import Fernet
import json, time, os, sqlite3, csv, io

app = Flask(__name__)

# --- Crypto setup ---
FERNET_KEY = os.environ.get("FERNET_KEY") or b'HyMs5PCyDY5oWoEKZs98gwwU7ZKxSBrqifkQHVCHn-s='
cipher = Fernet(FERNET_KEY)

# --- DB helpers ---
DB_FILE = "airlock.db"

def get_db():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    return con

def generate_sample_telemetry():
    ts = int(time.time())
    return {
        "altitude": 120 + (ts % 10),
        "speed": 40 + (ts % 5),
        "battery": 90 - (ts % 20),
        "location": {"lat": 12.9716, "lon": 77.5946}
    }

@app.before_request
def log_request():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {request.method} {request.path}")

# --- Routes ---
@app.route('/')
def index():
    return redirect('/dashboard')

@app.route('/favicon.ico')
def favicon():
    return ('', 204)

@app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

# --- Crypto endpoints ---
@app.route('/send', methods=['POST'])
def send():
    telemetry = None
    if request.is_json:
        body = request.get_json(silent=True)
        if isinstance(body, dict) and "data" in body:
            telemetry = body["data"]
        elif body is not None:
            telemetry = body
    if telemetry is None:
        telemetry = generate_sample_telemetry()
    plaintext = json.dumps(telemetry) if isinstance(telemetry, (dict, list)) else str(telemetry)
    encrypted = cipher.encrypt(plaintext.encode()).decode()
    return jsonify({"encrypted": encrypted}), 200

@app.route('/receive', methods=['POST'])
def receive():
    if not request.is_json:
        return jsonify({"error": "expected JSON with key 'encrypted'"}), 400
    encrypted = request.json.get("encrypted")
    if not encrypted:
        return jsonify({"error": "missing 'encrypted' value"}), 400
    try:
        decrypted = cipher.decrypt(encrypted.encode()).decode()
    except Exception as e:
        return jsonify({"error": "decryption_failed", "detail": str(e)}), 400
    try:
        obj = json.loads(decrypted)
        return jsonify({"decrypted": obj}), 200
    except Exception:
        return jsonify({"decrypted": decrypted}), 200

# --- Helpers for time window ---
def window_clause(minutes):
    """Return SQL WHERE + params to restrict by ts in last N minutes. None/'' => no filter."""
    if minutes in (None, "", "null", "None"):
        return ("", ())
    try:
        m = int(minutes)
        if m <= 0:
            return ("", ())
    except:
        return ("", ())
    cutoff = time.time() - (m * 60)
    return ("WHERE ts >= ?", (cutoff,))

# --- History APIs (support ?limit= and ?minutes=) ---
@app.route('/last', methods=['GET'])
def last():
    try:
        minutes = request.args.get("minutes")
        where, params = window_clause(minutes)
        con = get_db()
        cur = con.cursor()
        sql = f"""
            SELECT msg_id, ts, altitude, speed, battery, lat, lon, raw
            FROM telemetry
            {where}
            ORDER BY inserted_at DESC
            LIMIT 1
        """
        cur.execute(sql, params)
        row = cur.fetchone()
        con.close()
        if not row:
            return jsonify({"status": "empty"}), 200
        return jsonify({
            "msg_id": row["msg_id"], "ts": row["ts"],
            "altitude": row["altitude"], "speed": row["speed"], "battery": row["battery"],
            "lat": row["lat"], "lon": row["lon"],
            "raw": json.loads(row["raw"]) if row["raw"] else None
        }), 200
    except sqlite3.OperationalError as e:
        return jsonify({"error": "db_not_initialized", "detail": str(e)}), 500

@app.route('/history', methods=['GET'])
def history():
    limit_str = request.args.get("limit", "100")
    minutes = request.args.get("minutes")
    try:
        n = max(1, min(int(limit_str), 1000))
    except ValueError:
        n = 100

    try:
        con = get_db()
        cur = con.cursor()
        where, params = window_clause(minutes)
        sql = f"""
            SELECT msg_id, ts, altitude, speed, battery, lat, lon, raw
            FROM telemetry
            {where}
            ORDER BY inserted_at DESC
            LIMIT ?
        """
        cur.execute(sql, (*params, n))
        rows = cur.fetchall()
        con.close()
        items = []
        for r in rows:
            try:
                raw_obj = json.loads(r["raw"]) if r["raw"] else None
            except Exception:
                raw_obj = None
            items.append({
                "msg_id": r["msg_id"], "ts": r["ts"],
                "altitude": r["altitude"], "speed": r["speed"], "battery": r["battery"],
                "lat": r["lat"], "lon": r["lon"], "raw": raw_obj
            })
        return jsonify({"count": len(items), "items": items}), 200
    except sqlite3.OperationalError as e:
        return jsonify({"error": "db_not_initialized", "detail": str(e)}), 500

@app.route('/export', methods=['GET'])
def export_csv():
    limit_str = request.args.get("limit", "1000")
    minutes = request.args.get("minutes")
    try:
        n = max(1, min(int(limit_str), 10000))
    except ValueError:
        n = 1000

    con = get_db()
    cur = con.cursor()
    where, params = window_clause(minutes)
    sql = f"""
        SELECT msg_id, ts, altitude, speed, battery, lat, lon
        FROM telemetry
        {where}
        ORDER BY inserted_at DESC
        LIMIT ?
    """
    cur.execute(sql, (*params, n))
    rows = cur.fetchall()
    con.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["msg_id", "ts", "altitude", "speed", "battery", "lat", "lon"])
    for r in rows:
        writer.writerow([r["msg_id"], r["ts"], r["altitude"], r["speed"], r["battery"], r["lat"], r["lon"]])
    csv_data = output.getvalue()
    output.close()

    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename=telemetry.csv"
    return resp

@app.route('/stats', methods=['GET'])
def stats():
    """KPIs over recent history; supports ?minutes= (optional) and ?limit= cap."""
    minutes = request.args.get("minutes")
    limit_str = request.args.get("limit", "2000")
    try:
        limit_cap = max(1, min(int(limit_str), 5000))
    except ValueError:
        limit_cap = 2000

    con = get_db()
    cur = con.cursor()
    where, params = window_clause(minutes)
    sql = f"""
        SELECT ts, altitude, speed, battery, lat, lon
        FROM telemetry
        {where}
        ORDER BY inserted_at DESC
        LIMIT ?
    """
    cur.execute(sql, (*params, limit_cap))
    rows = cur.fetchall()
    con.close()

    if not rows:
        return jsonify({"count": 0, "message": "no data"}), 200

    now = time.time()
    ts_vals, alts, spds, bats, coords = [], [], [], [], []
    low_bat = 0
    for r in rows:
        ts = r["ts"]; alt = r["altitude"]; spd = r["speed"]; bat = r["battery"]
        lat = r["lat"]; lon = r["lon"]
        if ts is not None: ts_vals.append(ts)
        if isinstance(alt, (int, float)): alts.append(alt)
        if isinstance(spd, (int, float)): spds.append(spd)
        if isinstance(bat, (int, float)):
            bats.append(bat)
            if bat < 20: low_bat += 1
        if lat is not None and lon is not None:
            coords.append((lat, lon))

    def agg(arr):
        if not arr: return {"avg": None, "min": None, "max": None}
        return {"avg": sum(arr)/len(arr), "min": min(arr), "max": max(arr)}

    res = {
        "count": len(rows),
        "time": {
            "latest_ts": max(ts_vals) if ts_vals else None,
            "earliest_ts": min(ts_vals) if ts_vals else None,
            "last_seen_secs_ago": (now - max(ts_vals)) if ts_vals else None
        },
        "altitude": agg(alts),
        "speed": agg(spds),
        "battery": agg(bats),
        "low_battery_rate": (low_bat/len(rows))*100.0 if rows else 0.0,
        "path_sample": coords[::-1]
    }
    return jsonify(res), 200

# --- Dashboard (map left; bar chart under map; NEW scatter under bar; line charts right) ---
DASH_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>AirLock Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
        integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
        integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    .muted { color: #666; }
    .row { margin: 12px 0; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    input, button, a.btn, select { padding: 6px 10px; border: 1px solid #ddd; border-radius: 6px; text-decoration:none; background:inherit; color:inherit; }
    button, a.btn { cursor:pointer; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { border-bottom: 1px solid #eee; padding: 8px; text-align: left; }
    th { position: sticky; top: 0; background: #fafafa; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; background:#f0f0f0; }
    .pill.bad { background:#ffe5e5; color:#900; font-weight:600; }
    .grid { display:grid; grid-template-columns: 1fr; gap:16px; }
    @media(min-width: 1100px){ .grid { grid-template-columns: 1.2fr 1fr; } }
    canvas { width:100%; height:300px; }
    #map { width:100%; height: 360px; border:1px solid #eee; border-radius:8px; }
    .kpis { display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; margin: 16px 0; }
    .kpi { padding:12px; border:1px solid #eee; border-radius:10px; background:#fafafa; }
    .kpi .big { font-size: 22px; font-weight: 700; }
    .kpi .small { font-size: 12px; color:#666; }
    .alert { padding:10px 12px; border-radius:8px; background:#ffe5e5; color:#900; margin-top:8px; display:none; }
    .now { display:grid; grid-template-columns: repeat(2, 1fr); gap:10px; margin:12px 0; }
    .now .card { padding:10px; border:1px solid #eee; border-radius:10px; background:#fafafa; }
  </style>
</head>
<body>
  <h1>AirLock Dashboard</h1>
  <p class="muted">Live telemetry from <code>airlock.db</code> — charts, KPIs, map & table. Auto-refresh every 3s.</p>

  <div class="row">
    <label>Minutes:
      <select id="minutes">
        <option value="" selected>All</option>
        <option value="5">5m</option>
        <option value="15">15m</option>
        <option value="60">60m</option>
      </select>
    </label>
    <label>Limit: <input id="limit" type="number" min="20" max="1000" value="200" /></label>
    <label>Battery alert (%): <input id="batThresh" type="number" min="1" max="100" value="20" style="width:80px;" /></label>
    <button onclick="loadAll(true)">Refresh</button>
    <a class="btn" id="exportLink" href="/export?limit=1000">Export CSV</a>
    <button id="locateBtn" onclick="locateDrone()">Locate Drone</button>
    <label style="display:flex;align-items:center;gap:6px;">
      <input id="followToggle" type="checkbox" checked /> Follow latest
    </label>
  </div>

  <div id="alertBar" class="alert">Battery below threshold!</div>

  <div class="now">
    <div class="card" id="now_main">Latest: —</div>
    <div class="card" id="now_meta">Meta: —</div>
  </div>

  <div class="kpis">
    <div class="kpi"><div class="big" id="k_count">-</div><div class="small">Rows in window</div></div>
    <div class="kpi"><div class="big" id="k_last">-</div><div class="small">Last seen (s ago)</div></div>
    <div class="kpi"><div class="big" id="k_lowb">-</div><div class="small">Low battery rate (%)</div></div>

    <div class="kpi"><div class="big" id="k_alt_avg">-</div><div class="small">Altitude avg / min / max</div></div>
    <div class="kpi"><div class="big" id="k_spd_avg">-</div><div class="small">Speed avg / min / max</div></div>
    <div class="kpi"><div class="big" id="k_bat_avg">-</div><div class="small">Battery avg / min / max</div></div>
  </div>

  <!-- GRID: Left column => map + bar chart + NEW scatter; Right column => line charts -->
  <div class="grid">
    <div>
      <div id="map"></div>
      <!-- Battery Distribution bar chart (left column) -->
      <canvas id="batDistChart" style="margin-top:16px;"></canvas>
      <!-- NEW: Speed vs Altitude scatter (left column, below bar) -->
      <canvas id="spdAltChart" style="margin-top:16px;"></canvas>
    </div>
    <div>
      <canvas id="altChart"></canvas>
      <canvas id="spdChart" style="margin-top:16px;"></canvas>
      <canvas id="batChart" style="margin-top:16px;"></canvas>
    </div>
  </div>

  <table id="tbl">
    <thead>
      <tr>
        <th>#</th><th>msg_id</th><th>ts</th><th>alt</th><th>spd</th><th>bat</th><th>lat</th><th>lon</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>

<script>
let altChart, spdChart, batChart, batDistChart, spdAltChart, map, pathLine, droneMarker, droneCircle;
let t=3;

function fmt(x, d=2){ return (typeof x==='number' && !isNaN(x)) ? x.toFixed(d) : (x ?? '-') }
function fmtInt(x){ return (typeof x==='number' && !isNaN(x)) ? Math.round(x) : (x ?? '-') }
async function fetchJSON(url){ const r = await fetch(url); return await r.json(); }

function makeLine(ctx, labels, series, label){
  if (ctx.chart) { ctx.chart.destroy(); }
  const chart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [{ label, data: series, pointRadius: 0, tension: 0.2 }] },
    options: {
      responsive: true, animation: false,
      scales: { x: { ticks: { maxTicksLimit: 6 } }, y: { beginAtZero: false } },
      plugins: { legend: { display: true } }
    }
  });
  ctx.chart = chart;
  return chart;
}

function makeBars(canvas, labels, values, title){
  if (canvas.chart) { canvas.chart.destroy(); }
  const chart = new Chart(canvas, {
    type: 'bar',
    data: { labels, datasets: [{ label: title, data: values }] },
    options: {
      responsive: true, animation: false,
      scales: { y: { beginAtZero: true } },
      plugins: { legend: { display: false } }
    }
  });
  canvas.chart = chart;
  return chart;
}

function makeScatter(canvas, points, title){
  if (canvas.chart) { canvas.chart.destroy(); }
  const chart = new Chart(canvas, {
    type: 'scatter',
    data: {
      datasets: [{
        label: title,
        data: points,     // [{x: altitude, y: speed}, ...]
        pointRadius: 3
      }]
    },
    options: {
      responsive: true, animation: false,
      scales: {
        x: { title: { display: true, text: 'Altitude' } },
        y: { title: { display: true, text: 'Speed' } }
      },
      plugins: { legend: { display: true } }
    }
  });
  canvas.chart = chart;
  return chart;
}

function updateTable(items, thresh){
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  items.forEach((it, idx)=>{
    const tr = document.createElement('tr');
    const bad = (typeof it.battery==='number' ? it.battery < thresh : false);
    tr.innerHTML = `
      <td>${idx+1}</td>
      <td><span class="pill">${it.msg_id}</span></td>
      <td>${fmt(it.ts,3)}</td>
      <td>${it.altitude ?? ''}</td>
      <td>${it.speed ?? ''}</td>
      <td><span class="pill ${bad?'bad':''}">${it.battery ?? ''}</span></td>
      <td>${it.lat ?? ''}</td>
      <td>${it.lon ?? ''}</td>
    `;
    tbody.appendChild(tr);
  });
}

function ensureMap(){
  if (map) return map;
  map = L.map('map').setView([12.9716, 77.5946], 12);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19 }).addTo(map);
  pathLine = L.polyline([], { color: '#3388ff' }).addTo(map);
  return map;
}

function updateMap(coords){
  ensureMap();
  const clean = coords.filter(p => Array.isArray(p) && p.length===2 && isFinite(p[0]) && isFinite(p[1]));
  pathLine.setLatLngs(clean);
  if (clean.length) {
    const latest = clean[clean.length - 1];
    const latlng = [latest[0], latest[1]];
    if (!droneMarker) {
      const droneIcon = L.divIcon({
        className: 'drone-icon',
        html: `<div style="width:14px;height:14px;background:#2563eb;border:2px solid white;border-radius:50%;box-shadow:0 0 0 3px rgba(37,99,235,0.25);"></div>`,
        iconSize: [14,14], iconAnchor: [7,7]
      });
      droneMarker = L.marker(latlng, { icon: droneIcon }).addTo(map).bindPopup('Drone (latest)');
    } else {
      droneMarker.setLatLng(latlng);
    }
    if (!droneCircle) {
      droneCircle = L.circle(latlng, { radius: 25, color: '#2563eb', fillOpacity: 0.08 }).addTo(map);
    } else {
      droneCircle.setLatLng(latlng);
    }
    const follow = document.getElementById('followToggle')?.checked;
    if (follow) map.panTo(latlng, { animate: true });
  }
  const follow = document.getElementById('followToggle')?.checked;
  if (clean.length && !follow) map.fitBounds(pathLine.getBounds(), { padding:[20,20] });
}

function locateDrone(){
  if (droneMarker) {
    const ll = droneMarker.getLatLng();
    map.setView(ll, Math.max(map.getZoom(), 14), { animate: true });
    droneMarker.openPopup();
  } else {
    alert('No latest drone position yet.');
  }
}

async function updateNowCards(minutes){
  const last = await fetchJSON('/last' + (minutes ? ('?minutes=' + minutes) : ''));
  if (!last || last.status === 'empty') {
    document.getElementById('now_main').textContent = 'Latest: —';
    document.getElementById('now_meta').textContent = 'Meta: —';
    return;
  }
  const lat = last.lat, lon = last.lon;
  const alt = last.altitude, spd = last.speed, bat = last.battery;
  const ts = last.ts != null ? Number(last.ts).toFixed(3) : '-';
  document.getElementById('now_main').textContent =
    `Alt: ${alt ?? '-'}  |  Spd: ${spd ?? '-'}  |  Bat: ${bat ?? '-'}`;
  const age = (last.ts!=null) ? (Date.now()/1000 - Number(last.ts)) : null;
  document.getElementById('now_meta').textContent =
    `ID: ${last.msg_id || '-'}  |  @(${lat ?? '-'}, ${lon ?? '-'})  |  Age: ${age ? age.toFixed(1) : '-'}s`;
  if (droneMarker) {
    const html = `
      <div style="min-width:200px">
        <div><strong>Drone (latest)</strong></div>
        <div>ts: ${ts}</div>
        <div>alt: ${alt ?? '-'} | spd: ${spd ?? '-'}</div>
        <div>bat: ${bat ?? '-'}</div>
        <div>lat,lon: ${lat ?? '-'}, ${lon ?? '-'}</div>
      </div>`;
    droneMarker.bindPopup(html);
  }
}

function buildBatteryDistribution(items){
  // Buckets: ≥80, 50–79, 20–49, <20
  const buckets = {'≥80%':0,'50–79%':0,'20–49%':0,'<20%':0};
  items.forEach(it=>{
    const b = it.battery;
    if (typeof b !== 'number' || isNaN(b)) return;
    if (b >= 80) buckets['≥80%']++;
    else if (b >= 50) buckets['50–79%']++;
    else if (b >= 20) buckets['20–49%']++;
    else buckets['<20%']++;
  });
  return buckets;
}

async function loadAll(force=false){
  const minutesSel = document.getElementById('minutes').value; // "" by default (All)
  const limit = Math.max(20, Math.min(parseInt(document.getElementById('limit').value||'200'), 1000));
  const thresh = Math.max(1, Math.min(parseInt(document.getElementById('batThresh').value||'20'), 100));

  // build query strings
  const qs = '?limit='+limit + (minutesSel?('&minutes='+minutesSel):'');
  document.getElementById('exportLink').href = '/export'+qs;

  // fetch data
  const [hist, stat] = await Promise.all([
    fetchJSON('/history'+qs),
    fetchJSON('/stats'+(minutesSel?('?minutes='+minutesSel):''))
  ]);

  // charts (line series)
  const items = (hist.items||[]).slice().reverse(); // oldest -> newest for lines
  const labels = items.map(it => fmt(it.ts, 3));
  const alts = items.map(it => it.altitude ?? null);
  const spds = items.map(it => it.speed ?? null);
  const bats = items.map(it => it.battery ?? null);

  if(!altChart || force){ altChart = makeLine(document.getElementById('altChart'), labels, alts, 'Altitude'); }
  else { altChart.data.labels = labels; altChart.data.datasets[0].data = alts; altChart.update(); }

  if(!spdChart || force){ spdChart = makeLine(document.getElementById('spdChart'), labels, spds, 'Speed'); }
  else { spdChart.data.labels = labels; spdChart.data.datasets[0].data = spds; spdChart.update(); }

  if(!batChart || force){ batChart = makeLine(document.getElementById('batChart'), labels, bats, 'Battery'); }
  else { batChart.data.labels = labels; batChart.data.datasets[0].data = bats; batChart.update(); }

  // Battery Distribution bar (left)
  const dist = buildBatteryDistribution(items);
  const distLabels = Object.keys(dist);
  const distValues = distLabels.map(k => dist[k]);
  if (!batDistChart || force) {
    batDistChart = makeBars(document.getElementById('batDistChart'), distLabels, distValues, 'Battery Distribution (count)');
  } else {
    batDistChart.data.labels = distLabels;
    batDistChart.data.datasets[0].data = distValues;
    batDistChart.update();
  }

  // NEW: Speed vs Altitude scatter (left, under bar)
  const scatterPts = items
    .map(it => ({x: (typeof it.altitude==='number'?it.altitude:null), y: (typeof it.speed==='number'?it.speed:null)}))
    .filter(p => p.x !== null && p.y !== null);
  if (!spdAltChart || force) {
    spdAltChart = makeScatter(document.getElementById('spdAltChart'), scatterPts, 'Speed vs Altitude');
  } else {
    spdAltChart.data.datasets[0].data = scatterPts;
    spdAltChart.update();
  }

  // table (newest -> oldest)
  updateTable(items.slice().reverse(), thresh);

  // KPIs
  document.getElementById('k_count').textContent = fmtInt(stat.count);
  document.getElementById('k_last').textContent = fmt(stat.time?.last_seen_secs_ago, 1);
  document.getElementById('k_lowb').textContent = fmt(stat.low_battery_rate, 1);
  const a = stat.altitude || {}, s = stat.speed || {}, b = stat.battery || {};
  document.getElementById('k_alt_avg').textContent = `${fmt(a.avg,1)} / ${fmt(a.min,1)} / ${fmt(a.max,1)}`;
  document.getElementById('k_spd_avg').textContent = `${fmt(s.avg,1)} / ${fmt(s.min,1)} / ${fmt(s.max,1)}`;
  document.getElementById('k_bat_avg').textContent = `${fmt(b.avg,1)} / ${fmt(b.min,1)} / ${fmt(b.max,1)}`;

  // Map & Now
  updateMap(stat.path_sample || []);
  await updateNowCards(minutesSel);

  // Alert bar
  const last = await fetchJSON('/last' + (minutesSel?('?minutes='+minutesSel):''));
  const alertBar = document.getElementById('alertBar');
  const low = (last && typeof last.battery==='number' && last.battery < thresh);
  alertBar.style.display = low ? 'block' : 'none';
}

// auto-refresh every second (cycles 3..1 then refresh)
setInterval(()=>{
  t = (t<=1?3:t-1);
  if (t===3) loadAll();
}, 1000);

// initial load (force chart build)
loadAll(true);
</script>
</body>
</html>
"""

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return Response(DASH_HTML, mimetype="text/html")

if __name__ == '__main__':
    # Change port if 5000 is busy: app.run(..., port=5050)
    app.run(debug=True, host='127.0.0.1', port=5000)
