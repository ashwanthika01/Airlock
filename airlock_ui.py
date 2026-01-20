import streamlit as st
import requests
import time
import os
import math
import socket
from collections import deque
import concurrent.futures

import folium
from streamlit_folium import st_folium

from streamlit_autorefresh import st_autorefresh

# ======================================================
# CONFIG
# ======================================================

# (Keep your original log path)
AIRLOCK_LOG_PATH = r"D:\airlock\airlock.log"

# Tunables
FAILSAFE_BLOCK_RATE_THRESHOLD = 3.0  # packets/sec
AIRLOCK_PORT = 9001

# Discovery tuning for speed
MAX_SCAN_ADDRESSES = 128         # max addresses to probe in the /24
THREAD_WORKERS = 64              # concurrency level
HTTP_TIMEOUT_FAST = 0.18         # seconds per probe

st.set_page_config(
    page_title="AirLock Security Dashboard",
    layout="wide"
)

# ======================================================
# HEADER
# ======================================================

st.title("🔐 AirLock Security Dashboard")
st.caption("USB-based Drone Communication Security (Read-Only)")

refresh = st.slider(
    "Refresh interval (seconds)",
    min_value=1,
    max_value=5,
    value=2
)

# ======================================================
# Requests session (shared) and small helpers
# ======================================================
# create a single requests.Session per Streamlit run. It's lightweight and helps perf.
_session = requests.Session()
_adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)

# ======================================================
# AUTO BACKEND DISCOVERY (VERY FAST PARALLEL SCAN)
# ======================================================

PREFERRED_BACKEND_IPS = [
    "127.0.0.1",  # local
    "localhost"
]

def get_local_ip():
    """Return the local IP address used to reach the internet (or None)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # determine a routable local IP (no traffic sent)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
    return ip

def get_network_prefix(ip):
    """Return the network prefix (first three octets) for quick /24 scans."""
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3])

def try_status_at(ip, timeout=HTTP_TIMEOUT_FAST):
    """
    Try the /status endpoint at the given ip:port. Return parsed JSON or None.
    Uses the shared requests.Session for faster TCP reuse.
    """
    # handle localhost 'localhost' name separately
    host = ip
    if ip == "localhost":
        host = "127.0.0.1"
    url = f"http://{host}:{AIRLOCK_PORT}/status"
    try:
        r = _session.get(url, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            # simple validation of expected keys
            if isinstance(data, dict) and "service_running" in data and "usb_present" in data:
                return data
    except Exception:
        # ignore failures; return None
        return None
    return None

def build_candidate_list(prefix, local_ip, last_known=None, max_addrs=MAX_SCAN_ADDRESSES):
    """
    Build prioritized candidate IP list:
      1) preferred localhost entries
      2) last_known (if present)
      3) local_ip itself
      4) nearby addresses around local host octet (fast hits in LAN)
      5) sequential remainder to reach max_addrs
    """
    candidates = []
    # preferred
    for ip in PREFERRED_BACKEND_IPS:
        if ip not in candidates:
            candidates.append(ip)

    # last known
    if last_known and last_known not in candidates:
        candidates.append(last_known)

    # local ip
    if local_ip and local_ip not in candidates:
        candidates.append(local_ip)

    if not prefix:
        return candidates

    # get host octet
    try:
        host_octet = int(local_ip.split(".")[-1])
    except Exception:
        host_octet = 100

    # nearby window (first priority)
    window = []
    radius = min(40, max(5, max_addrs // 4))  # test neighbors first
    for delta in range(-radius, radius + 1):
        octet = host_octet + delta
        if 1 <= octet <= 254:
            ip = f"{prefix}.{octet}"
            if ip not in candidates:
                window.append(ip)

    # add window first
    for ip in window:
        if len(candidates) >= max_addrs:
            break
        candidates.append(ip)

    # fill remaining sequentially over prefix to reach max_addrs
    if len(candidates) < max_addrs:
        for i in range(1, 255):
            ip = f"{prefix}.{i}"
            if ip not in candidates:
                candidates.append(ip)
            if len(candidates) >= max_addrs:
                break

    return candidates[:max_addrs]

def discover_airlock_backend():
    """
    Fast parallel discovery:
      1) Try preferred IPs synchronously (very fast)
      2) Try last known and local IP
      3) Build candidate list prioritizing neighbors
      4) Probe candidates in parallel worker pool and return first match
      5) If nothing found return None (we set a discovery-failed flag)
    This function is designed to be called when st.session_state.backend_ip is None,
    so it should be reasonably fast and conservative.
    """
    # 1) Preferred quick tries
    for ip in PREFERRED_BACKEND_IPS:
        data = try_status_at(ip, timeout=0.12)
        if data:
            # discovery succeeded
            st.session_state.backend_discovery_failed = False
            return ip

    # 2) Last known quick try (if exists)
    last_known = st.session_state.get("backend_ip")
    if last_known:
        data = try_status_at(last_known, timeout=0.12)
        if data:
            st.session_state.backend_discovery_failed = False
            return last_known

    # 3) local ip quick try
    local_ip = get_local_ip()
    if local_ip:
        data = try_status_at(local_ip, timeout=0.12)
        if data:
            st.session_state.backend_discovery_failed = False
            return local_ip

    # 4) Parallel scan over prioritized candidate list
    prefix = get_network_prefix(local_ip)
    candidates = build_candidate_list(prefix, local_ip, last_known=last_known, max_addrs=MAX_SCAN_ADDRESSES)

    # worker that returns ip on success or None
    def worker(ip):
        try:
            res = try_status_at(ip, timeout=HTTP_TIMEOUT_FAST)
            if res:
                return ip
        except Exception:
            pass
        return None

    found_ip = None
    # Protect against weird values
    n_workers = min(THREAD_WORKERS, max(1, len(candidates)))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as executor:
            future_to_ip = {executor.submit(worker, ip): ip for ip in candidates}
            # iterate as futures complete; set short overall timeout to avoid blocking
            try:
                for future in concurrent.futures.as_completed(future_to_ip, timeout=5):
                    try:
                        ip = future.result()
                        if ip:
                            found_ip = ip
                            # best-effort cancel remaining
                            for f in future_to_ip:
                                if not f.done():
                                    f.cancel()
                            break
                    except concurrent.futures.CancelledError:
                        pass
                    except Exception:
                        # ignore individual worker errors
                        pass
            except concurrent.futures.TimeoutError:
                # timed out waiting for any to complete - we'll fall back to marking failed
                pass
    except Exception:
        # if threadpool creation fails for any reason, do synchronous fallback
        for ip in candidates:
            if try_status_at(ip, timeout=HTTP_TIMEOUT_FAST):
                found_ip = ip
                break

    if found_ip:
        st.session_state.backend_discovery_failed = False
        return found_ip

    # Nothing found: mark discovery as failed (so UI can show "service not available")
    st.session_state.backend_discovery_failed = True
    return None

# ======================================================
# INIT SESSION STATE (unchanged app state keys + new flags)
# ======================================================

if "backend_ip" not in st.session_state:
    st.session_state.backend_ip = None
if "backend_fail_count" not in st.session_state:
    # small failure counter so we don't clear backend_ip on single transient failure
    st.session_state.backend_fail_count = 0
# new discovery-failed flag (False until a discovery run fails)
if "backend_discovery_failed" not in st.session_state:
    st.session_state.backend_discovery_failed = False

# NEW: track whether backend was reachable in previous successful run
if "backend_was_reachable" not in st.session_state:
    st.session_state.backend_was_reachable = False

if "gps_last_update" not in st.session_state:
    st.session_state.gps_last_update = None

if "heading" not in st.session_state:
    st.session_state.heading = None

if "last_verified" not in st.session_state:
    st.session_state.last_verified = 0
    st.session_state.last_blocked = 0
    st.session_state.last_time = time.time()

if "flight_path" not in st.session_state:
    st.session_state.flight_path = []

if "threat_timeline" not in st.session_state:
    st.session_state.threat_timeline = deque(maxlen=50)

# new: track last known usb state to avoid repeated timeline messages
if "last_usb_present" not in st.session_state:
    st.session_state.last_usb_present = None

# new: track last fail-safe state so we only append timeline on transitions
if "last_fail_safe_active" not in st.session_state:
    st.session_state.last_fail_safe_active = False

# ======================================================
# TRY DISCOVERY (run once per session or when lost)
# ======================================================

# If we don't have a backend IP cached, attempt discovery now.
if st.session_state.backend_ip is None:
    with st.spinner("🔍 Searching for AirLock backend (fast)..."):
        found = discover_airlock_backend()
        st.session_state.backend_ip = found
        # reset fail counter
        st.session_state.backend_fail_count = 0

# ======================================================
# HELPERS (use discovered backend IP)
# ======================================================

def fetch_status():
    """
    Fetch /status from discovered backend.
    If a request fails several times in a row, clear backend_ip to force rediscovery.
    This avoids flapping on single transient failures.
    """
    ip = st.session_state.get("backend_ip")
    if not ip:
        return None
    url = f"http://{ip}:{AIRLOCK_PORT}/status"
    try:
        r = _session.get(url, timeout=1.0)
        if r.status_code == 200:
            # SUCCESS: mark backend reachable
            st.session_state.backend_fail_count = 0
            st.session_state.backend_was_reachable = True
            st.session_state.backend_discovery_failed = False
            return r.json()
        else:
            # treat non-200 as a transient failure
            st.session_state.backend_fail_count += 1
    except Exception:
        st.session_state.backend_fail_count += 1

    # if consecutive fails >= 2, drop and force rediscovery next run
    if st.session_state.backend_fail_count >= 2:
        # If backend WAS reachable and now we cleared backend_ip, the UI should show service-not-available.
        st.session_state.backend_ip = None
        st.session_state.backend_fail_count = 0
    return None

def fetch_gps():
    """
    Fetch /telemetry from discovered backend; if repeated failures occur, clear backend_ip.
    """
    ip = st.session_state.get("backend_ip")
    if not ip:
        return None
    url = f"http://{ip}:{AIRLOCK_PORT}/telemetry"
    try:
        r = _session.get(url, timeout=0.6)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "lat" in data and "lon" in data:
            # success; reset fail counter and mark reachable
            st.session_state.backend_fail_count = 0
            st.session_state.backend_was_reachable = True
            lat = float(data["lat"])
            lon = float(data["lon"])
            heading = data.get("heading")
            heading = float(heading) if heading is not None else None
            return lat, lon, heading
    except Exception:
        st.session_state.backend_fail_count += 1

    if st.session_state.backend_fail_count >= 2:
        st.session_state.backend_ip = None
        st.session_state.backend_fail_count = 0
    return None

# ======================================================
# AIRLOCK STATUS + RATES (UI logic with small state-change checks)
# ======================================================

status = fetch_status()

fail_safe_active = False
fail_safe_reason = "none"

verified_rate = 0.0
blocked_rate = 0.0
gps_available = False

if status:
    now = time.time()
    dt = max(now - st.session_state.last_time, 1e-6)

    dv = status["verified_packets"] - st.session_state.last_verified
    db = status["blocked_packets"] - st.session_state.last_blocked

    verified_rate = dv / dt
    blocked_rate = db / dt

    st.session_state.last_verified = status["verified_packets"]
    st.session_state.last_blocked = status["blocked_packets"]
    st.session_state.last_time = now

    # ---------------- FAIL-SAFE LOGIC ----------------

    if not status["usb_present"]:
        fail_safe_active = True
        fail_safe_reason = "AirLock USB removed"

    elif blocked_rate > FAILSAFE_BLOCK_RATE_THRESHOLD:
        fail_safe_active = True
        fail_safe_reason = "High blocked packet rate detected"

    elif status["last_block_reason"] not in ("none", "", None):
        fail_safe_active = True
        fail_safe_reason = f"Security anomaly: {status['last_block_reason']}"

    # ---------------- Threat timeline: only append on state changes ----------------
    current_time = time.strftime('%H:%M:%S')

    # USB insert/remove change detection: append *only once* on transition
    usb_present = bool(status["usb_present"])
    last_usb = st.session_state.last_usb_present
    if last_usb is None:
        # first time we learn state — set it but do NOT spam the timeline
        st.session_state.last_usb_present = usb_present
    elif usb_present != last_usb:
        if not usb_present:
            st.session_state.threat_timeline.appendleft(f"{current_time} — USB removed")
        else:
            st.session_state.threat_timeline.appendleft(f"{current_time} — USB connected")
        st.session_state.last_usb_present = usb_present

    # Fail-safe transition detection: append only when fail-safe toggles
    last_fs = st.session_state.last_fail_safe_active
    if fail_safe_active and not last_fs:
        st.session_state.threat_timeline.appendleft(f"{current_time} — FAIL-SAFE: {fail_safe_reason}")
    elif not fail_safe_active and last_fs:
        st.session_state.threat_timeline.appendleft(f"{current_time} — FAIL-SAFE CLEARED")
    # update last flag
    st.session_state.last_fail_safe_active = fail_safe_active

    # If blocked packets are detected, append blocked message once per change (use blocked count comparison)
    if db > 0:
        # if last_blocked count changed (we kept last_blocked updated above), adding a message is still useful.
        st.session_state.threat_timeline.appendleft(f"{current_time} — BLOCKED packets detected ({db})")

    # ---------------- UI METRICS ----------------

    c1, c2, c3 = st.columns(3)
    c1.metric("Security Status", "ON 🟢" if status["usb_present"] else "OFF 🔴")
    c2.metric("Verified Packets", status["verified_packets"], f"{verified_rate:.2f} / sec")
    c3.metric("Blocked Packets", status["blocked_packets"], f"{blocked_rate:.2f} / sec")

    st.divider()
    st.subheader("Last Block Reason")
    st.info(status["last_block_reason"])

else:
    # If discovery explicitly failed, show service not available error (instead of generic connecting)
    # NEW: also show "service not available" if backend WAS reachable previously (Ctrl+C)
    is_service_unavailable = st.session_state.backend_discovery_failed or (st.session_state.backend_was_reachable and st.session_state.backend_ip is None)
    if is_service_unavailable:
        # show only the service-unavailable banner
        st.error("❌ AirLock service not available (backend not found).")

        # reset the 'was_reachable' marker so message isn't permanent once backend comes back
        st.session_state.backend_was_reachable = False

        # Wait the selected refresh interval and then cause the app to rerun so discovery runs again.
        # This effectively performs background re-discovery in successive reruns without rendering the rest of the UI.
        time.sleep(refresh)
        # Clear backend_ip so discovery runs again at the top of the script
        st.session_state.backend_ip = None
        # Trigger a rerun to attempt discovery again immediately
        st.rerun()
    else:
        # graceful message while trying to discover / connect
        st.warning("🔄 Connecting to AirLock backend...")

# ======================================================
# FAIL-SAFE BANNER (unchanged)
# ======================================================

st.divider()

if fail_safe_active:
    st.error(
        f"🔴 FAIL-SAFE ACTIVE — COMMANDS SHOULD BE BLOCKED\n\n"
        f"Reason: {fail_safe_reason}"
    )
else:
    st.success("🟢 SYSTEM NORMAL — Commands Allowed")

# ======================================================
# SYSTEM STATE PANEL (unchanged)
# ======================================================

st.divider()
st.subheader("🧭 System State Panel")

s1, s2, s3, s4, s5 = st.columns(5)

s1.metric("AirLock USB", "CONNECTED" if status and status["usb_present"] else "REMOVED")
s2.metric("Security Mode", "FAIL-SAFE" if fail_safe_active else "NORMAL")
s3.metric("GPS State", "LOCKED" if gps_available else "WAITING")
s4.metric(
    "Telemetry",
    "LIVE" if st.session_state.gps_last_update and (time.time() - st.session_state.gps_last_update) < 3 else "TIMEOUT"
)
s5.metric(
    "Command Exec",
    "BLOCKED" if fail_safe_active else "ENABLED"
)

# ======================================================
# THREAT TIMELINE (unchanged rendering)
# ======================================================

st.divider()
st.subheader("🚨 Threat Timeline")

if st.session_state.threat_timeline:
    for event in list(st.session_state.threat_timeline):
        st.warning(event)
else:
    st.info("No security threats detected yet.")

# ================= ADDITION: FLIGHT PATH UTILITIES (unchanged)
# ======================================================

def haversine(lat1, lon1, lat2, lon2):
    R = 6371000  # meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = math.sin(dphi/2)**2 + \
        math.cos(phi1) * math.cos(phi2) * math.sin(dlambda/2)**2
    return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def calculate_path_distance(path):
    if len(path) < 2:
        return 0.0
    total = 0.0
    for i in range(1, len(path)):
        lat1, lon1 = path[i-1]
        lat2, lon2 = path[i]
        total += haversine(lat1, lon1, lat2, lon2)
    return total

# ================= ADDITION: FLIGHT PATH PANEL (unchanged)
# ======================================================

st.divider()
st.subheader("🧵 Flight Path Monitor")

fp_col1, fp_col2, fp_col3 = st.columns(3)

path_points = len(st.session_state.flight_path)
path_distance_m = calculate_path_distance(st.session_state.flight_path)

fp_col1.metric("Path Points", path_points)
fp_col2.metric("Distance Traveled", f"{path_distance_m:.1f} m")
fp_col3.metric(
    "Path State",
    "PAUSED (Fail-Safe)" if fail_safe_active else "ACTIVE"
)

# Manual clear (visual only)
if st.button("🧹 Clear Flight Path (UI Only)"):
    st.session_state.flight_path.clear()
    st.success("Flight path cleared (telemetry unaffected).")
    
# ======================================================
# RADAR + MAP SECTION (unchanged logic & visuals)
# ======================================================

st.divider()
radar_col, map_col = st.columns([1.1, 1.7], gap="large")

# ---------------------- RADAR -------------------------

with radar_col:
    st.subheader("📡 Live Drone Radar")

    RADAR_SIZE = 420
    CENTER = RADAR_SIZE // 2
    RADIUS = CENTER - 12
    RADAR_RANGE_M = 1000.0

    gps = fetch_gps()

    if gps:
        lat, lon, heading = gps
        st.session_state.gps_last_update = time.time()
        st.session_state.heading = heading

        if "home_lat" not in st.session_state:
            st.session_state.home_lat = lat
            st.session_state.home_lon = lon

        st.session_state.last_lat = lat
        st.session_state.last_lon = lon
        gps_available = True

        # 🔽 ADD REAL GPS POINT TO FLIGHT PATH (ONLY IF NOT FAIL-SAFE)
        if not fail_safe_active:
            if not st.session_state.flight_path or \
               st.session_state.flight_path[-1] != (lat, lon):
                st.session_state.flight_path.append((lat, lon))

    else:
        gps_available = False

    drone_left_style = ""
    drone_top_style = ""
    drone_opacity = 0.25

    if gps_available:
        lat0 = st.session_state.home_lat
        lon0 = st.session_state.home_lon
        lat1 = st.session_state.last_lat
        lon1 = st.session_state.last_lon

        meters_per_deg_lat = 111320.0
        meters_per_deg_lon = 111320.0 * math.cos(math.radians(lat0))

        dx_m = (lon1 - lon0) * meters_per_deg_lon
        dy_m = (lat1 - lat0) * meters_per_deg_lat

        px_x = (dx_m / RADAR_RANGE_M) * RADIUS
        px_y = (dy_m / RADAR_RANGE_M) * RADIUS

        dist_px = math.hypot(px_x, px_y)
        if dist_px > RADIUS:
            scale = RADIUS / dist_px
            px_x *= scale
            px_y *= scale

        x = CENTER + px_x
        y = CENTER - px_y

        drone_left_style = f"left: {x}px;"
        drone_top_style = f"top: {y}px;"
        drone_opacity = 1.0

    heading_deg = st.session_state.heading if st.session_state.heading is not None else 0
    heading_display = "block" if st.session_state.heading is not None else "none"

    radar_html = f"""
    <style>
    @keyframes rotateRadar {{
      from {{ transform: rotate(0deg); }}
      to {{ transform: rotate(360deg); }}
    }}
    .radar-container {{
      width:{RADAR_SIZE}px;height:{RADAR_SIZE}px;
      border-radius:50%;background:#001a0f;
      border:3px solid #00ff99;position:relative;margin:auto;
    }}
    .radar-sweep {{
      position:absolute;width:50%;height:4px;
      background:linear-gradient(to right, rgba(0,229,168,0.95), transparent);
      top:50%;left:50%;transform-origin:left center;
      animation:rotateRadar 2s linear infinite;
    }}
    .drone-dot {{
      position:absolute;width:12px;height:12px;
      background:#00ff99;border-radius:50%;
      transform:translate(-50%,-50%);
      opacity:{drone_opacity};
      {drone_left_style}{drone_top_style}
    }}
    .heading-arrow {{
      position:absolute;width:26px;height:3px;
      background:#ffffff;top:50%;left:50%;
      transform-origin:left center;
      transform:translate(-50%, -50%) rotate({heading_deg}deg);
      display:{heading_display};
    }}
    </style>
    <div class="radar-container">
      <div class="radar-sweep"></div>
      <div class="heading-arrow"></div>
      <div class="drone-dot"></div>
    </div>
    """

    st.markdown(radar_html, unsafe_allow_html=True)

# ---------------------- MAP ---------------------------

with map_col:
    st.subheader("🗺️ Live Drone Map")

    if "last_lat" in st.session_state and "last_lon" in st.session_state:
        lat = st.session_state.last_lat
        lon = st.session_state.last_lon
        gps_available = True
    else:
        lat, lon = 0.0, 0.0
        gps_available = False

    zoom = 16 if gps_available else 2

    drone_map = folium.Map(
        location=[lat, lon],
        zoom_start=zoom,
        tiles="https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
        attr="Esri World Imagery",
        control_scale=True
    )

    # 🔽 DRAW FLIGHT PATH TRAIL (REAL DATA ONLY)
    if len(st.session_state.flight_path) >= 2:
        folium.PolyLine(
            st.session_state.flight_path,
            color="#00E5A8",
            weight=3,
            opacity=0.85
        ).add_to(drone_map)

    folium.Marker(
        [lat, lon],
        tooltip="Drone Location" if gps_available else "Waiting for GPS fix",
        icon=folium.Icon(color="green" if gps_available else "gray", icon="send")
    ).add_to(drone_map)

    # Added stable key to prevent re-mount flashing, everything else unchanged
    st_folium(drone_map, width=720, height=460, key="airlock_drone_map")

# ======================================================
# GPS STATUS (unchanged)
# ======================================================

st.divider()

if gps_available:
    st.success("🛰️ GPS LOCK ACQUIRED — Live telemetry active")
    if st.session_state.gps_last_update:
        st.caption(
            f"Last GPS update: {time.strftime('%H:%M:%S', time.localtime(st.session_state.gps_last_update))}"
        )
    if st.session_state.heading is not None:
        st.caption(f"Heading: {st.session_state.heading:.1f}°")
else:
    st.warning("🟡 Waiting for GPS fix from drone / simulator")

# ======================================================
# AUTO REFRESH (unchanged)
# ======================================================

from streamlit_autorefresh import st_autorefresh
st_autorefresh(interval=refresh * 1000, key="airlock_refresh")