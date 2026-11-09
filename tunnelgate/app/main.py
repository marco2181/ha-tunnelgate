#!/usr/bin/env python3
"""TunnelGate add-on for Home Assistant OS.

Routes only the configured LAN clients (e.g. a TV that uses this host as its
IPv4 gateway) through a WireGuard (NordLynx) tunnel of a NordVPN subscription.
Exposes an ingress web panel and MQTT-discovered entities to switch the VPN
on/off and pick the location. Unofficial, not affiliated with Nord Security.

Modes
  ON : client traffic -> wg tunnel (MASQUERADE). Kill switch: if the tunnel is
       down the client has no internet. Client DNS (port 53, any server) is
       redirected to a local proxy that resolves through the tunnel and hides
       AAAA/HTTPS records, so the client prefers IPv4 (= the tunnel). This only
       works if the client has no IPv6 DNS of its own (configure it with a
       static IPv4 setup and IPv4 DNS servers).
  OFF: client traffic is forwarded to the normal LAN gateway (MASQUERADE).

On stop the add-on removes all its rules: the clients go back to direct
internet access (fail open).
"""
import base64
import hashlib
import http.client
import http.server
import ipaddress
import json
import logging
import os
import random
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tunnelgate")

OPTIONS_FILE = "/data/options.json"
STATE_FILE = "/data/state.json"
SERVERS_FILE = "/data/servers.json"
KEY_FILE = "/data/nordlynx.json"
OLD_KEY_FILE = "/data/nordlynx.key"

WG_IF = "tgate0"
WG_ADDR = "10.5.0.2"
WG_PORT = 51820
WG_MTU = 1420
TABLE = 51820
RULE_PRIO_LAN = 5000
RULE_PRIO_CLIENT = 5001
RULE_PRIO_SELF = 5002
NORD_DNS = ["103.86.96.100", "103.86.99.100"]
DNS_PORT = 5354
WEB_PORT = 8099
INGRESS_IP = "172.30.32.2"
SERVERS_MAX_AGE = 12 * 3600
SERVERS_RETRY = 600
HANDSHAKE_TIMEOUT = 300
API = "https://api.nordvpn.com"
SERVER_FIELDS = ["hostname", "station", "load", "status", "locations.country.code",
                 "locations.country.name", "locations.country.city.name",
                 "locations.latitude", "locations.longitude",
                 "technologies.identifier", "technologies.metadata"]

FILTER_CHAINS = (("filter", "TGATE_FWD", "FORWARD"), ("filter", "TGATE_OUT", "OUTPUT"),
                 ("filter", "TGATE_IN", "INPUT"),
                 ("nat", "TGATE_POST", "POSTROUTING"), ("nat", "TGATE_PRE", "PREROUTING"),
                 ("mangle", "TGATE_MSS", "FORWARD"))

OPTS = json.load(open(OPTIONS_FILE))
TOKEN = (OPTS.get("token") or "").strip()
KILL_ON_STOP = bool(OPTS.get("kill_switch_on_stop", False))
LAN_IF = OPTS.get("lan_interface") or "eth0"
CLIENTS = []
for _c in OPTS.get("clients", []):
    try:
        CLIENTS.append(str(ipaddress.IPv4Address(_c.strip())))
    except ValueError:
        log.error("Client ignored, not a valid IPv4 address: %r", _c)
BLOCKED_DOMAINS = {_d.strip().strip(".").lower() for _d in OPTS.get("blocked_domains") or []}
BLOCKED_DOMAINS.discard("")

lock = threading.RLock()
runtime = {"status": "disconnected", "server": None, "city": None, "country": None,
           "ip": None, "error": None, "since": None, "load": None}
state = {"enabled": False, "country": "US", "city": "", "favorites": []}
servers = []
servers_lock = threading.Lock()
servers_last_try = 0.0
last_server = None
mqtt_client = None
stopping = False
IPT = None
LAN_NET = None


# --------------------------------------------------------------------------- utils
def run(cmd, check=True):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr.strip() or p.stdout.strip()}")
    return p.stdout


def ok(cmd):
    return subprocess.run(cmd, capture_output=True).returncode == 0


def http_json(url, headers=None, src=None, timeout=30):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(u.hostname, timeout=timeout,
                                       source_address=(src, 0) if src else None,
                                       context=ssl.create_default_context())
    try:
        path = u.path + ("?" + u.query if u.query else "")
        conn.request("GET", path, headers={"User-Agent": "ha-tunnelgate", **(headers or {})})
        r = conn.getresponse()
        body = r.read()
    finally:
        conn.close()
    if r.status != 200:
        raise RuntimeError(f"HTTP {r.status} from {u.hostname}{u.path}")
    return json.loads(body)


def save_state():
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def detect_lan_if(wanted):
    if wanted and os.path.exists(f"/sys/class/net/{wanted}"):
        return wanted
    out = run(["ip", "-4", "route", "show", "default", "table", "main"])
    for line in out.splitlines():
        parts = line.split()
        if "dev" in parts:
            dev = parts[parts.index("dev") + 1]
            log.info("Interface '%s' not found, using '%s' (default route)", wanted, dev)
            return dev
    raise RuntimeError("no default route")


def lan_network():
    out = run(["ip", "-4", "-o", "addr", "show", "dev", LAN_IF]).split()
    if len(out) < 4:
        raise RuntimeError(f"no IPv4 address on {LAN_IF}")
    return str(ipaddress.ip_interface(out[3]).network)


# --------------------------------------------------------------------------- nord api
def get_private_key(force=False):
    token_sha = hashlib.sha256(TOKEN.encode()).hexdigest()
    if not force:
        try:
            d = json.load(open(KEY_FILE))
            if d.get("token_sha") == token_sha and d.get("key"):
                return d["key"]
        except (OSError, ValueError):
            pass
    if not TOKEN:
        raise RuntimeError("Access token missing in the add-on configuration")
    auth = base64.b64encode(f"token:{TOKEN}".encode()).decode()
    try:
        data = http_json(API + "/v1/users/services/credentials",
                         {"Authorization": "Basic " + auth})
    except RuntimeError as e:
        if "HTTP 401" in str(e) or "HTTP 403" in str(e):
            raise RuntimeError("Access token invalid or expired: generate a new one") from e
        raise
    key = data.get("nordlynx_private_key")
    if not key:
        raise RuntimeError("The NordVPN API response does not contain the NordLynx key")
    with open(KEY_FILE, "w") as f:
        json.dump({"token_sha": token_sha, "key": key}, f)
    os.chmod(KEY_FILE, 0o600)
    if os.path.exists(OLD_KEY_FILE):
        os.remove(OLD_KEY_FILE)
    log.info("NordLynx key obtained from the NordVPN API")
    return key


def _load_cached_servers():
    global servers
    with open(SERVERS_FILE) as f:
        servers = json.load(f)


def refresh_servers(force=False):
    """Download the server list if stale; fall back to the cached copy on errors."""
    global servers, servers_last_try
    with servers_lock:
        fresh = os.path.exists(SERVERS_FILE) and \
            time.time() - os.path.getmtime(SERVERS_FILE) < SERVERS_MAX_AGE
        if not servers and os.path.exists(SERVERS_FILE):
            try:
                _load_cached_servers()
            except (OSError, ValueError):
                pass
        if servers and "lat" not in servers[0]:
            fresh = False  # cache from an older version without coordinates
            force = True
        if servers and (fresh or (not force and time.time() - servers_last_try < SERVERS_RETRY)):
            return
        servers_last_try = time.time()
        log.info("Downloading the server list...")
        params = [("limit", "20000"),
                  ("filters[servers_technologies][identifier]", "wireguard_udp")]
        params += [(f"fields[servers.{f}]", "") for f in SERVER_FIELDS]
        try:
            raw = http_json(f"{API}/v1/servers?{urllib.parse.urlencode(params)}", timeout=120)
        except Exception as e:
            if servers:
                log.warning("Server list not refreshed (%s): using the cached copy", e)
                return
            raise
        out = [c for c in (compact(s) for s in raw) if c]
        del raw
        if not out:
            if servers:
                log.warning("Empty server list: using the cached copy")
                return
            raise RuntimeError("Empty server list")
        servers = out
        tmp = SERVERS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(out, f)
        os.replace(tmp, SERVERS_FILE)
        log.info("WireGuard servers available: %d", len(out))


def locations():
    countries = {}
    for s in servers:
        c = countries.setdefault(s["cc"], {"code": s["cc"], "name": s["cn"], "cities": {},
                                           "servers": 0})
        c["servers"] += 1
        if s["city"] and s["city"] not in c["cities"]:
            c["cities"][s["city"]] = [s.get("lat"), s.get("lon")]
    return [{"code": c["code"], "name": c["name"], "servers": c["servers"],
             "cities": sorted(c["cities"]), "coords": c["cities"]}
            for c in sorted(countries.values(), key=lambda x: x["name"])]


def country_name(code):
    for s in servers:
        if s["cc"] == code:
            return s["cn"]
    return code


def country_code(value):
    """Accept a code ('US') or a name ('United States'); None if unknown."""
    if not value:
        return None
    v = value.strip()
    for s in servers:
        if s["cc"].upper() == v.upper() or s["cn"].lower() == v.lower():
            return s["cc"]
    return v.upper() if not servers and len(v) == 2 else None


def compact(s):
    """NordVPN API server object -> compact dict, or None if no WireGuard key."""
    if s.get("status", "online") != "online" or not s.get("locations"):
        return None
    pub = None
    for t in s.get("technologies", []):
        if t.get("identifier") == "wireguard_udp":
            for m in t.get("metadata", []):
                if m.get("name") == "public_key":
                    pub = m.get("value")
    if not pub:
        return None
    loc = s["locations"][0]
    c = loc["country"]
    return {"h": s["hostname"], "ip": s["station"], "l": s.get("load", 100),
            "cc": c["code"], "cn": c["name"],
            "city": (c.get("city") or {}).get("name", ""), "pk": pub,
            "lat": loc.get("latitude"), "lon": loc.get("longitude")}


_country_ids = {}


def recommended(country, city):
    """Servers NordVPN itself recommends (what the official apps use)."""
    if not _country_ids:
        for c in http_json(API + "/v1/servers/countries", timeout=30):
            _country_ids[c["code"]] = (c["id"], {x["name"]: x["id"] for x in c.get("cities", [])})
    cid, cities = _country_ids.get(country, (None, {}))
    if cid is None:
        return []
    params = [("filters[servers_technologies][identifier]", "wireguard_udp"), ("limit", "10")]
    if city and city in cities:
        params.append(("filters[country_city_id]", str(cities[city])))
    else:
        params.append(("filters[country_id]", str(cid)))
    raw = http_json(f"{API}/v1/servers/recommendations?{urllib.parse.urlencode(params)}",
                    timeout=20)
    return [c for c in (compact(s) for s in raw) if c and (not city or c["city"] == city)]


def candidates(country, city, exclude=()):
    """Ordered list of servers to try: NordVPN recommendations first, then the cached list."""
    out = []
    try:
        out = [s for s in recommended(country, city) if s["h"] not in exclude]
    except Exception as e:
        log.warning("Recommended servers unavailable (%s): using the cached list", e)
    if not out:
        cand = [s for s in servers if s["cc"] == country and (not city or s["city"] == city)
                and s["h"] not in exclude]
        # almost empty servers (load < 5%) are often not in service yet: try them last
        cand.sort(key=lambda s: (s["l"] < 5, s["l"]))
        out = cand[:3]
        random.shuffle(out)
    if not out:
        raise RuntimeError(f"No server available for {country} {city or ''}".strip())
    return out


# --------------------------------------------------------------------------- netfilter
def detect_iptables():
    for cmd in ("iptables-nft", "iptables-legacy"):
        try:
            if "DOCKER" in run([cmd, "-S"], check=False):
                return cmd
        except FileNotFoundError:
            pass
    return "iptables"


def ipt(*args, check=True):
    return run([IPT, *args], check=check)


def ensure_chain(table, chain, parent):
    ipt("-t", table, "-N", chain, check=False)
    if not ok([IPT, "-t", table, "-C", parent, "-j", chain]):
        ipt("-t", table, "-I", parent, "1", "-j", chain)


def remove_chain(table, chain, parent):
    while ok([IPT, "-t", table, "-D", parent, "-j", chain]):
        pass
    ipt("-t", table, "-F", chain, check=False)
    ipt("-t", table, "-X", chain, check=False)


def ip_rules_clear():
    for prio in (RULE_PRIO_LAN, RULE_PRIO_CLIENT, RULE_PRIO_SELF):
        while ok(["ip", "rule", "del", "priority", str(prio)]):
            pass


def rules_ok(vpn_on):
    if not CLIENTS:
        return True
    for table, chain, parent in FILTER_CHAINS:
        if not ok([IPT, "-t", table, "-C", parent, "-j", chain]):
            return False
    if len(ipt("-t", "filter", "-S", "TGATE_FWD", check=False).splitlines()) <= 1:
        return False
    if vpn_on and f"lookup {TABLE}" not in run(["ip", "rule", "show", "priority",
                                                str(RULE_PRIO_CLIENT)], check=False):
        return False
    if vpn_on and "blackhole" not in run(["ip", "route", "show", "table", str(TABLE)],
                                         check=False):
        return False  # kill-switch fallback route lost
    return True


def read_sysctl(key):
    try:
        return open("/proc/sys/" + key.replace(".", "/")).read().strip()
    except OSError:
        return None


def flush_conntrack():
    """Existing flows keep their old NAT after a mode switch: drop them."""
    for c in CLIENTS:
        for flag in ("-s", "-d"):
            subprocess.run(["conntrack", "-D", flag, c], capture_output=True)


def apply_rules(vpn_on):
    if read_sysctl("net.ipv4.ip_forward") == "0":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        except OSError:
            log.error("ip_forward is 0 and cannot be changed: disable Protection mode")

    for table, chain, parent in FILTER_CHAINS:
        ensure_chain(table, chain, parent)
        ipt("-t", table, "-F", chain)

    # the DNS proxy answers only the managed clients (not an open resolver for the LAN)
    for c in CLIENTS:
        for proto in ("udp", "tcp"):
            ipt("-A", "TGATE_IN", "-s", c, "-p", proto, "--dport", str(DNS_PORT),
                "-j", "ACCEPT")
    for proto in ("udp", "tcp"):
        ipt("-A", "TGATE_IN", "-p", proto, "--dport", str(DNS_PORT), "!", "-s", "127.0.0.1",
            "-j", "DROP")

    for c in CLIENTS:
        # never tell clients to bypass us (replaces send_redirects=0)
        ipt("-A", "TGATE_OUT", "-d", c, "-p", "icmp", "--icmp-type", "redirect", "-j", "DROP")
        # return traffic
        ipt("-A", "TGATE_FWD", "-d", c, "-m", "conntrack", "--ctstate",
            "RELATED,ESTABLISHED", "-j", "ACCEPT")
        # LAN <-> LAN hairpin
        ipt("-A", "TGATE_FWD", "-s", c, "-d", LAN_NET, "-j", "ACCEPT")
        if vpn_on:
            # DNS over TLS would bypass the AAAA filter: force plain DNS
            for proto in ("tcp", "udp"):
                ipt("-A", "TGATE_FWD", "-s", c, "-p", proto, "--dport", "853",
                    "-j", "REJECT")
            ipt("-A", "TGATE_FWD", "-s", c, "-o", WG_IF, "-j", "ACCEPT")
            ipt("-A", "TGATE_FWD", "-s", c, "-j", "DROP")  # kill switch
            ipt("-t", "nat", "-A", "TGATE_POST", "-s", c, "-o", WG_IF, "-j", "MASQUERADE")
            for proto in ("udp", "tcp"):
                ipt("-t", "nat", "-A", "TGATE_PRE", "-s", c, "-p", proto, "--dport", "53",
                    "-j", "REDIRECT", "--to-ports", str(DNS_PORT))
        else:
            ipt("-A", "TGATE_FWD", "-s", c, "-o", LAN_IF, "-j", "ACCEPT")
            ipt("-t", "nat", "-A", "TGATE_POST", "-s", c, "-o", LAN_IF, "!", "-d", LAN_NET,
                "-j", "MASQUERADE")
    # tunnel MTU is 1420: clamp TCP MSS so big packets are never lost
    for d in ("-o", "-i"):
        ipt("-t", "mangle", "-A", "TGATE_MSS", d, WG_IF, "-p", "tcp", "--tcp-flags",
            "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")

    ip_rules_clear()
    run(["ip", "route", "replace", "blackhole", "default", "metric", "4000",
         "table", str(TABLE)])
    run(["ip", "rule", "add", "priority", str(RULE_PRIO_SELF), "from", WG_ADDR,
         "lookup", str(TABLE)])
    if vpn_on:
        for c in CLIENTS:
            run(["ip", "rule", "add", "priority", str(RULE_PRIO_LAN), "from", c,
                 "to", LAN_NET, "lookup", "main"])
            run(["ip", "rule", "add", "priority", str(RULE_PRIO_CLIENT), "from", c,
                 "lookup", str(TABLE)])
    run(["ip", "route", "flush", "cache"], check=False)


def stop_fail_closed():
    """Option kill_switch_on_stop: keep clients blocked while the add-on is stopped."""
    wg_down()
    remove_chain("nat", "TGATE_PRE", "PREROUTING")  # no DNS redirect to a dead port
    remove_chain("filter", "TGATE_IN", "INPUT")
    ensure_chain("filter", "TGATE_FWD", "FORWARD")
    ipt("-F", "TGATE_FWD")
    for c in CLIENTS:
        ipt("-A", "TGATE_FWD", "-s", c, "-d", LAN_NET, "-j", "ACCEPT")
        ipt("-A", "TGATE_FWD", "-s", c, "-j", "DROP")
    flush_conntrack()


def stop_fail_open():
    """Default on stop: tunnel down, but keep forwarding the clients to the LAN gateway.

    The clients still use this host as their gateway, and Docker's FORWARD policy is
    DROP, so removing every rule would leave them with no internet at all.
    """
    wg_down()
    apply_rules(False)
    ip_rules_clear()
    flush_conntrack()


def cleanup_all():
    """Remove everything (not used on a normal stop: see stop_fail_open)."""
    for table, chain, parent in FILTER_CHAINS:
        while ok([IPT, "-t", table, "-D", parent, "-j", chain]):
            pass
    ip_rules_clear()
    wg_down()
    for table, chain, parent in FILTER_CHAINS:
        remove_chain(table, chain, parent)
    run(["ip", "route", "flush", "table", str(TABLE)], check=False)
    flush_conntrack()


# --------------------------------------------------------------------------- wireguard
def wg_down():
    run(["ip", "link", "del", WG_IF], check=False)


def wg_up(server, key):
    wg_down()
    p = subprocess.run(["ip", "link", "add", WG_IF, "type", "wireguard"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        log.warning("Kernel WireGuard not available (%s), using wireguard-go",
                    p.stderr.strip())
        subprocess.Popen(["wireguard-go", WG_IF])
        for _ in range(20):
            if os.path.exists(f"/sys/class/net/{WG_IF}"):
                break
            time.sleep(0.25)
    keyfile = "/tmp/wg.key"
    with open(keyfile, "w") as f:
        f.write(key)
    os.chmod(keyfile, 0o600)
    try:
        run(["wg", "set", WG_IF, "private-key", keyfile, "peer", server["pk"],
             "endpoint", f"{server['ip']}:{WG_PORT}", "allowed-ips", "0.0.0.0/0",
             "persistent-keepalive", "25"])
    finally:
        os.remove(keyfile)
    run(["ip", "addr", "add", f"{WG_ADDR}/32", "dev", WG_IF])
    run(["ip", "link", "set", WG_IF, "mtu", str(WG_MTU), "up"])
    run(["ip", "route", "replace", "default", "dev", WG_IF, "metric", "100",
         "table", str(TABLE)])


def wg_stats():
    """(latest handshake ts, rx bytes)"""
    hs, rx = 0, 0
    try:
        hs = int(run(["wg", "show", WG_IF, "latest-handshakes"], check=False).split()[1])
        rx = int(run(["wg", "show", WG_IF, "transfer"], check=False).split()[1])
    except (IndexError, ValueError):
        pass
    return hs, rx


def check_ip():
    try:
        d = http_json(API + "/v1/helpers/ips/insights", src=WG_ADDR, timeout=15)
        return d.get("ip")
    except Exception as e:
        log.warning("IP check failed: %s", e)
        return None


def try_server(srv, key):
    log.info("Connecting to %s (%s, %s, load %s%%)", srv["h"], srv["cn"], srv["city"], srv["l"])
    wg_up(srv, key)
    for i in range(20):
        if stopping or wg_stats()[0] > 0:
            break
        if i % 4 == 0:  # generate traffic so WireGuard starts the handshake
            subprocess.run(["ping", "-c", "1", "-W", "1", "-I", WG_IF, NORD_DNS[0]],
                           capture_output=True)
        time.sleep(0.5)
    if wg_stats()[0] > 0:
        return True
    xfer = [l.strip() for l in run(["wg", "show", WG_IF], check=False).splitlines()
            if "transfer" in l]
    log.warning("No handshake with %s (%s)", srv["h"], xfer[0] if xfer else "no traffic")
    return False


# --------------------------------------------------------------------------- control
def set_status(**kw):
    runtime.update(kw)
    publish_state()


def connect(exclude=()):
    """Bring the tunnel up for state['country'/'city']. Caller holds lock."""
    global last_server
    set_status(status="connecting", error=None, server=None, ip=None, city=None,
               country=None, load=None, lat=None, lon=None)
    try:
        apply_rules(True)  # kill switch first
        flush_conntrack()
        refresh_servers()
        key = get_private_key()
        tried = list(exclude)
        connected = None
        queue = candidates(state["country"], state["city"], tried)
        for attempt in range(3):
            if stopping:
                return
            queue = [s for s in queue if s["h"] not in tried] or \
                candidates(state["country"], state["city"], tried)
            srv = queue[0]
            tried.append(srv["h"])
            last_server = srv["h"]
            if try_server(srv, key):
                connected = srv
                break
            if attempt == 1:
                # two servers refused us: maybe the NordLynx key was rotated/revoked
                key = get_private_key(force=True)
        if not connected:
            raise RuntimeError("No server answered ("
                               + ", ".join(h for h in tried if h not in exclude) + ")")
        ip = check_ip()
        set_status(status="connected", server=connected["h"], city=connected["city"],
                   country=connected["cn"], load=connected["l"], ip=ip,
                   since=int(time.time()), lat=connected.get("lat"), lon=connected.get("lon"))
        log.info("Connected. Public IP: %s", ip)
    except Exception as e:
        log.error("Connection failed: %s", e)
        set_status(status="error", error=str(e), server=None, ip=None)


def disconnect():
    wg_down()
    try:
        apply_rules(False)
    except Exception as e:
        log.error("OFF rules not applied: %s", e)
    flush_conntrack()
    set_status(status="disconnected", server=None, ip=None, city=None, country=None,
               load=None, error=None, since=None, lat=None, lon=None)
    log.info("VPN off: clients go out directly through the LAN")


def request(enabled=None, country=None, city=None, source="?"):
    """Single entry point for every command (panel, MQTT). Idempotent."""
    with lock:
        if stopping:
            return
        changed_loc = False
        if country is not None:
            code = country_code(country)
            if not code:
                log.warning("Unknown country %r (requested by %s)", country, source)
                return
            if code != state["country"]:
                state["country"], state["city"] = code, ""
                changed_loc = True
        if city is not None and city != state["city"]:
            state["city"] = city
            changed_loc = True
        was_on = state["enabled"]
        if enabled is not None:
            state["enabled"] = bool(enabled)
        save_state()
        if changed_loc:
            publish_discovery_city()
        on = state["enabled"]
        if on and (changed_loc or not was_on or runtime["status"] not in
                   ("connected", "connecting")):
            log.info("VPN ON -> %s %s (requested by %s)", state["country"],
                     state["city"] or "(fastest)", source)
            connect()
        elif not on and (was_on or runtime["status"] != "disconnected"):
            log.info("VPN OFF (requested by %s)", source)
            disconnect()
        else:
            log.info("Request from %s had no effect: already in this state", source)
            publish_state()


def watchdog():
    while not stopping:
        time.sleep(20)
        try:
            with lock:
                if stopping:
                    return
                on = state["enabled"]
                if not rules_ok(on):
                    log.warning("Network rules missing (Docker restart?), restoring them")
                    apply_rules(on)
                if on:
                    hs = wg_stats()[0]
                    stale = hs == 0 or time.time() - hs > HANDSHAKE_TIMEOUT
                    if runtime["status"] != "connected" or stale:
                        log.warning("Tunnel not active, reconnecting...")
                        connect(exclude=(last_server,) if last_server else ())
            publish_state()
        except Exception as e:
            log.error("Watchdog: %s", e)


# --------------------------------------------------------------------------- dns proxy
def dns_question_end(q):
    i = 12
    while True:
        n = q[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:
            i += 2
            break
        i += n + 1
    return i + 4


dns_blocked_seen = set()


def dns_is_blocked(q):
    """True if the queried name is in blocked_domains or is a subdomain of one."""
    if not BLOCKED_DOMAINS:
        return False
    labels, i = [], 12
    while q[i] and not q[i] & 0xC0:
        labels.append(q[i + 1:i + 1 + q[i]].decode("ascii", "replace").lower())
        i += q[i] + 1
    if not any(".".join(labels[k:]) in BLOCKED_DOMAINS for k in range(len(labels))):
        return False
    name = ".".join(labels)
    if name not in dns_blocked_seen and len(dns_blocked_seen) < 1000:
        dns_blocked_seen.add(name)  # log each name once, these queries repeat a lot
        log.info("DNS blocked: %s", name)
    return True


# root-zone SOA (TTL/minimum 300 s) so clients can cache the NODATA answer
DNS_SOA = (b"\x00" + struct.pack(">HHIH", 6, 1, 300, 22) + b"\x00\x00"
           + struct.pack(">IIIII", 1, 3600, 600, 86400, 300))


def dns_reply(q, rcode):
    """NODATA (rcode 0, with SOA) or SERVFAIL (rcode 2) reply echoing the question."""
    qend = dns_question_end(q)
    rd = struct.unpack(">H", q[2:4])[0] & 0x0100
    ns = 1 if rcode == 0 else 0
    return (q[:2] + struct.pack(">HHHHH", 0x8080 | rd | rcode, 1, 0, ns, 0) + q[12:qend]
            + (DNS_SOA if ns else b""))


def tunnel_up():
    return runtime["status"] == "connected" and os.path.exists(f"/sys/class/net/{WG_IF}")


def dns_upstream_udp(q):
    for server in NORD_DNS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((WG_ADDR, 0))
            s.connect((server, 53))
            s.settimeout(2)
            s.send(q)
            r = s.recv(4096)
            if r[:2] == q[:2]:
                return r
        except OSError:
            continue
        finally:
            s.close()
    return None


def dns_upstream_tcp(q):
    for server in NORD_DNS:
        try:
            with socket.create_connection((server, 53), timeout=3,
                                          source_address=(WG_ADDR, 0)) as s:
                s.sendall(struct.pack(">H", len(q)) + q)
                n = struct.unpack(">H", recv_exact(s, 2))[0]
                return recv_exact(s, n)
        except (OSError, struct.error):
            continue
    return None


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


def dns_answer(q, tcp=False):
    if len(q) < 17:
        return None
    try:
        qend = dns_question_end(q)
        qtype = struct.unpack(">H", q[qend - 4:qend - 2])[0]
        blocked = dns_is_blocked(q)
    except (IndexError, struct.error):
        return None
    if qtype in (28, 65) or blocked:  # AAAA, HTTPS -> no IPv6 for clients in VPN
        return dns_reply(q, 0)
    if not tunnel_up():
        return dns_reply(q, 2)  # SERVFAIL: client retries later instead of hanging
    r = dns_upstream_tcp(q) if tcp else dns_upstream_udp(q)
    return r or dns_reply(q, 2)


class DnsUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            r = dns_answer(data)
            if r:
                sock.sendto(r, self.client_address)
        except Exception:
            pass


class DnsTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            n = struct.unpack(">H", recv_exact(self.request, 2))[0]
            r = dns_answer(recv_exact(self.request, n), tcp=True)
            if r:
                self.request.sendall(struct.pack(">H", len(r)) + r)
        except (OSError, struct.error):
            pass


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    sem = threading.BoundedSemaphore(64)

    def process_request(self, request, client_address):
        if not self.sem.acquire(blocking=False):
            return  # overloaded: drop (client will retry)
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.sem.release()


class TUDP(BoundedThreads, socketserver.UDPServer):
    allow_reuse_address = True


class TTCP(BoundedThreads, socketserver.TCPServer):
    allow_reuse_address = True


# --------------------------------------------------------------------------- mqtt
DEV = {"identifiers": ["tunnelgate"], "name": "TunnelGate",
       "manufacturer": "TunnelGate add-on", "model": "WireGuard gateway"}
BASE = "tunnelgate"
AVAIL = f"{BASE}/availability"
TEXTS = {
    "en": {"vpn": "VPN", "country": "Country", "city": "City", "status": "Status",
           "server": "Server", "ip": "Public IP", "location": "Location",
           "fastest": "Fastest", "connected": "Connected", "connecting": "Connecting...",
           "disconnected": "Disconnected", "error": "Error"},
    "it": {"vpn": "VPN", "country": "Paese", "city": "Città", "status": "Stato",
           "server": "Server", "ip": "IP pubblico", "location": "Posizione",
           "fastest": "Più veloce", "connected": "Connesso", "connecting": "Connessione...",
           "disconnected": "Disconnesso", "error": "Errore"},
}
LANG = (OPTS.get("language") or "en").strip().lower()
T = TEXTS.get(LANG, TEXTS["en"])
FASTEST = T["fastest"]
FASTEST_ALIASES = {t["fastest"] for t in TEXTS.values()}


def mqtt_pub(topic, payload, retain=True):
    c = mqtt_client
    if c:
        if not isinstance(payload, str):
            payload = json.dumps(payload)
        c.publish(topic, payload, retain=retain)


def publish_discovery():
    common = {"device": DEV, "availability_topic": AVAIL}
    mqtt_pub(f"homeassistant/switch/{BASE}/vpn/config", {
        **common, "name": T["vpn"], "unique_id": f"{BASE}_vpn", "icon": "mdi:shield-lock",
        "command_topic": f"{BASE}/vpn/set", "state_topic": f"{BASE}/vpn/state"})
    mqtt_pub(f"homeassistant/select/{BASE}/country/config", {
        **common, "name": T["country"], "unique_id": f"{BASE}_country", "icon": "mdi:earth",
        "command_topic": f"{BASE}/country/set", "state_topic": f"{BASE}/country/state",
        "options": [c["name"] for c in locations()] or [country_name(state["country"])]})
    publish_discovery_city()
    for key, name, icon in (("status", T["status"], "mdi:lan-connect"),
                            ("server", T["server"], "mdi:server-network"),
                            ("ip", T["ip"], "mdi:ip-network"),
                            ("location", T["location"], "mdi:map-marker")):
        mqtt_pub(f"homeassistant/sensor/{BASE}/{key}/config", {
            **common, "name": name, "unique_id": f"{BASE}_{key}", "icon": icon,
            "state_topic": f"{BASE}/{key}/state"})


def publish_discovery_city():
    cities = []
    for c in locations():
        if c["code"] == state["country"]:
            cities = c["cities"]
    mqtt_pub(f"homeassistant/select/{BASE}/city/config", {
        "device": DEV, "availability_topic": AVAIL, "name": T["city"],
        "unique_id": f"{BASE}_city", "icon": "mdi:city",
        "command_topic": f"{BASE}/city/set", "state_topic": f"{BASE}/city/state",
        "options": [FASTEST] + cities})


def publish_state():
    if not mqtt_client:
        return
    mqtt_pub(f"{BASE}/vpn/state", "ON" if state["enabled"] else "OFF")
    mqtt_pub(f"{BASE}/country/state", country_name(state["country"]))
    mqtt_pub(f"{BASE}/city/state", state["city"] or FASTEST)
    mqtt_pub(f"{BASE}/status/state", T.get(runtime["status"], runtime["status"]))
    mqtt_pub(f"{BASE}/server/state", runtime["server"] or "-")
    mqtt_pub(f"{BASE}/ip/state", runtime["ip"] or "-")
    loc = ", ".join(x for x in (runtime["city"], runtime["country"]) if x) or "-"
    mqtt_pub(f"{BASE}/location/state", loc)


def on_mqtt_message(client, userdata, msg):
    payload = msg.payload.decode(errors="ignore").strip()
    t = msg.topic
    if msg.retain:
        # a stale retained command would replay on every reconnect: drop and clear it
        if payload:
            log.info("Retained MQTT command ignored and cleared: %s=%s", t, payload)
            client.publish(t, b"", retain=True)
        return
    if not payload:
        return
    log.info("MQTT command: %s = %s", t, payload)
    kw = {"source": "MQTT"}
    if t == f"{BASE}/vpn/set":
        kw["enabled"] = payload.upper() == "ON"
    elif t == f"{BASE}/country/set":
        kw["country"] = payload
    elif t == f"{BASE}/city/set":
        kw["city"] = "" if payload in FASTEST_ALIASES else payload
    else:
        return
    threading.Thread(target=request, kwargs=kw, daemon=True).start()


def on_mqtt_connect(client, userdata, flags, rc, *args):
    failed = getattr(rc, "is_failure", None)
    if (failed if failed is not None else rc != 0):
        log.error("MQTT refused the connection: %s", rc)
        return
    log.info("MQTT connected")
    client.subscribe(f"{BASE}/+/set")
    client.publish(AVAIL, "online", retain=True)
    publish_discovery()
    publish_state()


def supervisor_token():
    for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
        try:  # s6-overlay v3 keeps the container env here
            return open(f"/run/s6/container_environment/{name}").read().strip()
        except OSError:
            pass
    return None


def start_mqtt():
    global mqtt_client
    tok = supervisor_token()
    if not tok:
        log.warning("Supervisor token missing: MQTT disabled")
        return
    try:
        conn = http.client.HTTPConnection("supervisor", timeout=10)
        conn.request("GET", "/services/mqtt", headers={"Authorization": f"Bearer {tok}"})
        r = conn.getresponse()
        cfg = json.loads(r.read()).get("data") or {}
        if r.status != 200 or not cfg.get("host"):
            log.warning("MQTT service not available: entities disabled")
            return
    except Exception as e:
        log.warning("MQTT not available: %s", e)
        return
    import paho.mqtt.client as mqtt
    cid = f"tunnelgate_{socket.gethostname()}_{os.getpid()}"
    if hasattr(mqtt, "CallbackAPIVersion"):
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid)
    else:
        c = mqtt.Client(client_id=cid)
    if cfg.get("username"):
        c.username_pw_set(cfg["username"], cfg.get("password"))
    if cfg.get("ssl"):
        c.tls_set()
    c.will_set(AVAIL, "offline", retain=True)
    c.on_connect = on_mqtt_connect
    c.on_message = on_mqtt_message
    mqtt_client = c
    c.connect_async(cfg["host"], int(cfg.get("port", 1883)))
    c.loop_start()


# --------------------------------------------------------------------------- web panel
HTML = open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8").read()
refreshing = threading.Lock()


class Web(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _allowed(self):
        if self.client_address[0] != INGRESS_IP:
            self.send_error(403)
            return False
        return True

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not self._allowed():
            return
        p = self.path.split("?")[0].rstrip("/")
        if p in ("", "/index.html"):
            b = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif p == "/api/status":
            rx = tx = 0
            if runtime["status"] == "connected":
                try:
                    _, rx, tx = run(["wg", "show", WG_IF, "transfer"], check=False).split()
                    rx, tx = int(rx), int(tx)
                except ValueError:
                    pass
            self._json({"state": state, "runtime": runtime, "clients": CLIENTS,
                        "country_name": country_name(state["country"]),
                        "refreshing": refreshing.locked(), "rx": rx, "tx": tx,
                        "now": time.time()})
        elif p == "/api/locations":
            self._json(locations())
        else:
            self.send_error(404)

    def do_POST(self):
        if not self._allowed():
            return
        p = self.path.split("?")[0].rstrip("/")
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n)) if n else {}
        except ValueError:
            body = {}
        if p == "/api/connect":
            kw = {"enabled": True, "source": "panel"}
            if body.get("country"):
                kw["country"] = body["country"]
                kw["city"] = body.get("city") or ""
            threading.Thread(target=request, kwargs=kw, daemon=True).start()
            self._json({"ok": True})
        elif p == "/api/disconnect":
            threading.Thread(target=request, kwargs={"enabled": False, "source": "panel"},
                             daemon=True).start()
            self._json({"ok": True})
        elif p == "/api/favorite":
            code = country_code(str(body.get("country") or ""))
            if not code:
                self._json({"ok": False}, 400)
                return
            fav = [code, str(body.get("city") or "")]
            with lock:
                favs = [f for f in state.get("favorites", []) if f != fav]
                if body.get("on"):
                    favs.append(fav)
                state["favorites"] = favs[:12]
                save_state()
            self._json({"ok": True, "favorites": state["favorites"]})
        elif p == "/api/refresh":
            if refreshing.acquire(blocking=False):
                def job():
                    try:
                        refresh_servers(force=True)
                        publish_discovery()
                    except Exception as e:
                        log.error("Server list refresh: %s", e)
                    finally:
                        refreshing.release()
                threading.Thread(target=job, daemon=True).start()
            self._json({"ok": True})
        else:
            self.send_error(404)


class TWeb(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# --------------------------------------------------------------------------- main
def shutdown(*_):
    global stopping
    stopping = True
    fail_closed = KILL_ON_STOP and state["enabled"]
    log.info("Stopping: %s", "clients stay blocked (kill switch)" if fail_closed
             else "VPN down, clients go out through the LAN gateway without VPN")
    got = lock.acquire(timeout=3)
    try:
        if fail_closed:
            stop_fail_closed()
        else:
            stop_fail_open()
    except Exception as e:
        log.error("Cleanup: %s", e)
    finally:
        if got:
            lock.release()
    if mqtt_client:
        mqtt_client.publish(AVAIL, "offline", retain=True)
        time.sleep(0.3)
        mqtt_client.loop_stop()
    os._exit(0)


def main():
    global IPT, LAN_NET, LAN_IF
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    for attempt in range(30):  # at boot the LAN may not be ready yet
        try:
            LAN_IF = detect_lan_if(LAN_IF)
            LAN_NET = lan_network()
            break
        except Exception as e:
            if attempt == 29:
                raise
            log.info("LAN not ready (%s), retrying...", e)
            time.sleep(5)
    IPT = detect_iptables()
    log.info("iptables: %s | LAN: %s on %s | clients: %s", IPT, LAN_NET, LAN_IF,
             ", ".join(CLIENTS) or "none")
    if not CLIENTS:
        log.error("No clients configured")

    try:
        state.update(json.load(open(STATE_FILE)))
    except (OSError, ValueError):
        state["country"] = (OPTS.get("default_country") or "US").strip()
        state["city"] = (OPTS.get("default_city") or "").strip()
    try:
        refresh_servers()
    except Exception as e:
        log.error("Server list not available: %s", e)
    state["country"] = country_code(state["country"]) or "US"
    if not state.get("favorites"):
        state["favorites"] = [[state["country"], state["city"]]]

    for srv_cls, handler in ((TUDP, DnsUDP), (TTCP, DnsTCP)):
        s = srv_cls(("0.0.0.0", DNS_PORT), handler)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    web = TWeb(("0.0.0.0", WEB_PORT), Web)
    threading.Thread(target=web.serve_forever, daemon=True).start()

    start_mqtt()
    with lock:
        try:
            if state["enabled"]:
                connect()
            else:
                disconnect()
        except Exception as e:
            log.error("Startup: %s", e)
    threading.Thread(target=watchdog, daemon=True).start()
    log.info("Ready. Panel on Ingress, DNS proxy on :%d", DNS_PORT)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
