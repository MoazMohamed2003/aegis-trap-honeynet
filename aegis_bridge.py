#!/usr/bin/env python3
"""
Aegis-Bridge v3.4 - Active Mitigation Automation
Built on v3.3. Same confirmed schema. Same GCP / STIX / TTL / registry logic.
This is the final, hardened version.

WHY v3.0 EXISTED (data-driven breakout detection)
  v2.3 detected breakout by looking for dedicated hpfeed channels such as
  cowrie.direct-tcpip.request and cowrie.session.file_upload. Investigation of
  THIS deployment proved those channels are never produced. The only channels
  present are: cowrie.sessions, dionaea.connections, conpot.events. Cowrie
  records everything an attacker typed inside the payload.commands array of a
  single cowrie.sessions document, not as separate channels. So v2.3's flagship
  feature could never fire here.

WHAT IS NEW IN v3.0
  1. breakout_check() replaces is_compromised(). It reads recent cowrie.sessions
     for the attacker IP and scans payload.commands (and payload.urls) for
     high-confidence attacker tradecraft. A match is a confirmed breakout:
     immediate block + (optional) self-heal. It returns a rich verdict
     (label + MITRE technique + the exact offending command) used to enrich the
     firewall record and the STIX indicator.
  2. Escalation pattern database. A curated regex set covering lateral movement,
     ingress tool transfer, IoT botnet probes, execution staging, reverse
     shells, obfuscation, crypto-mining, persistence, defense evasion,
     destruction and anti-forensics. Patterns are deliberately specific
     (word boundaries, required arguments, redirect/pipe context) so ordinary
     reconnaissance (ls, cd, pwd, whoami, id, uname -a, cat /etc/passwd,
     cat /proc/cpuinfo, ps, netstat ...) does NOT match. Strong signals only.
  3. record_analysis() now reads the channels this stack actually emits, so the
     analysis collection builds a live behavioural profile of every observed IP.
  4. HPFEED_IP_FIELD set to the confirmed value "payload.peerIP".

WHAT IS NEW IN v3.1 (coverage + reliability, after a full logic audit)
  1. command_sweep(): volume-independent breakout detection. v3.0 only scanned
     commands for IPs that a volume/port rule already flagged, so a low-and-slow
     attacker who opened a few sessions, ran "wget ... | sh", and left was never
     evaluated. command_sweep now scans EVERY recent cowrie.sessions IP each
     cycle and blocks any that ran post-exploit tradecraft, regardless of volume.
     This replaces the old breakout_check (which was gated behind hot_ips).
  2. multi_service_ips(): cross-honeypot correlation. An IP that touches two or
     more distinct honeypots inside the window is multi-service reconnaissance
     even when each honeypot stays below its own threshold. Internal/management
     IPs are excluded so our own testing never trips it.
  3. Threat-intel denylist. Optional local file of known-bad IPs. Any match is
     blocked immediately on first contact. Safe no-op when the file is absent.
  4. block_ip() hardened. The GCP insert is wrapped: an API error no longer
     crashes the loop, a duplicate-rule conflict is repaired by delete+reinsert,
     and the record carries gcp_synced so a desync is visible.
  5. unblock_ip() only marks an IP unblocked when GCP actually removed the rule
     (or it was already gone). A transient delete failure is retried next cycle.
  6. record_sighting() de-duplicates. It counts one sighting per detection
     window, not one per 30-second poll, so confidence is no longer inflated by
     an IP simply sitting above threshold for several minutes.
  7. match_escalation() returns ALL matched patterns, so an indicator can carry
     several MITRE techniques at once (download AND pipe-to-shell, for example).

WHAT IS NEW IN v3.2 (deadline hardening)
  1. Internal-IP guard on every detection path. command_sweep() and hot_ips()
     now skip private / loopback / management addresses, like multi_service_ips()
     already did. This stops the team's own testing (for example running wget
     from an internal host) from blocking your own infrastructure.
  2. Failed firewall insert no longer parks an IP. If the GCP insert fails,
     block_ip() returns False and does NOT add the IP to the active set, so the
     next cycle re-flags and retries it instead of leaving it unblocked for the
     whole TTL. rebuild_registry() also skips unsynced records after a restart.
  3. Verdict merge keeps all intelligence. _merge_targets() now unions the MITRE
     techniques from both verdicts and keeps both reasons, so a multi-service
     scanner that also breaches a volume threshold no longer loses its
     correlation tags in the published indicator.
  4. Analysis count fixed. record_analysis() stored a cumulative counter that
     re-counted the same window every cycle and inflated. It now records a
     snapshot of recent activity instead, so the number is meaningful.
  5. Threat-intel denylist validates entries. Lines that are not valid IPs are
     skipped and counted, so malformed lines cannot pollute the known-bad set.

WHAT IS NEW IN v3.3 (richer threat intelligence)
  Each STIX indicator now links a proper STIX 2.1 observed-data object carrying
  the evidence the bridge already holds at block time:
    - the attacker's typed commands (every Cowrie block, not only breakouts),
    - the matched behaviour labels (when escalation patterns fired),
    - the credential attempts tried (login-based blocks),
    - the sighting count and the honeypots the IP touched.
  gather_evidence() collects these in one place. publish_stix() builds an
  ipv4-addr observable, an ObservedData object holding the evidence, and a
  Relationship linking the indicator to it. The evidence is also stored in the
  blocked_ips audit record. The evidence build is wrapped, so any STIX issue
  falls back to the plain indicator rather than failing the block.
  NOTE: commands exist only for Cowrie (no shell on Dionaea/Conpot); each field
  appears only where its data exists.

WHAT IS NEW IN v3.4 (final hardening pass)
  Crash safety:
    - hot_ips() now wraps its aggregation. A transient MongoDB error returns an
      empty list instead of killing the poll loop. This was the one realistic
      crash path left in v3.3.
    - The whole per-cycle body in main() is wrapped. Any unexpected error in a
      cycle is logged and the loop continues, rather than exiting the process.
    - The publish_stix() call inside block_ip() is wrapped, so a STIX failure can
      never affect a block that already landed in GCP and MongoDB.
    - The local STIX fallback write is wrapped, so a full disk cannot crash the loop.
  Intelligence correctness:
    - gather_evidence() now also captures first_seen, so the ObservedData object
      carries a real observation window (first_observed..last_observed) instead of
      a zero-duration one.
    - Credential pairs are only recorded when a login or password is actually
      present, so malformed auth entries no longer publish "None/None".
    - The hpfeed and session evidence cursors are bounded with .limit(), so an
      attacker active for a long window cannot make a single block read an
      unbounded number of documents.
  Fixed the startup log line, which still printed an old version string.
  KEPT (verified against the STIX 2.1 spec): indicator "based-on" observed-data is
  a standard relationship type. It is correct and is not changed.

CONFIRMED SCHEMA
  session : source_ip, honeypot, timestamp, destination_port, protocol,
            auth_attempts[]   (NO destination_ip)
  hpfeed  : channel, timestamp(Date), payload.peerIP, payload.commands[],
            payload.urls[]
            channels present: cowrie.sessions, dionaea.connections, conpot.events

DORMANT BY DESIGN (no data to drive them, so they never fire falsely)
  * classify() rule 0 (mgmt-subnet breakout) needs session.destination_ip,
    which this schema does not have yet. Safe and silent until it appears.
  * self-heal needs SELF_HEAL_ENABLED=True AND a working SSH key at
    HONEYPOT_KEY. Wiring is complete; it is off until you enable it.
"""

import os, time, logging, requests, uuid, ipaddress, re
import geoip2.database
from geoip2.errors import AddressNotFoundError
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING
from google.cloud import compute_v1
from google.oauth2 import service_account
import stix2

# -- CONFIG --------------------------------------------------------------------
PROJECT      = "Project ID"
NETWORK      = "aegis-vpc"
CREDS_FILE   = os.getenv("GCP_CREDS_FILE", "/opt/aegis-bridge/gcp-key.json")
POLL_SEC     = 30
WINDOW_SEC   = 60
# v2.3: expiry derived from severity (days)
BLOCK_TTL    = {"critical": 30, "high": 14, "medium": 7, "low": 3}

# Per-honeypot session-count thresholds (events per WINDOW_SEC)
THRESHOLDS = {"cowrie": 10, "dionaea": 5, "conpot": 3}

# Honeypots where any contact is treated as an attack
HIGH_SEVERITY_HONEYPOTS = {"conpot"}

# Login attempts in the window that count as a credential attack on their own
AUTH_THRESHOLD = 20

# Ports that raise severity by service type (confirmed exposed ports)
ICS_PORTS = {502, 102, 44818, 161}   # industrial / SCADA (Conpot)
DB_PORTS  = {1433, 3306, 27017}      # database services (Dionaea)

# Staged response. Seconds to observe before blocking, per severity.
# critical is 0 because critical never observes, it blocks at once.
OBSERVE_SEC = {"critical": 0, "high": 180, "medium": 300}

# Management subnet. A session aimed here is a breakout (classify rule 0).
MGMT_SUBNET = "10.0.0.0/24"

# STIX / TAXII (posts through the Nginx gate on 8080, basic auth, envelope format)
TAXII_URL      = os.environ.get("TAXII_URL",
    "http://localhost:8080/taxii2/<api-root-id>/collections/<collection-id>/objects/")
TAXII_USER     = os.environ["TAXII_USER"]
TAXII_PASSWORD = os.environ["TAXII_PASSWORD"]

# GeoIP
GEOIP_CITY_DB = "/opt/aegis-bridge/geoip/GeoLite2-City.mmdb"
GEOIP_ASN_DB  = "/opt/aegis-bridge/geoip/GeoLite2-ASN.mmdb"

# Self-heal (SSH to the honeypot VM)
HONEYPOT_HOST = "10.0.1.3"
HONEYPOT_USER = "your-user"
HONEYPOT_KEY  = "/opt/aegis-bridge/honeypot_key"
HONEYPOT_DIRS = {
    "cowrie":  "/home/your-user/aegis-trap/cowrie",
    "dionaea": "/home/your-user/aegis-trap/dionaea",
    "conpot":  "/home/your-user/aegis-trap/conpot",
}
SELF_HEAL_ENABLED = True   # turn on only after blocking is verified + SSH key set
HEAL_COOLDOWN_SEC = 300     # do not rebuild the same honeypot more than once / 5 min

# v3.0: channels this stack actually emits. record_analysis() reads these to
# build a behavioural profile of observed attackers. None of them trigger a block.
ANALYSIS_CHANNELS = {"cowrie.sessions", "dionaea.connections", "conpot.events"}

# v3.0: confirmed attacker-IP field inside hpfeed documents (cowrie + dionaea).
# While None, breakout_check and record_analysis stay dormant.
HPFEED_IP_FIELD = "payload.peerIP"

# v3.0: how far back to look in hpfeed for an attacker's recent activity.
BREAKOUT_LOOKBACK_SEC = 600
ANALYSIS_LOOKBACK_SEC = 600

# confidence base by severity. Each sighting adds 1, capped at 100.
CONFIDENCE_BASE = {"critical": 90, "high": 75, "medium": 60, "low": 40}

# v3.1: count one sighting per detection window, not per poll, so an IP sitting
# above threshold for minutes does not inflate its own confidence.
SIGHTING_DEDUP_SEC = 300

# v3.1: an IP seen on this many distinct honeypots in the window is treated as
# multi-service reconnaissance even if each honeypot stays below its threshold.
MULTI_SERVICE_MIN = 2

# v3.1: optional threat-intel denylist. One IP per line, '#' comments allowed.
# Drop a file here (e.g. refreshed by cron from a free feed) to block known-bad
# IPs on first contact. Absent file = feature dormant, never an error.
THREAT_INTEL_FILE        = "/opt/aegis-bridge/threat_intel/badips.txt"
THREAT_INTEL_REFRESH_SEC = 3600
KNOWN_BAD   = set()
_TI_LAST_LOAD = [0.0]

# -- ESCALATION PATTERN DATABASE (v3.0) ----------------------------------------
# Each tuple: (regex, human label, [MITRE ATT&CK ids]).
# Design rule: a pattern is included ONLY if it has no legitimate purpose inside
# an SSH honeypot session. Word boundaries and required arguments stop benign
# reconnaissance from matching. Matching is per-command, never across commands.
_ESCALATION_RULES = [
    # --- Lateral movement: pivoting onward from the honeypot ----------------
    # ssh/telnet require a real connection target (user@host, an IPv4, or -p port)
    # so service-management commands like "service ssh status" do NOT match.
    (r"\bssh\s+[^;|&\n]{0,40}(?:@|-p\s*\d|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                                             "lateral movement: onward ssh",         ["T1021.004"]),
    (r"\btelnet\s+[^;|&\n]{0,40}(?:@|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                                             "lateral movement: onward telnet",      ["T1021"]),
    (r"\b(rsh|rlogin)\s+[^;|&\n]{0,40}(?:@|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                                             "lateral movement: onward rsh/rlogin",  ["T1021"]),
    (r"\bsshpass\b",                         "lateral movement: sshpass",            ["T1021.004"]),

    # --- Ingress tool transfer: pulling a payload into the box --------------
    (r"\bwget\s+\S",                         "tool transfer: wget",                  ["T1105"]),
    (r"\bcurl\s+\S",                         "tool transfer: curl",                  ["T1105"]),
    (r"\btftp\b",                            "tool transfer: tftp",                  ["T1105"]),
    (r"\bftpget\b",                          "tool transfer: ftpget",                ["T1105"]),
    (r"\bscp\s+\S",                          "tool transfer: scp",                   ["T1105"]),
    (r"https?://",                           "tool transfer: inline URL fetch",      ["T1105"]),

    # --- IoT botnet infection probes (Mirai / Gafgyt family) ---------------
    (r"\bbusybox\b",                         "botnet probe: busybox",                ["T1059", "T1105"]),
    (r"/bin/busybox",                        "botnet probe: /bin/busybox",           ["T1059", "T1105"]),
    (r"\b(mirai|gafgyt|tsunami|dofloo|mozi|kaiten|bashlite|hajime)\b",
                                             "known botnet family string",           ["T1059"]),

    # --- Execution staging: making a payload runnable ----------------------
    (r"\bchmod\s+(\+x|u\+x|777|0777|755|0755)\b",
                                             "execution staging: chmod +x",          ["T1222"]),

    # --- Piping remote content straight into an interpreter ----------------
    (r"\|\s*(sh|bash|ash|dash)\b",           "execution: pipe to shell",             ["T1059.004"]),
    (r"\b(sh|bash|ash|dash)\s+-c\b",         "execution: shell -c",                  ["T1059.004"]),
    (r"\bpython\d?\s+-c\b",                  "execution: python one-liner",          ["T1059.006"]),
    (r"\bperl\s+-e\b",                       "execution: perl one-liner",            ["T1059"]),
    (r"\bphp\s+-r\b",                        "execution: php one-liner",             ["T1059"]),

    # --- Reverse shells -----------------------------------------------------
    (r"/dev/tcp/",                           "reverse shell: /dev/tcp",              ["T1059.004"]),
    (r"\bbash\s+-i\b",                       "reverse shell: interactive bash",      ["T1059.004"]),
    (r"\bmkfifo\b",                          "reverse shell: mkfifo",                ["T1059.004"]),
    (r"\bnc(at)?\b.{0,40}\s-e(\s|/|$)",      "reverse shell: netcat -e",             ["T1059.004"]),
    (r"\bsocat\s+\S",                        "reverse shell/tunnel: socat",          ["T1059.004"]),

    # --- Obfuscation / encoded payloads ------------------------------------
    (r"\bbase64\s+(-d|--decode)\b",          "obfuscation: base64 decode",           ["T1140"]),
    (r"\bopenssl\s+enc\b",                   "obfuscation: openssl enc",             ["T1140"]),
    (r"\bxxd\s+-r\b",                         "obfuscation: xxd reverse",             ["T1140"]),

    # --- Crypto miners ------------------------------------------------------
    (r"\b(xmrig|minerd|cpuminer|ccminer|cgminer)\b",
                                             "resource hijack: crypto miner",        ["T1496"]),
    (r"stratum\+tcp://",                     "resource hijack: mining pool",         ["T1496"]),

    # --- Persistence --------------------------------------------------------
    (r">{1,2}\s*\S*authorized_keys",         "persistence: write authorized_keys",   ["T1098.004"]),
    (r"\btee\b.*authorized_keys",            "persistence: tee authorized_keys",     ["T1098.004"]),
    (r">{1,2}\s*/etc/(cron|rc\.local|init\.d)",
                                             "persistence: cron/rc write",           ["T1053"]),
    (r"\bcrontab\s+-",                       "persistence: crontab edit",            ["T1053.003"]),
    (r"\b(useradd|adduser)\s+\S",            "persistence: add user account",        ["T1136.001"]),
    (r"\bchattr\s+\+i\b",                    "persistence: immutable file",          ["T1222"]),
    (r"\b(insmod|modprobe)\s+\S",            "rootkit: load kernel module",          ["T1547.006"]),

    # --- Defense evasion: disabling controls -------------------------------
    (r"\biptables\s+-F\b",                   "defense evasion: flush iptables",      ["T1562.004"]),
    (r"\bsetenforce\s+0\b",                  "defense evasion: disable SELinux",     ["T1562.001"]),
    (r"\bufw\s+disable\b",                   "defense evasion: disable ufw",         ["T1562.004"]),

    # --- Destruction / anti-forensics on system roots ----------------------
    (r"\brm\s+-rf\s+/(?:\s|$|bin|etc|var|usr|root|boot|lib|sbin|\*)",
                                             "destructive: rm -rf system root",      ["T1485"]),
    (r">\s*/var/log/\S",                     "anti-forensics: overwrite logs",       ["T1070"]),
    (r"\bhistory\s+-c\b",                    "anti-forensics: clear history",        ["T1070.003"]),
    (r"\bunset\s+HISTFILE\b",                "anti-forensics: unset HISTFILE",       ["T1070.003"]),
]
_ESCALATION_COMPILED = [(re.compile(rx, re.IGNORECASE), label, attack)
                        for rx, label, attack in _ESCALATION_RULES]


def match_escalation(commands, urls):
    """Return {labels, attack, evidence} listing EVERY strong pattern matched,
    else None. Commands are checked one at a time so a pattern never spans two
    unrelated commands. A captured download URL counts as ingress tool transfer.
    """
    labels, attack, evidence = [], [], None
    for cmd in commands:
        if not isinstance(cmd, str):
            continue
        for rx, label, ids in _ESCALATION_COMPILED:
            if rx.search(cmd):
                if label not in labels:
                    labels.append(label)
                for t in ids:
                    if t not in attack:
                        attack.append(t)
                if evidence is None:
                    evidence = cmd[:200]
    for u in urls:
        if isinstance(u, str) and u.strip():
            lbl = "tool transfer: captured download URL"
            if lbl not in labels:
                labels.append(lbl)
            if "T1105" not in attack:
                attack.append("T1105")
            if evidence is None:
                evidence = u[:200]
    if not labels:
        return None
    return {"labels": labels, "attack": attack, "evidence": evidence}


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("aegis-bridge")

BLOCKED   = {}   # rebuilt from blocked_ips on startup
OBSERVING = {}   # ip -> observation record, rebuilt from observed_ips on startup
HEALED    = {}   # honeypot -> last heal time, for the cooldown

# -- THREAT INTEL (v3.1, optional) ---------------------------------------------
def load_threat_intel():
    # Reads a newline-delimited IP denylist if the file exists. Blank lines and
    # '#' comments are ignored. Safe no-op when the file is absent.
    _TI_LAST_LOAD[0] = time.time()
    try:
        if not os.path.exists(THREAT_INTEL_FILE):
            return
        new = set()
        skipped = 0
        with open(THREAT_INTEL_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                token = line.split()[0]
                try:
                    ipaddress.ip_address(token)   # v3.2: only accept valid IPs
                    new.add(token)
                except ValueError:
                    skipped += 1
        KNOWN_BAD.clear()
        KNOWN_BAD.update(new)
        msg = f"Threat intel loaded: {len(KNOWN_BAD)} known-bad IPs"
        if skipped:
            msg += f" ({skipped} malformed lines skipped)"
        log.info(msg)
    except Exception as e:
        log.error(f"Threat intel load failed: {e}")

def is_known_bad(ip):
    return ip in KNOWN_BAD

def _is_internal(ip):
    # True for RFC1918 / loopback / management ranges, so our own hosts and
    # testing never get flagged as attackers.
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or in_mgmt(ip)
    except Exception:
        return False

# -- DATABASE ------------------------------------------------------------------
def get_db():
    # MongoDB only listens inside its container, not on the host. Ask Docker for
    # the container IP, fall back to localhost if that lookup ever fails.
    import subprocess
    host = "localhost"
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
             "chnserver-mongodb-1"],
            capture_output=True, text=True, timeout=10)
        ip = out.stdout.strip()
        if ip:
            host = ip
    except Exception:
        pass
    return MongoClient(f"mongodb://{host}:27017/",
                       serverSelectionTimeoutMS=5000)["mnemosyne"]

def init_collections(db):   # v3.0: indexes analysis as well
    db.blocked_ips.create_index([("ip", ASCENDING)], unique=True)
    db.blocked_ips.create_index([("expires_at", ASCENDING)])
    db.observed_ips.create_index([("ip", ASCENDING)], unique=True)
    db.sightings.create_index([("ip", ASCENDING)], unique=True)
    db.analysis.create_index([("ip", ASCENDING)], unique=True)
    db.analysis.create_index([("last_seen", ASCENDING)])
    db.published_recon.create_index([("ip", ASCENDING)], unique=True)
    db.published_recon.create_index([("published_at", ASCENDING)])
    log.info("collections ready (blocked_ips, observed_ips, sightings, analysis, published_recon)")

def rebuild_registry(db):
    now = datetime.utcnow()
    n = 0
    # v3.2: skip records whose GCP rule never synced, so they retry instead of
    # being masked as active after a restart.
    for rec in db.blocked_ips.find({"expires_at": {"$gt": now}, "unblocked": False,
                                    "gcp_synced": {"$ne": False}}):
        BLOCKED[rec["ip"]] = {"expires": rec["expires_at"], "honeypot": rec["honeypot"]}
        n += 1
    log.info(f"Registry rebuilt from MongoDB: {n} active blocks loaded")

def rebuild_observing(db):
    n = 0
    for rec in db.observed_ips.find({"resolved": False}):
        OBSERVING[rec["ip"]] = {
            "honeypot": rec["honeypot"], "severity": rec["severity"],
            "reason": rec["reason"], "attack": rec.get("attack", []),
            "block_due": rec["block_due"],
        }
        n += 1
    log.info(f"Observation queue rebuilt from MongoDB: {n} IPs under observation")

# -- SIGHTINGS -----------------------------------------------------------------
def record_sighting(db, ip, honeypot):
    # v3.1: count one sighting per detection window. If the IP was already seen
    # within SIGHTING_DEDUP_SEC, refresh last_seen and honeypots but do not
    # increment, so a long flood does not inflate confidence.
    now = datetime.utcnow()
    doc = db.sightings.find_one({"ip": ip})
    recent = bool(doc and doc.get("last_seen") and
                  (now - doc["last_seen"]).total_seconds() < SIGHTING_DEDUP_SEC)
    upd = {"$addToSet": {"honeypots": honeypot},
           "$set": {"last_seen": now},
           "$setOnInsert": {"first_seen": now}}
    if not recent:
        upd["$inc"] = {"count": 1}
    db.sightings.update_one({"ip": ip}, upd, upsert=True)

def get_sighting_count(db, ip):
    doc = db.sightings.find_one({"ip": ip})
    return doc["count"] if doc else 1

def confidence(severity, sightings):
    return min(100, CONFIDENCE_BASE.get(severity, 50) + min(sightings, 20))

# -- GEOIP ---------------------------------------------------------------------
def geoip_lookup(ip):
    out = {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "org": "Unknown"}
    try:
        with geoip2.database.Reader(GEOIP_CITY_DB) as r:
            resp = r.city(ip)
            out["country"] = resp.country.name or "Unknown"
            out["city"]    = resp.city.name or "Unknown"
    except AddressNotFoundError:
        pass
    except FileNotFoundError:
        log.error(f"GeoIP city database missing at {GEOIP_CITY_DB}")
    try:
        with geoip2.database.Reader(GEOIP_ASN_DB) as r:
            resp = r.asn(ip)
            out["asn"] = str(resp.autonomous_system_number or "Unknown")
            out["org"] = resp.autonomous_system_organization or "Unknown"
    except AddressNotFoundError:
        pass
    except FileNotFoundError:
        log.error(f"GeoIP ASN database missing at {GEOIP_ASN_DB}")
    return out

# -- GCP FIREWALL --------------------------------------------------------------
def gcp_client():
    creds = service_account.Credentials.from_service_account_file(
        CREDS_FILE, scopes=["https://www.googleapis.com/auth/compute"])
    return compute_v1.FirewallsClient(credentials=creds)

# -- EVIDENCE FOR INTELLIGENCE (v3.3) ------------------------------------------
def gather_evidence(db, ip, honeypot):
    # Collect context the bridge already holds at block time, to enrich the STIX
    # indicator: typed commands and derived behaviour labels (Cowrie only, no
    # shell elsewhere), credential attempts, the sighting count, and the
    # honeypots touched. Every lookup is wrapped so enrichment never breaks a block.
    ev = {"commands": [], "labels": [], "credentials": [],
          "sightings": 1, "honeypots": [], "first_seen": None}
    try:
        s = db.sightings.find_one({"ip": ip})
        if s:
            ev["sightings"] = s.get("count", 1)
            ev["honeypots"] = s.get("honeypots", [])
            ev["first_seen"] = s.get("first_seen")   # v3.4: real observation start
    except Exception as e:
        log.error(f"Evidence sightings failed for {ip}: {e}")
    if HPFEED_IP_FIELD is not None:
        try:
            cutoff = datetime.utcnow() - timedelta(seconds=BREAKOUT_LOOKBACK_SEC)
            cmds, urls = [], []
            for evt in db.hpfeed.find(
                    {"channel": "cowrie.sessions", "timestamp": {"$gte": cutoff},
                     HPFEED_IP_FIELD: ip},
                    {"payload.commands": 1, "payload.urls": 1}).limit(200):
                p = evt.get("payload", {}) or {}
                c = p.get("commands") or []
                u = p.get("urls") or []
                if isinstance(c, list):
                    cmds.extend(x for x in c if isinstance(x, str))
                if isinstance(u, list):
                    urls.extend(x for x in u if isinstance(x, str))
            ev["commands"] = cmds[:50]
            hit = match_escalation(cmds, urls)   # derive behaviour labels, if any
            if hit:
                ev["labels"] = hit["labels"]
        except Exception as e:
            log.error(f"Evidence commands failed for {ip}: {e}")
    try:
        cutoff = datetime.utcnow() - timedelta(seconds=WINDOW_SEC * 10)
        creds = []
        for s in db.session.find({"source_ip": ip, "timestamp": {"$gte": cutoff}},
                                 {"auth_attempts": 1}).limit(200):
            for a in (s.get("auth_attempts") or []):
                login = a.get("login")
                password = a.get("password")
                if not login and not password:   # v3.4: skip empty/malformed entries
                    continue
                pair = f"{login}/{password}"
                if pair not in creds:
                    creds.append(pair)
        ev["credentials"] = creds[:30]
    except Exception as e:
        log.error(f"Evidence credentials failed for {ip}: {e}")
    return ev

# expiry derived from severity via BLOCK_TTL dict.
def block_ip(db, client, ip, honeypot, reason, severity, attack, sightings):
    name    = "aegis-block-" + ip.replace(".", "-")
    days    = BLOCK_TTL.get(severity, 7)
    expires = datetime.utcnow() + timedelta(days=days)
    geo     = geoip_lookup(ip)
    conf    = confidence(severity, sightings)
    evidence = gather_evidence(db, ip, honeypot)   # v3.3

    fw = compute_v1.Firewall()
    fw.name        = name
    fw.network     = f"projects/{PROJECT}/global/networks/{NETWORK}"
    fw.direction   = "INGRESS"
    fw.priority    = 100
    fw.denied      = [compute_v1.Denied(I_p_protocol="all")]  # client quirk, keep as is
    fw.source_ranges = [ip + "/32"]
    fw.description = (f"Auto-blocked by Aegis-Bridge {datetime.utcnow().isoformat()} "
                     f"| honeypot={honeypot} | severity={severity} "
                     f"| attack={','.join(attack) or 'n/a'} | confidence={conf} "
                     f"| country={geo['country']} | {reason}")
    # v3.1: insert is wrapped. An API error no longer crashes the poll loop, and
    # a leftover rule from a previous block is repaired by delete + reinsert.
    synced = True
    try:
        client.insert(project=PROJECT, firewall_resource=fw)
    except Exception as ex:
        msg = str(ex).lower()
        if any(k in msg for k in ("already exists", "conflict", "409", "duplicate")):
            try:
                client.delete(project=PROJECT, firewall=name)
                client.insert(project=PROJECT, firewall_resource=fw)
            except Exception as ex2:
                synced = False
                log.error(f"GCP re-block failed for {ip}: {ex2}")
        else:
            synced = False
            log.error(f"GCP insert failed for {ip}: {ex}")

    db.blocked_ips.update_one({"ip": ip}, {"$set": {
        "ip": ip, "honeypot": honeypot, "reason": reason, "severity": severity,
        "attack": attack, "confidence": conf, "sightings": sightings,
        "gcp_synced": synced,   # v3.1: visible if GCP and our records disagree
        "country": geo["country"], "city": geo["city"],
        "asn": geo["asn"], "org": geo["org"],
        "commands": evidence["commands"], "behaviour_labels": evidence["labels"],
        "credentials": evidence["credentials"],
        "honeypots_touched": evidence["honeypots"],   # v3.3 evidence
        "blocked_at": datetime.utcnow(), "expires_at": expires, "unblocked": False,
    }}, upsert=True)
    # v3.2: only treat the IP as actively blocked if the GCP rule synced. On a
    # failed insert we leave it out of BLOCKED so the next cycle re-flags and
    # retries it, rather than parking an unprotected IP for the whole TTL.
    if synced:
        BLOCKED[ip] = {"expires": expires, "honeypot": honeypot}
        log.warning(f"BLOCKED {ip} | {severity} | conf {conf} | {geo['country']}/{geo['org']} "
                    f"| {honeypot} | {reason} | expires {expires.date()}")
    else:
        log.error(f"{ip} recorded but NOT active (GCP rule unsynced); will retry next cycle")
    try:
        publish_stix(ip, honeypot, reason, severity, geo, expires, attack, conf, evidence)
    except Exception as e:
        # v3.4: the block already landed in GCP and MongoDB above. A STIX/TAXII
        # problem must never undo or interrupt that, so it is logged and dropped.
        log.error(f"publish_stix failed for {ip} (block stands): {e}")
    return synced

def unblock_ip(db, client, ip):
    name = "aegis-block-" + ip.replace(".", "-")
    removed = False
    try:
        client.delete(project=PROJECT, firewall=name)
        removed = True
        log.info(f"UNBLOCKED {ip} (TTL expired)")
    except Exception as ex:
        msg = str(ex).lower()
        if "not found" in msg or "404" in msg:
            removed = True   # already gone, treat as removed
            log.info(f"UNBLOCK {ip}: GCP rule already absent")
        else:
            # v3.1: keep the IP blocked in our records and retry next cycle,
            # so we never claim an IP is unblocked while its rule still exists.
            log.error(f"Failed to delete GCP rule for {ip}: {ex} (will retry)")
    if removed:
        db.blocked_ips.update_one({"ip": ip},
            {"$set": {"unblocked": True, "unblocked_at": datetime.utcnow()}})
        BLOCKED.pop(ip, None)

# -- STIX / TAXII --------------------------------------------------------------
def publish_stix(ip, honeypot, reason, severity, geo, expires, attack, conf, evidence=None):
    ev = evidence or {}
    labels = ["malicious-activity", "honeypot",
              f"honeypot:{honeypot}", f"severity:{severity}"]
    labels += [f"mitre-attack:{t}" for t in attack]

    cmd_n  = len(ev.get("commands", []))
    cred_n = len(ev.get("credentials", []))
    extra  = ""
    if cmd_n or cred_n:
        extra = f" Evidence: {cmd_n} commands, {cred_n} credential attempts captured."

    indicator = stix2.Indicator(
        id=f"indicator--{uuid.uuid4()}",
        name=f"Malicious IP detected: {ip}",
        description=(f"Caught by Aegis-Trap honeypot network. Honeypot: {honeypot}. "
                     f"Severity: {severity}. Confidence: {conf}. "
                     f"ATT&CK: {', '.join(attack) or 'n/a'}. Trigger: {reason}. "
                     f"Origin: {geo['country']}, {geo['city']}. "
                     f"Network: AS{geo['asn']} ({geo['org']}). Expires: {expires.date()}."
                     f"{extra}"),
        pattern=f"[ipv4-addr:value = '{ip}']",
        pattern_type="stix",
        valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        valid_until=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        confidence=conf,
        labels=labels,
        custom_properties={
            "x_aegis_honeypot": honeypot, "x_aegis_severity": severity,
            "x_aegis_attack": attack, "x_aegis_confidence": conf,
            "x_aegis_country": geo["country"], "x_aegis_asn": geo["asn"],
            "x_aegis_org": geo["org"], "x_aegis_trigger": reason,
        })

    objs = [indicator]
    # v3.3: attach the evidence as a proper linked STIX 2.1 observed-data object.
    # Wrapped, so any STIX issue falls back to the plain indicator above.
    try:
        now_s = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        first_s = now_s
        fseen = ev.get("first_seen")
        if fseen is not None:
            try:
                first_s = fseen.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                first_s = now_s
        sco_ip = stix2.IPv4Address(value=ip)
        observed = stix2.ObservedData(
            first_observed=first_s, last_observed=now_s,
            number_observed=max(1, int(ev.get("sightings", 1))),
            object_refs=[sco_ip.id],
            allow_custom=True,
            custom_properties={
                "x_aegis_commands": ev.get("commands", []),
                "x_aegis_behaviour_labels": ev.get("labels", []),
                "x_aegis_credentials": ev.get("credentials", []),
                "x_aegis_sightings": int(ev.get("sightings", 1)),
                "x_aegis_honeypots": ev.get("honeypots", []),
            })
        rel = stix2.Relationship(
            relationship_type="based-on",
            source_ref=indicator.id, target_ref=observed.id)
        objs += [sco_ip, observed, rel]
    except Exception as e:
        log.error(f"STIX evidence object build failed for {ip}: {e}")

    bundle = stix2.Bundle(objects=objs, allow_custom=True)
    import json as _json
    envelope = _json.dumps({"objects": [_json.loads(o.serialize()) for o in objs]})
    try:
        resp = requests.post(TAXII_URL, data=envelope,
            headers={"Content-Type": "application/taxii+json;version=2.1",
                     "Accept": "application/taxii+json;version=2.1"},
            auth=(TAXII_USER, TAXII_PASSWORD), timeout=10)
        if resp.status_code in (200, 201, 202):
            log.info(f"STIX published to TAXII for {ip}")
        else:
            log.error(f"TAXII publish failed: {resp.status_code} -- {resp.text}")
    except requests.RequestException as e:
        log.error(f"TAXII unreachable: {e}")
        try:
            os.makedirs("/opt/aegis-bridge/stix_fallback", exist_ok=True)
            path = f"/opt/aegis-bridge/stix_fallback/{ip.replace('.', '-')}.json"
            with open(path, "w") as f:
                f.write(bundle.serialize(pretty=True))
            log.warning(f"STIX saved locally to {path}")
        except Exception as werr:
            log.error(f"STIX local fallback write failed for {ip}: {werr}")

# -- BREAKOUT (session destination check, dormant until destination_ip exists) -
def in_mgmt(ip_str):
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(MGMT_SUBNET)
    except Exception:
        return False

# -- ATTACK CLASSIFICATION (decides block + severity + mode + attack) ----------
def classify(group):
    ip        = group["_id"]["ip"]
    honeypot  = group["_id"].get("honeypot", "unknown")
    count     = group["count"]
    ports     = set(p for p in group.get("ports", []) if p is not None)
    auth_cnt  = group.get("auth_count", 0)
    dst_ips   = set(d for d in group.get("dst_ips", []) if d)

    # 0a. Threat-intel hit. A known-bad IP is blocked on first contact. (v3.1)
    if is_known_bad(ip):
        return {"block": True, "severity": "critical", "mode": "immediate",
                "attack": ["T1071"],
                "reason": "known-malicious IP (threat-intel denylist match)"}

    # 0. Breakout toward the management subnet. Dormant until session carries
    #    a destination_ip (this schema does not yet).
    if any(in_mgmt(d) for d in dst_ips):
        return {"block": True, "severity": "critical", "mode": "immediate",
                "attack": ["T1021"],
                "reason": f"breakout attempt toward management subnet {MGMT_SUBNET}"}

    # 1. Industrial decoy contact. Any touch on Conpot or an ICS port.
    if honeypot in HIGH_SEVERITY_HONEYPOTS or (ports & ICS_PORTS):
        hit = sorted(ports & ICS_PORTS) or "n/a"
        return {"block": True, "severity": "critical", "mode": "immediate",
                "attack": ["T0886"],
                "reason": f"ICS/SCADA decoy contact ({honeypot}, ics-ports {hit})"}

    # 2. Session-count threshold. Classic brute-force volume.
    if count >= THRESHOLDS.get(honeypot, 10):
        return {"block": True, "severity": "high", "mode": "observe",
                "attack": ["T1110"],
                "reason": f"threshold {count} sessions in {WINDOW_SEC}s on {honeypot}"}

    # 3. Credential attack. Many login tries even under the session threshold.
    if auth_cnt >= AUTH_THRESHOLD:
        return {"block": True, "severity": "high", "mode": "observe",
                "attack": ["T1110"],
                "reason": f"credential attack {auth_cnt} login attempts on {honeypot}"}

    # 4. Database / sensitive service probe. Lower volume, higher value.
    if ports & DB_PORTS:
        hit = sorted(ports & DB_PORTS)
        return {"block": True, "severity": "medium", "mode": "observe",
                "attack": ["T1046"],
                "reason": f"database service probe (ports {hit}) on {honeypot}"}

    return {"block": False, "severity": "low", "mode": "none",
            "attack": [], "reason": "below thresholds"}

# -- THRESHOLD / TYPE CHECK ----------------------------------------------------
def hot_ips(db):
    cutoff = datetime.utcnow() - timedelta(seconds=WINDOW_SEC)
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {
            "_id": {"ip": "$source_ip", "honeypot": "$honeypot"},
            "count": {"$sum": 1},
            "ports": {"$addToSet": "$destination_port"},
            "auth_count": {"$sum": {"$size": {"$ifNull": ["$auth_attempts", []]}}},
            "dst_ips": {"$addToSet": "$destination_ip"},   # empty if field absent
        }},
    ]
    results = []
    try:
        rows = list(db.session.aggregate(pipeline))
    except Exception as e:
        log.error(f"hot_ips aggregation failed, skipping this cycle: {e}")
        return results
    for row in rows:
        ip = row["_id"].get("ip")
        if not ip or _is_internal(ip):   # v3.2: never act on our own hosts
            continue
        verdict = classify(row)
        if verdict["block"]:
            results.append({"ip": ip,
                            "honeypot": row["_id"].get("honeypot", "unknown"),
                            "reason": verdict["reason"],
                            "severity": verdict["severity"],
                            "mode": verdict["mode"],
                            "attack": verdict["attack"]})
    return results

# -- ANALYSIS COLLECTION (v3.0) ------------------------------------------------
def record_analysis(db, ip, honeypot):
    # Runs every cycle for every observed IP. Never touches block logic.
    # Builds a rolling picture of what the attacker is doing inside the trap.
    if HPFEED_IP_FIELD is None:
        return
    try:
        cutoff = datetime.utcnow() - timedelta(seconds=ANALYSIS_LOOKBACK_SEC)
        events = list(db.hpfeed.find({
            "channel": {"$in": list(ANALYSIS_CHANNELS)},
            "timestamp": {"$gte": cutoff},
            HPFEED_IP_FIELD: ip,
        }, {"channel": 1}))
        if not events:
            return
        db.analysis.update_one({"ip": ip}, {
            # v3.2: snapshot of the most recent window, not a cumulative counter
            # that re-counted the same events every cycle and inflated.
            "$set":         {"honeypot": honeypot, "last_seen": datetime.utcnow(),
                             "recent_events": len(events)},
            "$addToSet":    {"channels_seen": {"$each": [e["channel"] for e in events]}},
            "$setOnInsert": {"first_seen": datetime.utcnow()},
        }, upsert=True)
    except Exception as e:
        log.error(f"Analysis record failed for {ip}: {e}")

# -- BREAKOUT DETECTION (v3.1, volume-independent command sweep) ---------------
def command_sweep(db, client):
    # Scan EVERY recent cowrie.sessions IP for escalation tradecraft and block
    # any that ran post-exploit commands, regardless of session volume. This is
    # the fix for the low-and-slow gap: an attacker who stays under every
    # threshold but runs "wget ... | sh" is still caught here. Dormant while
    # HPFEED_IP_FIELD is None.
    if HPFEED_IP_FIELD is None:
        return
    cutoff = datetime.utcnow() - timedelta(seconds=BREAKOUT_LOOKBACK_SEC)
    by_ip = {}
    try:
        cursor = db.hpfeed.find(
            {"channel": "cowrie.sessions", "timestamp": {"$gte": cutoff}},
            {"payload.peerIP": 1, "payload.commands": 1, "payload.urls": 1})
        for ev in cursor:
            p = ev.get("payload", {}) or {}
            ip = p.get("peerIP")
            if not ip:
                continue
            rec = by_ip.setdefault(ip, {"cmds": [], "urls": []})
            c = p.get("commands") or []
            u = p.get("urls") or []
            if isinstance(c, list):
                rec["cmds"].extend(c)
            if isinstance(u, list):
                rec["urls"].extend(u)
    except Exception as e:
        log.error(f"Command sweep query failed: {e}")
        return
    for ip, rec in by_ip.items():
        if ip in BLOCKED or _is_internal(ip):   # v3.2: internal-IP guard
            continue
        hit = match_escalation(rec["cmds"], rec["urls"])
        if not hit:
            continue
        if ip in OBSERVING:          # escalated while under observation
            end_observation(db, ip)
        record_sighting(db, ip, "cowrie")
        n = get_sighting_count(db, ip)
        primary = hit["labels"][0]
        reason  = f"breakout - {primary} (evidence: {hit['evidence']})"
        log.warning(f"BREAKOUT [command sweep] {ip} | {', '.join(hit['labels'])} "
                    f"| evidence: {hit['evidence']}")
        synced = block_ip(db, client, ip, "cowrie", reason, "critical", hit["attack"], n)
        if synced:                   # v3.2: only heal after a real block
            self_heal("cowrie")

# -- CROSS-HONEYPOT CORRELATION (v3.1) -----------------------------------------
def multi_service_ips(db):
    # An IP touching MULTI_SERVICE_MIN or more distinct honeypots inside the
    # window is multi-service reconnaissance even if each honeypot stays below
    # its own threshold. Internal / management IPs are skipped (those are us).
    cutoff = datetime.utcnow() - timedelta(seconds=WINDOW_SEC)
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {"_id": "$source_ip",
                    "honeypots": {"$addToSet": "$honeypot"},
                    "count": {"$sum": 1}}},
    ]
    out = []
    try:
        rows = db.session.aggregate(pipeline)
    except Exception as e:
        log.error(f"Multi-service aggregation failed: {e}")
        return out
    for row in rows:
        ip = row.get("_id")
        if not ip or _is_internal(ip):
            continue
        hps = sorted(set(h for h in row.get("honeypots", []) if h))
        if len(hps) >= MULTI_SERVICE_MIN:
            out.append({"ip": ip, "honeypot": "multi-service",
                        "reason": f"multi-service recon across {hps} "
                                  f"({row['count']} events in {WINDOW_SEC}s)",
                        "severity": "high", "mode": "observe",
                        "attack": ["T1046", "T1595"]})
    return out

# -- OBSERVATION QUEUE ---------------------------------------------------------
def start_observation(db, e):
    wait = OBSERVE_SEC.get(e["severity"], 300)
    block_due = datetime.utcnow() + timedelta(seconds=wait)
    OBSERVING[e["ip"]] = {
        "honeypot": e["honeypot"], "severity": e["severity"],
        "reason": e["reason"], "attack": e["attack"], "block_due": block_due,
    }
    db.observed_ips.update_one({"ip": e["ip"]}, {"$set": {
        "ip": e["ip"], "honeypot": e["honeypot"], "severity": e["severity"],
        "reason": e["reason"], "attack": e["attack"], "block_due": block_due,
        "created_at": datetime.utcnow(), "resolved": False,
    }}, upsert=True)
    log.info(f"OBSERVING {e['ip']} on {e['honeypot']} | {e['severity']} "
             f"| block in {wait}s | {e['reason']}")

def end_observation(db, ip):
    OBSERVING.pop(ip, None)
    db.observed_ips.update_one({"ip": ip},
        {"$set": {"resolved": True, "resolved_at": datetime.utcnow()}})

def promote_observed(db, client):
    # v3.1: timer-based promotion only. Command-based early promotion (an IP
    # that escalates mid-observation) is handled by command_sweep, which runs
    # every cycle and ends observation before blocking.
    now = datetime.utcnow()
    for ip, m in list(OBSERVING.items()):   # list() so we can edit during the loop
        if now < m["block_due"]:
            continue
        n = get_sighting_count(db, ip)
        block_ip(db, client, ip, m["honeypot"], m["reason"],
                 m["severity"], m["attack"], n)
        end_observation(db, ip)

# -- TTL EXPIRY ----------------------------------------------------------------
def expire_blocks(db, client):
    now = datetime.utcnow()
    for ip in [ip for ip, m in list(BLOCKED.items()) if now >= m["expires"]]:
        unblock_ip(db, client, ip)

# -- SELF-HEAL (SSH to honeypot VM, breakout only) -----------------------------
def self_heal(honeypot):
    if not SELF_HEAL_ENABLED:
        return
    last = HEALED.get(honeypot)
    if last and (datetime.utcnow() - last).total_seconds() < HEAL_COOLDOWN_SEC:
        log.info(f"Self-heal skipped for {honeypot}: cooldown active")
        return
    path = HONEYPOT_DIRS.get(honeypot)
    if not path:
        return
    try:
        import paramiko   # imported here so a missing lib disables heal, not crash
    except ImportError:
        log.error("Self-heal needs paramiko. Install with: sudo pip3 install paramiko")
        return
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(HONEYPOT_HOST, username=HONEYPOT_USER,
                    key_filename=HONEYPOT_KEY, timeout=15)
        cmd = f"cd {path} && sudo docker compose down && sudo docker compose up -d"
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
        rc  = stdout.channel.recv_exit_status()   # wait, so the log reflects reality
        err = stderr.read().decode(errors="ignore").strip()
        ssh.close()
        if rc == 0:
            HEALED[honeypot] = datetime.utcnow()
            log.warning(f"SELF-HEAL: rebuilt {honeypot} after confirmed breakout")
        else:
            log.error(f"Self-heal command failed for {honeypot} (exit {rc}): {err[:300]}")
    except Exception as e:
        log.error(f"Self-heal failed for {honeypot}: {e}")

# -- VERDICT HANDLING (v3.1) ---------------------------------------------------
_SEV_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

def _merge_targets(per_honeypot, cross):
    # Combine per-honeypot and cross-honeypot verdicts, one per IP. The higher
    # severity verdict is the base, but the MITRE techniques from both are
    # unioned and both reasons are kept, so no intelligence is lost when two
    # rules fire on the same IP (v3.2).
    by_ip = {}
    for e in list(per_honeypot) + list(cross):
        cur = by_ip.get(e["ip"])
        if cur is None:
            by_ip[e["ip"]] = dict(e)
            continue
        union = list(cur.get("attack", []))
        for t in e.get("attack", []):
            if t not in union:
                union.append(t)
        if _SEV_ORDER.get(e["severity"], 0) > _SEV_ORDER.get(cur["severity"], 0):
            base = dict(e)
            base["reason"] = f"{e['reason']} | also: {cur['reason']}"
        else:
            base = dict(cur)
            base["reason"] = f"{cur['reason']} | also: {e['reason']}"
        base["attack"] = union
        by_ip[e["ip"]] = base
    return list(by_ip.values())

def process_verdict(db, client, e):
    # Apply one detection verdict. Immediate verdicts (threat-intel, ICS, mgmt
    # breakout) block at once. Everything else enters the observation window.
    # Command-based breakout and its self-heal are handled by command_sweep, not
    # here, so this path never self-heals.
    record_sighting(db, e["ip"], e["honeypot"])
    if e["ip"] in BLOCKED:
        return
    in_obs = e["ip"] in OBSERVING
    if e["mode"] == "immediate":
        if in_obs:
            end_observation(db, e["ip"])
        n = get_sighting_count(db, e["ip"])
        log.warning(f"TRIGGER (immediate): {e['ip']} on {e['honeypot']} "
                    f"| {e['severity']} | {e['reason']}")
        block_ip(db, client, e["ip"], e["honeypot"],
                 e["reason"], e["severity"], e["attack"], n)
    elif in_obs:
        return                                   # already waiting, leave it
    else:
        start_observation(db, e)



# -- RECONNAISSANCE INDICATORS (no block, intelligence only) -------------------
RECON_COOLDOWN_HOURS = 24   # do not republish the same recon IP within this window

def recon_sweep(db):
    """Publish low-confidence indicators for IPs that touched honeypots
    but did not cross any blocking or observation threshold. Runs once
    per IP per RECON_COOLDOWN_HOURS. No firewall rule is created."""
    cutoff = datetime.utcnow() - timedelta(seconds=WINDOW_SEC)
    cooldown_cutoff = datetime.utcnow() - timedelta(hours=RECON_COOLDOWN_HOURS)
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {
            "_id": "$source_ip",
            "honeypots": {"$addToSet": "$honeypot"},
            "count": {"$sum": 1},
            "ports": {"$addToSet": "$destination_port"},
        }},
    ]
    try:
        rows = list(db.session.aggregate(pipeline))
    except Exception as e:
        log.error(f"recon_sweep aggregate failed: {e}")
        return
    for row in rows:
        ip = row.get("_id")
        if not ip or _is_internal(ip):
            continue
        if ip in BLOCKED or ip in OBSERVING:
            continue
        # skip if already published recon for this IP recently
        try:
            recent = db.published_recon.find_one({
                "ip": ip, "published_at": {"$gte": cooldown_cutoff}
            })
            if recent:
                continue
        except Exception:
            continue
        honeypots = row.get("honeypots", [])
        count = row.get("count", 1)
        honeypot = honeypots[0] if honeypots else "unknown"
        reason = f"reconnaissance: {count} session(s) on {', '.join(honeypots)}"
        attack = ["T1595"]   # Active Scanning
        geo = geoip_lookup(ip)
        conf = min(40, 20 + count)   # low confidence: 21-40
        expires = datetime.utcnow() + timedelta(days=3)
        evidence = gather_evidence(db, ip, honeypot)
        try:
            publish_stix(ip, honeypot, reason, "low", geo, expires, attack, conf, evidence)
        except Exception as e:
            log.error(f"recon_sweep publish failed for {ip}: {e}")
            continue
        try:
            db.published_recon.update_one({"ip": ip}, {"$set": {
                "ip": ip, "honeypots": honeypots, "count": count,
                "published_at": datetime.utcnow(),
            }}, upsert=True)
        except Exception as e:
            log.error(f"recon_sweep record failed for {ip}: {e}")
        log.info(f"RECON indicator published for {ip} | {count} session(s) on {', '.join(honeypots)}")


# -- MAIN ----------------------------------------------------------------------
def main():
    log.info("Aegis-Bridge v3.4 starting...")
    db = get_db()
    init_collections(db)
    rebuild_registry(db)
    rebuild_observing(db)
    load_threat_intel()
    client = gcp_client()
    log.info("Running -- watching Cowrie, Dionaea, Conpot")
    while True:
        try:
            if time.time() - _TI_LAST_LOAD[0] > THREAT_INTEL_REFRESH_SEC:
                load_threat_intel()

            expire_blocks(db, client)
            promote_observed(db, client)     # timer-based blocks
            command_sweep(db, client)        # volume-independent command breakout

            # keep building analysis for every IP still under observation
            for ip, m in list(OBSERVING.items()):
                record_analysis(db, ip, m["honeypot"])

            # per-honeypot rules + cross-honeypot correlation, merged and deduped
            for e in _merge_targets(hot_ips(db), multi_service_ips(db)):
                process_verdict(db, client, e)
            recon_sweep(db)   # publish low-confidence indicators for below-threshold IPs
        except Exception as e:
            # v3.4: a single bad cycle (DB blip, transient API error) is logged
            # and skipped. The process stays up and retries on the next poll.
            log.error(f"Poll cycle failed, continuing: {e}")

        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
