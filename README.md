# Aegis-Trap: HoneyNet

**A cloud-native deception honeynet that turns passive honeypot data into automated, standards-based threat intelligence.**

Graduation Project, Networks and Cyber Security Program
Faculty of Computing & AI, Cairo University, Academic Year 2025-2026

---

## Overview

Traditional cybersecurity is mostly reactive: defenses detect known threats after they happen and produce large volumes of low-context alerts. **Aegis-Trap** takes a different approach. It deploys decoy systems on Google Cloud Platform (GCP) that no legitimate user has any reason to touch, so every interaction is high-confidence and low-noise. It then automatically classifies attackers, blocks them at the cloud firewall, and publishes what it learned as shareable threat intelligence.

At the center of the system is the **Aegis-Bridge**, a custom Python automation component that:

- Monitors the honeypot attack database continuously (every 30 seconds)
- Classifies attacks using a rule-based engine and a **43-pattern command detection database** mapped to **MITRE ATT&CK** techniques
- Creates **GCP firewall deny rules** automatically to block confirmed attackers
- Uses a **staged response**: critical attackers are blocked immediately, lower-severity ones are observed first to capture more behavioral intelligence
- Publishes an enriched **STIX 2.1** indicator for every attacker to a **TAXII 2.1** server
- Rebuilds compromised honeypot containers automatically (self-healing)

## Key Features

- **Three honeypot types** covering different attack surfaces (SSH/Telnet, Windows services, industrial control systems)
- **Deterministic, explainable detection**: every block decision traces back to a specific rule (no black-box ML)
- **Staged response** with configurable observation windows and block lifetimes
- **Cross-honeypot correlation**: IPs touching two or more honeypot types are flagged as multi-service reconnaissance
- **Enriched STIX 2.1 indicators**: GeoIP location, network ownership (ASN), MITRE ATT&CK tags, confidence score, and an evidence bundle (captured commands, attempted credentials, behavior labels)
- **Reconnaissance indicators**: attackers below every blocking threshold still produce a low-confidence indicator, so no malicious contact goes unrecorded
- **Persistent state**: blocks and the observation queue survive bridge restarts (stored in MongoDB)
- **Automatic block expiry** via TTL, with a full audit trail kept in the database
- **Web dashboard** with live filters (severity, IP, honeypot) and expandable evidence cards

## Architecture

The system runs on two GCP virtual machines inside a custom VPC (`aegis-vpc`), split into two isolated subnets:

| Component | Subnet | Role |
|---|---|---|
| **Control VM** (`aegis-control`) | Management `10.0.0.0/24` | CHN management hub, MongoDB, Aegis-Bridge, OpenTAXII server, Nginx gate, dashboard |
| **Honeypot VM** (`aegis-honeypot`) | Honeypot `10.0.1.0/24` | Cowrie, Dionaea, and Conpot in Docker containers |

A permanent firewall deny rule blocks all traffic from the honeypot subnet to the management subnet. A higher-priority rule opens only the three ports the data pipeline needs (hpfeeds, MongoDB, TLS). Even if an attacker compromises a honeypot container, the management infrastructure stays unreachable.

### Data flow

```
 Attacker
    │
    ▼
┌─────────────────────────────────────────┐
│ Honeypot VM (10.0.1.0/24)               │
│  Cowrie   → SSH / Telnet                │
│  Dionaea  → SMB, FTP, MySQL, ...        │
│  Conpot   → Modbus, SNMP (ICS/SCADA)    │
└──────────────────┬──────────────────────┘
                   │ hpfeeds3
                   ▼
┌─────────────────────────────────────────┐
│ Control VM (10.0.0.0/24)                │
│  CHN hub + Mnemosyne → MongoDB          │
│          │                              │
│          ▼  polled every 30 s           │
│  ┌──────────────────┐                   │
│  │   Aegis-Bridge   │                   │
│  │ classify → decide│                   │
│  └───┬──────────┬───┘                   │
│      │          │                       │
│      ▼          ▼                       │
│  GCP Firewall   STIX 2.1 indicator      │
│  deny rule          │                   │
│                     ▼                   │
│        Nginx gate → OpenTAXII (TAXII 2.1)│
│                     │                   │
│                     ▼                   │
│        Web dashboard / SIEM / SOC tools │
└─────────────────────────────────────────┘
```

### The honeypots

| Honeypot | Emulates | Detection threshold |
|---|---|---|
| **Cowrie** | SSH and Telnet services | 10 sessions / 60 s (high background noise from scanners) |
| **Dionaea** | Windows services: SMB, FTP, MySQL, and others | 5 sessions / 60 s |
| **Conpot** | ICS/SCADA protocols (Modbus, SNMP) | Any contact is critical (no legitimate internet traffic) |

### Staged response

| Severity | Response | Observation window | Block TTL |
|---|---|---|---|
| Critical | Immediate block | 0 s | 30 days |
| High | Observe, then block | 180 s | 14 days |
| Medium | Observe, then block | 300 s | 7 days |
| Low | Reconnaissance indicator only (no block) | n/a | n/a |

If an attacker under observation types a dangerous command, the bridge ends the observation early and escalates to an immediate critical block.

### Command detection database

43 regular-expression patterns in 12 behavioral families, each mapped to MITRE ATT&CK, including: onward connection (T1021), tool transfer (T1105), botnet signatures and payload execution (T1059), obfuscation (T1140), cryptomining (T1496), persistence (T1053 / T1098 / T1136), defense evasion (T1562), kernel module loading (T1547.006), log clearing (T1070), and destruction (T1485). Patterns require real attack syntax rather than matching isolated keywords, so ordinary reconnaissance commands such as `ls`, `whoami`, or `uname -a` do not trigger a block.

## Technology Stack

| Category | Technology |
|---|---|
| Cloud | Google Cloud Platform (VMs, VPC, Compute Firewall API) |
| Containers | Docker + Docker Compose v2 |
| Honeypot management | Community Honey Network (CHN) v1.9.1, hpfeeds3 |
| Honeypots | Cowrie, Dionaea, Conpot |
| Database | MongoDB |
| Automation | Python 3 (`google-cloud-compute`, `pymongo`, `stix2`, `geoip2`, `requests`) |
| Enrichment | MaxMind GeoLite2 (City + ASN) |
| Threat intel | STIX 2.1, OpenTAXII (TAXII 2.1), Gunicorn |
| Gateway / UI | Nginx, single-page HTML dashboard |
| OS / services | Ubuntu 22.04 LTS, systemd |

## Repository Structure

```
.
├── aegis_bridge.py                      # The Aegis-Bridge automation component
├── docs/
│   └── Final_Graduation_Document.pdf    # Full project documentation (77 pages)
├── requirements.txt
├── .env.example
└── README.md
```

## Setup

> **Note:** Aegis-Trap is designed for a specific two-VM GCP deployment. The steps below outline the full setup. See the [project documentation](docs/Final_Graduation_Document.pdf) (Chapters 4 and 5) for the detailed architecture, firewall rules, and configuration.

### Prerequisites

- A Google Cloud project with billing or free-trial credit enabled
- A service account with permission to manage Compute Engine firewall rules, and its JSON key
- A free [MaxMind](https://www.maxmind.com/) account to download the GeoLite2 City and ASN databases
- Basic Linux, Docker, and GCP familiarity

### 1. Provision the infrastructure

1. Create a custom VPC (`aegis-vpc`) with two subnets: `10.0.0.0/24` (management) and `10.0.1.0/24` (honeypots).
2. Create two Ubuntu 22.04 VMs (the project used `e2-standard-2`): a **control VM** in the management subnet and a **honeypot VM** in the honeypot subnet.
3. Configure firewall rules:
   - Allow only hpfeeds (10000), MongoDB (27017), and TLS (443) from the honeypot subnet to the management subnet.
   - Deny all other honeypot-to-management traffic (lower priority than the allow rule).
   - Expose only the honeypot service ports you want attackers to reach. Keep management ports private.

### 2. Deploy the honeypots and data pipeline

1. On the control VM, install Docker and deploy the Community Honey Network hub (CHN v1.9.1).
2. On the honeypot VM, deploy the Cowrie, Dionaea, and Conpot sensor containers, pointing each at the control VM's private IP for the CHN server and hpfeeds broker.
3. Verify that attack sessions are arriving in MongoDB (the `mnemosyne` database) **before** installing the bridge.

### 3. Set up the TAXII server and dashboard

1. Install OpenTAXII in an isolated Python virtual environment and run it with Gunicorn as a systemd service.
2. Configure Nginx to listen on port 8080: `/taxii2/` is proxied to OpenTAXII (POST requires Basic Auth, GET is open), and `/` serves the static dashboard page.
3. Create a TAXII collection and note its URL.

### 4. Install the Aegis-Bridge

On the control VM:

```bash
# Clone the repository
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

# Install dependencies
pip install -r requirements.txt

# Place secrets and data files (never commit these)
sudo mkdir -p /opt/aegis-bridge/geoip
sudo cp gcp-key.json /opt/aegis-bridge/gcp-key.json
sudo cp GeoLite2-City.mmdb GeoLite2-ASN.mmdb /opt/aegis-bridge/geoip/
sudo cp honeypot_key /opt/aegis-bridge/honeypot_key   # only if self-heal is enabled
```

Set the required environment variables (see `.env.example`):

| Variable | Required | Description |
|---|---|---|
| `TAXII_USER` | Yes | Basic-auth username for publishing to the TAXII server |
| `TAXII_PASSWORD` | Yes | Basic-auth password for publishing |
| `TAXII_URL` | No | TAXII collection objects endpoint (defaults to localhost:8080) |
| `GCP_CREDS_FILE` | No | Path to the service account key (default `/opt/aegis-bridge/gcp-key.json`) |

Then edit the configuration block at the top of `aegis_bridge.py` for your environment: `PROJECT` (your GCP project ID), `NETWORK`, `MGMT_SUBNET`, `HONEYPOT_HOST`, `HONEYPOT_USER`, `HONEYPOT_DIRS`, and the detection thresholds. Set `SELF_HEAL_ENABLED = False` until blocking has been verified and the SSH key is in place.

### 5. Run it

Test in the foreground first:

```bash
python3 aegis_bridge.py
```

Then run it permanently as a systemd service (example unit):

```ini
[Unit]
Description=Aegis-Bridge
After=network.target

[Service]
EnvironmentFile=/etc/aegis-bridge.env
ExecStart=/usr/bin/python3 /opt/aegis-bridge/aegis_bridge.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Open `http://<control-vm-ip>:8080/` to view the live threat-intelligence dashboard.

## Testing and Results

The system was validated against nine test cases, **all of which passed**:

| ID | Test | Detection path | Block time |
|---|---|---|---|
| TC-01 | Command breakout | `command_sweep` | < 62 s |
| TC-02 | Volume threshold | `hot_ips` + staged response | 180-210 s |
| TC-03 | Credential flooding | auth-count threshold | 180-210 s |
| TC-04 | ICS/SCADA contact | high-severity honeypot rule | < 62 s |
| TC-05 | Cross-honeypot scanning | `multi_service_ips` | 180-210 s |
| TC-06 | Reconnaissance indicator | `recon_sweep` (no block) | n/a |
| TC-07 | Threat-intel denylist block | known-bad rule | < 62 s |
| TC-08 | Automatic block expiry | `expire_blocks` (TTL) | < 30 s |
| TC-09 | Restart state persistence | registry / queue rebuild | n/a |

Selected performance figures: session-to-database latency under 2 seconds, GCP rule creation in 2-5 seconds, STIX publication in under 1 second, and block and observation-queue state rebuilt in under 1 second after a restart.

## Known Limitations

- Dionaea malware-capture is integrated but was not triggered by a real payload during the testing period.
- The threat-intelligence denylist is implemented but empty, because no external feeds were integrated.
- The medium-severity path (database-port probes) is implemented and unit-tested, but those ports were not exposed in the live deployment.

## Future Work

1. **Malware hash indicators**: compute MD5/SHA-256 for payloads captured by Dionaea and publish STIX File indicators for EDR/SIEM use.
2. **Denylist population**: integrate public feeds such as Abuse.ch or Emerging Threats for immediate blocking of known-bad IPs.
3. **Multi-region deployment**: add honeypot sensors in other GCP regions or cloud providers to compare attacker behavior geographically.

## Security Notice

This project deliberately exposes vulnerable-looking services to the internet. Deploy it only in an isolated cloud project you control, keep the management subnet firewalled from the honeypot subnet, and never commit credentials, service account keys, SSH keys, or GeoLite2 databases to version control. GeoLite2 data is subject to MaxMind's license terms.

## Team

| Name |
|---|
| Mohamed Yasser Zakaria |
| Omar Rami Mohammad |
| Moaz Mohamed Fathy |
| Omar Nader Ahmed |

**Supervisor:** Dr. Shaimaa Mosaad
Faculty of Computing & AI, Cairo University, Networks and Cyber Security Program

## Acknowledgments

Built on open-source projects: [Community Honey Network](https://github.com/CommunityHoneyNetwork/communityhoneynetwork), [Cowrie](https://github.com/cowrie/cowrie), [Dionaea](https://github.com/DinoTools/dionaea), [Conpot](https://github.com/mushorg/conpot), [OpenTAXII](https://github.com/eclecticiq/OpenTAXII), and [MITRE ATT&CK](https://attack.mitre.org/).

## License

Add your chosen license here (for example, MIT) and include a `LICENSE` file in the repository.
