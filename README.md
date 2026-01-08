# Ironclad Anti-DDoS & Anti-Bot Stack

**Traefik + CrowdSec + Anubis + Grafana (LGT Stack)**

> **Automated, resource-efficient protection for multi-domain Docker environments and legacy web servers.**

---

## Table of Contents

- [Introduction](#introduction)
- [Architecture](#architecture)
- [Components](#components)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Configuration Reference](#configuration-reference)
- [Operations Manual](#operations-manual)
- [Apache Legacy Configuration](#apache-legacy-configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Introduction

High-traffic environments require robust defense mechanisms that do not compromise performance. This project provides a production-ready infrastructure stack designed to protect hundreds of domains running on a single Docker host or hybrid environments.

It integrates industry-standard components to provide a multi-layered defense strategy:

1. **Traefik**: High-performance edge routing and SSL termination.
2. **CrowdSec**: Collaborative Intrusion Prevention System (IPS) leveraging global threat intelligence.
3. **Anubis**: Custom "ForwardAuth" middleware implementing Proof-of-Work (PoW) challenges to mitigate sophisticated bot attacks.
4. **Alloy & Loki**: Modern, resource-efficient log aggregation and processing pipeline.
5. **Grafana**: Centralized observability and analytics.

The system is fully automated. A Python orchestrator (`generate-config.py`) dynamically compiles complex Traefik configurations from a simple CSV inventory, ensuring consistent security policies across all services.

---

## Architecture

The stack operates on a "Defense in Depth" principle, filtering traffic through a precise middleware chain (The "Golden Chain") before it ever reaches the backend application.

```mermaid
graph TD
    classDef user fill:#e0e0e0,stroke:#333,stroke-width:2px;
    classDef traefik fill:#8cb5ff,stroke:#333,stroke-width:2px;
    classDef security fill:#ff9999,stroke:#333,stroke-width:2px;
    classDef app fill:#99ff99,stroke:#333,stroke-width:2px;
    classDef observ fill:#ffffcc,stroke:#333,stroke-width:2px;

    User((User/Bot)):::user -->|HTTPS :443| T_Entry[Traefik EntryPoint]:::traefik

    subgraph "Traefik Middleware Chain"
        T_Entry --> MW_CS{1. CrowdSec Check}:::security
        MW_CS -- Blocked IP --> Block[403 Forbidden]:::security
        MW_CS -- Allowed --> MW_Sec["2. Security Headers"]:::traefik
        MW_Sec --> MW_RL["3. Rate Limiting"]:::traefik
        MW_RL --> MW_Comp["4. Compression"]:::traefik
        MW_Comp --> MW_Auth{5. Auth Required?}:::traefik
    end

    subgraph "Anubis Logic (Bot Defense)"
        MW_Auth -- No (Public) --> Backend
        MW_Auth -- Yes (Protected) --> Check_Auth{"Valid Cookie?"}:::security
        Check_Auth -- Yes --> Backend[Backend Service]:::app
        Check_Auth -- No --> Anubis_Svc[Anubis Service]:::security
        Anubis_Svc -->|Challenge Page| User
        Anubis_Svc -.->|Session State| Redis[(Redis/Valkey)]:::app
    end

    subgraph "Observability Pipeline"
        Docker_Sock(Docker Socket) -->|Discovery| Alloy:::observ
        Alloy -->|Filter & Push| Loki[(Loki DB)]:::observ
        Loki -->|Query| Grafana[Grafana]:::observ
        
        Traefik_Logs[Traefik Logs] -.->|Analysis| CrowdSec[CrowdSec Engine]:::security
        CrowdSec -.->|Bouncer API| MW_CS
    end
```

---

## Components

### Traefik (Edge Router)

Traefik serves as the ingress controller and the first line of defense.

- **SSL Termination**: Automatically handles Let's Encrypt certificates (staging or production).
- **Bouncer Integration**: Uses the CrowdSec Traefik Bouncer plugin to enforce IP bans at the edge.
- **Dynamic Configuration**: Reloads rules on-the-fly without downtime.

### The Golden Chain (Middleware Pipeline)

Every request entering the stack passes through a sequential chain of middlewares designed to filter, protect, and optimize traffic before it reaches your applications.

| Order | Middleware | Purpose | Security Benefit |
|:---:|:---|:---|:---|
| 1 | **CrowdSec Check** | Consults the local CrowdSec database for the client IP. | **Instant Mitigation**: Blocks known malicious IPs (botnets, scanners) at the entry point. |
| 2 | **Security Headers** | Injects recommended browser security headers (HSTS, XSS, Frame-Options). | **Client Hardening**: Protects users from clickjacking and protocol downgrade attacks. |
| 3 | **Global Buffering** | Reads the entire request into memory before passing it to the backend. | **Slowloris Defense**: Prevents attackers from exhausting server sockets by sending data very slowly. |
| 4 | **Rate Limiting** | Throttles requests based on average and burst thresholds (global or per-domain). | **Flood Protection**: Mitigates automated scraping and brute-force attempts. |
| 5 | **Concurrency** | Limits the number of simultaneous active connections per client. | **Resource Preservation**: Ensures one heavy/malicious user cannot consume all backend worker threads. |
| 6 | **ForwardAuth (Anubis)** | (Optional) Intercepts requests to protected routes to verify or challenge the session. | **Bot Defense**: Forces suspicious or unauthenticated traffic to solve a Proof-of-Work challenge. |
| 7 | **Compression** | Dynamically compresses response bodies (Gzip) for supported clients. | **Performance**: Reduces bandwidth usage and improves load times for end-users. |

#### Specialized Middlewares

- **`apache-forward-headers`**: Injects `X-Forwarded-Proto: https` headers. Critical for legacy apps like WordPress to detect they are behind an SSL proxy.
- **`redirect-regex`**: Handles 301/302 redirections defined in `domains.csv` with optimized regex matching.
- **`anubis-assets-stripper`**: Internal helper to clean request paths for Anubis static assets, ensuring the backend receives clean URIs.

### CrowdSec (IPS)

CrowdSec is a collaborative Intrusion Prevention System that analyzes behavior to detect attacks (brute force, scanning, bot spam).

- **Log Analysis**: Reads logs via the Docker socket, matching patterns against community scenarios.
- **Community Blocklist**: Automatically shares and receives ban lists from the global network.
- **Remediation**: Instructs Traefik to ban IPs (403 Forbidden) via the bouncer API.

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CrowdSec Engine                        │
├─────────────────────────────────────────────────────────────┤
│  Parsers          │  Scenarios         │  LAPI (REST API)   │
│  ├─ traefik       │  ├─ http-probing   │  ├─ Decisions DB   │
│  ├─ nginx         │  ├─ http-crawlers  │  ├─ Bouncer API    │
│  └─ syslog        │  └─ brute-force    │  └─ Central API    │
└─────────────────────────────────────────────────────────────┘
         ▲                    │                    │
         │ Logs               │ Alerts             ▼
    ┌────┴────┐          ┌────┴────┐       ┌──────────────┐
    │ Traefik │          │ Console │       │   Bouncer    │
    │  Logs   │          │ CrowdSec│       │  (Traefik)   │
    └─────────┘          └─────────┘       └──────────────┘
```

#### Key Concepts

| Concept | Description |
|---------|-------------|
| **Parser** | Extracts structured data from logs (IP, user-agent, status codes) |
| **Scenario** | Defines malicious behavior patterns (e.g., 10 failed logins in 1 minute) |
| **Decision** | The remediation action (ban, captcha, throttle) with duration |
| **Bouncer** | Component that enforces decisions (Traefik plugin in our case) |
| **LAPI** | Local API that stores decisions and communicates with bouncers |
| **CAPI** | Central API for sharing threat intelligence with the community |

#### Installed Collections

This stack comes pre-configured with the following CrowdSec collections:

| Collection | Description |
|------------|-------------|
| `crowdsecurity/traefik` | Parsers and scenarios for Traefik access logs |
| `crowdsecurity/http-cve` | Detection of CVE exploits in HTTP requests |
| `crowdsecurity/sshd` | SSH brute-force detection |
| `crowdsecurity/whitelist-good-actors` | Whitelists known good bots (Google, Bing, etc.) |
| `crowdsecurity/base-http-scenarios` | Common HTTP attack patterns (path traversal, SQL injection) |
| `crowdsecurity/http-dos` | HTTP flood and DDoS detection |

#### Aggressive Ban Policy

Custom profiles in `config/crowdsec/profiles.yaml` enforce longer ban durations:

| Profile | Trigger | Ban Duration |
|---------|---------|--------------|
| Repeat Offender | IP triggers >5 events | **7 days** |
| Standard Attack | Any IP-based alert | **24 hours** (default is 4h) |
| Range Attack | Subnet-based alert | **48 hours** |

> [!TIP]
> You can customize ban durations by editing `config/crowdsec/profiles.yaml`.

#### CrowdSec Console (Optional)

You can enroll your instance in the [CrowdSec Console](https://app.crowdsec.net) to gain:
- Centralized view of alerts across multiple servers
- Access to premium blocklists
- Visual dashboards of attack trends

To enable it, provide your enrollment key during setup (`config/crowdsec/console-enrollment-key` is not used, use the interactive script or `.env`).

### Anubis (Bot Defense)

Anubis is a specialized "ForwardAuth" middleware for mitigating bots.

- **Mechanism**: When a user accesses a protected route without a valid session, Anubis intercepts the request.
- **Challenge**: Presents a cryptographic Proof-of-Work (PoW) challenge the client must solve.
- **Isolation**: One Anubis instance is deployed per TLD to respect "Same-Site" cookie policies.

#### Custom Assets

Anubis supports custom styling and images. The project includes default assets (with `.dist` extension) that are automatically used if you don't provide custom versions.

**Asset files:**

| File | Location | Description |
|------|----------|-------------|
| `custom.css` | `config/anubis/assets/` | Custom stylesheet for the challenge page |
| `happy.webp` | `config/anubis/assets/static/img/` | Image shown on successful challenge |
| `pensive.webp` | `config/anubis/assets/static/img/` | Image shown while solving challenge |
| `reject.webp` | `config/anubis/assets/static/img/` | Image shown on failed challenge |

**How it works:**

1. Default assets are stored with `.dist` extension (e.g., `custom.css.dist`)
2. When `start.sh` runs, it checks for each asset file
3. If a custom version exists (without `.dist`), it uses your custom file
4. If no custom version exists, it copies the default `.dist` file

**To customize:**

```bash
# Example: Create custom CSS
cp config/anubis/assets/custom.css.dist config/anubis/assets/custom.css
# Edit config/anubis/assets/custom.css with your changes

# Example: Use custom images
cp /path/to/your/happy.webp config/anubis/assets/static/img/happy.webp
```

> [!TIP]
> Your custom assets are git-ignored, so they won't be overwritten by project updates.

### Redis (State Management)

A high-performance Valkey (Redis-compatible) instance acts as the session store for Anubis.

- **Configuration**: Tuned for cache usage (`allkeys-lru`).
- **Persistence**: Uses AOF with per-second synchronization.

### Observability Stack (Alloy, Loki, Grafana)

- **Alloy**: OpenTelemetry-compatible agent that discovers Docker containers and forwards logs to Loki.
- **Loki**: Log aggregation system optimized for efficiency.
- **Grafana**: Visual dashboards for traffic analysis and attack monitoring.

### Stack-Watchdog (Monitoring)

A lightweight utility service that monitors the stack and sends Telegram alerts.

| Script | Interval | Function |
|--------|----------|----------|
| `check-certs.sh` | 24 hours | Scans `acme.json` for certificates close to expiration |
| `check-dns.sh` | 6 hours (configurable) | Verifies all domains point to the correct IP |
| `check-crowdsec.sh` | 1 hour (configurable) | Monitors CrowdSec health, LAPI status, and bouncer connectivity |

### Auxiliary Tools

- **Dozzle**: Real-time log viewer for all containers (`https://dozzle.<domain>`).
- **ctop**: Interactive container monitoring (run manually with `docker compose -f docker-compose-tools.yaml run --rm ctop`).
- **Anubis-Assets**: Nginx server for local Anubis static assets.

---

## Project Structure

```
.
├── .env.dist                              # Environment template
├── domains.csv.dist                       # Domain inventory template
├── generate-config.py                     # Configuration generator
├── initialize-env.sh                      # Interactive setup wizard
├── start.sh                               # Deployment script
├── stop.sh                                # Shutdown script
│
├── config/
│   ├── alloy/                             # Alloy log collector config
│   │   └── config.alloy
│   ├── anubis/                            # Anubis bot defense
│   │   └── assets/                        # Static assets (images, CSS)
│   ├── crowdsec/                          # CrowdSec IPS
│   │   ├── acquis.yaml
│   │   ├── profiles.yaml
│   │   └── parsers/                       # Custom parsers (IP whitelist)
│   ├── grafana/                           # Grafana datasources
│   │   └── config.yaml
│   ├── loki/                              # Loki log storage
│   │   └── config.yaml
│   ├── redis/                             # Redis/Valkey session store
│   │   └── redis.conf
│   ├── stack-watchdog/                    # Monitoring scripts
│   │   ├── Dockerfile
│   │   ├── check-certs.sh
│   │   ├── check-crowdsec.sh
│   │   └── check-dns.sh
│   └── traefik/                           # Traefik configuration
│       ├── traefik.yaml.template           # Static config template
│       └── dynamic-config/                # Generated routers/middlewares
│
└── Docker Compose Files:
    ├── docker-compose-traefik-crowdsec-redis.yaml   # Core infrastructure
    ├── docker-compose-tools.yaml                     # Tools & monitoring
    ├── docker-compose-grafana-loki-alloy.yaml        # Observability stack
    ├── docker-compose-anubis-base.yaml               # Anubis template
    └── docker-compose-anubis-generated.yaml          # Auto-generated Anubis instances
```

---

## Installation & Setup

### 1. Prerequisites

- **Docker Engine** & **Docker Compose** (v2.x+)
- **Python 3** with required modules:
  ```bash
  # Debian/Ubuntu
  sudo apt install python3-yaml python3-tldextract
  
  # macOS
  pip3 install pyyaml tldextract
  ```
- Ports `80` and `443` free on the host machine.

### 2. Environment Initialization

Run the interactive setup wizard:

```bash
chmod +x initialize-env.sh
./initialize-env.sh
```

> [!NOTE]
> **Auto-Initialization**: If you run `./start.sh` without a `.env` file, the system will automatically launch this wizard for you.

The wizard will prompt for:
- **Admin credentials**: Applied to Grafana (plaintext) and hashed (bcrypt) for Traefik/Dozzle dashboards.
- **Domain & Timezone**: Your primary domain and server timezone.
- **Telegram alerts** (optional): Bot token and chat ID for notifications.
- **ACME environment**: Staging (testing) or Production (real certificates).

### 3. Domain Configuration

Copy and edit the domain inventory:

```bash
cp domains.csv.dist domains.csv
```

**Columns:**

| Column | Description | Example |
|--------|-------------|---------|
| `domain` | Public FQDN | `app.example.com` |
| `redirection` | (Optional) 301 redirect target | `www.example.com` |
| `service` | Docker container name or `apache-host` | `wordpress` |
| `anubis_subdomain` | Subdomain for auth portal | `auth` → `auth.example.com` |
| `rate_limit` | Requests/second (average) | `50` |
| `burst` | Maximum burst size | `100` |
| `concurrency` | Max simultaneous connections | `20` |

### 4. Deployment

```bash
./start.sh
```

This script:
1. Synchronizes environment: Compares `.env` with `.env.dist`. It appends any missing variables from the template while preserving your current values and custom additions.
2. Auto-Initialize: Runs `./initialize-env.sh` if the `.env` file is completely missing.
3. Generates `traefik-generated.yaml` from template
4. Runs `generate-config.py` to create routes
5. Creates required networks
6. Boots CrowdSec/Redis first (security layer)
7. Waits for CrowdSec health check
8. Registers the bouncer API key
9. Deploys all remaining services

---

## Configuration Reference

### Environment Variables (`.env`)

#### General

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMAIN` | Primary domain for admin dashboards | - |
| `TZ` | Server timezone | `Europe/Madrid` |

#### Anubis

| Variable | Description | Default |
|----------|-------------|---------|
| `ANUBIS_DIFFICULTY` | PoW challenge complexity (1-5) | `4` |
| `ANUBIS_REDIS_PRIVATE_KEY` | Key for session signing | Auto-generated |
| `ANUBIS_CPU_LIMIT` | CPU limit per instance | `0.10` |
| `ANUBIS_MEM_LIMIT` | Memory limit per instance | `32M` |

#### Redis

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_PASSWORD` | Redis authentication password | Auto-generated |

#### CrowdSec

| Variable | Description | Default |
|----------|-------------|---------|
| `CROWDSEC_API_KEY` | Bouncer API key | Auto-generated |
| `CROWDSEC_DISABLE` | Set to `true` to completely disable the CrowdSec firewall plugin | `false` |
| `CROWDSEC_UPDATE_INTERVAL` | Blocklist refresh interval from LAPI (seconds) | `60` |
| `CROWDSEC_ENROLLMENT_KEY` | Optional key to connect instance to CrowdSec Console | - |
| `CROWDSEC_COLLECTIONS` | Space-separated list of CrowdSec collections to load | See [Installed Collections](#installed-collections) |
| `CROWDSEC_WHITELIST_IPS` | Comma-separated list of trusted IPs/CIDRs to bypass detection | - |

> [!TIP]
> **IP Whitelisting**: Use `CROWDSEC_WHITELIST_IPS` to prevent false positives from trusted IPs (e.g., office networks, monitoring services). Example: `192.168.1.1,10.0.0.0/8,203.0.113.50`. The whitelist is regenerated on each `./start.sh` run.

> [!WARNING]
> **Changing Collections**: If you modify `CROWDSEC_COLLECTIONS`, you may need to remove CrowdSec's data volumes for the changes to take effect:
> ```bash
> docker compose -f docker-compose-traefik-crowdsec-redis.yaml down crowdsec
> docker volume rm $(docker volume ls -q | grep crowdsec)
> ./start.sh
> ```
> This will reset all CrowdSec state including current bans. Consider exporting decisions first with `docker exec crowdsec cscli decisions list -o json`.

#### Traefik

| Variable | Description | Default |
|----------|-------------|---------|
| `TRAEFIK_LISTEN_IP` | IP to bind ports 80/443 | `0.0.0.0` |
| `TRAEFIK_GLOBAL_RATE_AVG` | Default rate limit (req/s) | `60` |
| `TRAEFIK_GLOBAL_RATE_BURST` | Default burst size | `120` |
| `TRAEFIK_GLOBAL_CONCURRENCY` | Default concurrent connections | `25` |
| `TRAEFIK_HSTS_MAX_AGE` | HSTS header duration (seconds) | `31536000` |
| `TRAEFIK_ACME_EMAIL` | Let's Encrypt contact email | - |
| `TRAEFIK_ACME_ENV_TYPE` | `staging` or `production` (ignored if `TRAEFIK_ACME_CA_SERVER` is set) | `staging` |
| `TRAEFIK_ACME_CA_SERVER` | Optional direct URL override for the ACME server | - |
| `TRAEFIK_DASHBOARD_AUTH` | Basic auth for dashboard (htpasswd format) | - |
| `TRAEFIK_BLOCKED_PATHS` | Comma-separated list of path prefixes to block globally (regex supported) | - |
| `TRAEFIK_FRAME_ANCESTORS` | Comma-separated list of domains allowed to embed this site in an iframe | - |

#### Traefik Timeouts

Legacy applications or slow backends may require adjusted timeouts. We provide two variables to control the entire pipeline (**Client** ↔ **Traefik** ↔ **Backend**).

| Variable | Default | Function |
|----------|---------|----------|
| `TRAEFIK_TIMEOUT_ACTIVE` | `60` | **Active Connection Limit** (Seconds).<br>Controls `readTimeout`, `writeTimeout` (EntryPoints) and `responseHeaderTimeout` (Transport).<br><br>• **readTimeout**: Max time to read the entire request (headers + body) from the client.<br>• **writeTimeout**: Max time to write the response to the client. This is the effective "Time To First Byte" limit for your apps.<br>• **responseHeaderTimeout**: Max time Traefik waits for the backend to send response headers. |
| `TRAEFIK_TIMEOUT_IDLE` | `90` | **Idle Connection Buffer** (Seconds).<br>Controls `idleTimeout` (EntryPoints) and `idleConnTimeout` (Transport).<br><br>It is recommended to keep this value **higher** than the active timeout to avoid race conditions where a connection is closed just as a new request arrives.<br><br>• **idleTimeout**: Max time to keep an inactive connection open (Keep-Alive) waiting for a new request.<br>• **idleConnTimeout**: Max time an idle connection to the backend is kept open for reuse. |

> [!IMPORTANT]
> **Synchronization**: These variables update the configuration at **both ends** of the proxy.
> If your application takes 70 seconds to respond, you must increase **`TRAEFIK_TIMEOUT_ACTIVE`** to at least 75s. Setting only one side (e.g., Transport) would be useless if the other side (EntryPoint) cuts the connection at 60s.

#### Grafana

| Variable | Description | Default |
|----------|-------------|---------|
| `GRAFANA_ADMIN_USER` | Grafana admin username | - |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin password | - |

#### Stack-Watchdog Alerts

| Variable | Description | Default |
|----------|-------------|---------|
| `WATCHDOG_TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | - |
| `WATCHDOG_TELEGRAM_RECIPIENT_ID` | Chat/group ID for alerts | - |
| `WATCHDOG_CERT_DAYS_WARNING` | Certificate expiration threshold (days) | `10` |
| `WATCHDOG_DNS_CHECK_INTERVAL` | DNS verification interval (seconds) | `21600` (6h) |
| `WATCHDOG_CROWDSEC_CHECK_INTERVAL` | CrowdSec check interval (seconds) | `3600` (1h) |

---

## Operations Manual

### Service Management

| Command | Description |
|---------|-------------|
| `./start.sh` | Deploy/update the stack |
| `./stop.sh` | Stop all containers |
| `docker compose -f docker-compose-tools.yaml run --rm ctop` | Interactive container monitor |

### Security Operations (CrowdSec)

All CrowdSec commands use `cscli` (CrowdSec CLI) inside the container:

```bash
docker exec crowdsec cscli <command>
```

#### Decision Management (Bans)

**Ban an IP:**
```bash
docker exec crowdsec cscli decisions add --ip <IP> --duration 24h --reason "Manual Ban"
```

**Ban an IP range (CIDR):**
```bash
docker exec crowdsec cscli decisions add --range 192.168.1.0/24 --duration 24h --reason "Subnet ban"
```

**Unban an IP:**
```bash
docker exec crowdsec cscli decisions delete --ip <IP>
```

**List active bans:**
```bash
docker exec crowdsec cscli decisions list
```

**List bans with details (JSON):**
```bash
docker exec crowdsec cscli decisions list -o json
```

#### Metrics & Statistics

**View real-time metrics:**
```bash
docker exec crowdsec cscli metrics
```

This shows:
- Parsed log lines per source
- Active scenarios and their triggers
- Bouncer API requests
- Decision counts (bans, captchas)

**View metrics in Prometheus format:**
```bash
docker exec crowdsec cscli metrics -o json
```

#### Alerts & Attack History

**List recent alerts:**
```bash
docker exec crowdsec cscli alerts list
```

**View detailed alert information:**
```bash
docker exec crowdsec cscli alerts inspect <ALERT_ID>
```

**Show alerts from the last hour:**
```bash
docker exec crowdsec cscli alerts list --since 1h
```

#### Scenario & Parser Management

**List installed scenarios:**
```bash
docker exec crowdsec cscli scenarios list
```

**List installed parsers:**
```bash
docker exec crowdsec cscli parsers list
```

**List installed collections:**
```bash
docker exec crowdsec cscli collections list
```

#### Hub Management (Install/Update Components)

**Update the hub index:**
```bash
docker exec crowdsec cscli hub update
```

**Upgrade all installed components:**
```bash
docker exec crowdsec cscli hub upgrade
```

**Install a new collection (e.g., for WordPress):**
```bash
docker exec crowdsec cscli collections install crowdsecurity/wordpress
```

**Search for available scenarios:**
```bash
docker exec crowdsec cscli hub list -a | grep <keyword>
```

#### Bouncer Management

**Check bouncer status:**
```bash
docker exec crowdsec cscli bouncers list
```

**Delete a bouncer:**
```bash
docker exec crowdsec cscli bouncers delete <bouncer_name>
```

**Add a new bouncer with specific key:**
```bash
docker exec crowdsec cscli bouncers add <name> --key <API_KEY>
```

#### Diagnostic Commands

**Check CrowdSec health:**
```bash
docker exec crowdsec cscli lapi status
```

**Validate configuration:**
```bash
docker exec crowdsec cscli config show
```

**Test log parsing (dry-run):**
```bash
docker exec crowdsec cscli explain --file /var/log/traefik/access.log --type traefik
```

> [!TIP]
> Use `docker exec crowdsec cscli <command> --help` for detailed options on any command.

### Monitoring Dashboards

| Dashboard | URL | Auth |
|-----------|-----|------|
| Traefik | `https://traefik.<domain>` | Basic Auth |
| Grafana | `https://grafana.<domain>` | Login form |
| Dozzle | `https://dozzle.<domain>` | Basic Auth |

### Stack-Watchdog Alerts

The stack-watchdog sends Telegram notifications for:

- ⚠️ **SSL Alerts**: Certificate expiring within threshold
- 🌐 **DNS Alerts**: Domain not resolving to expected IP
- 🛡️ **CrowdSec Alerts**: LAPI down, no bouncers, or stale bouncer connections

---

## Apache Legacy Configuration

This section covers the configuration required for legacy Apache installations running directly on the host (not in Docker containers). When using the `apache-host` service type in `domains.csv`, Traefik proxies requests to Apache on `host.docker.internal:8080`. Additional configuration is needed to ensure proper functionality.

### Real Client IP Forwarding

By default, Apache will log Docker's internal IP (e.g., `172.18.0.5`) instead of the real client IP because Traefik acts as a reverse proxy. To restore real client IPs in Apache logs and applications, configure the `mod_remoteip` module.

#### Step 1: Enable the RemoteIP Module

```bash
sudo a2enmod remoteip
```

#### Step 2: Create the RemoteIP Configuration

Create or edit `/etc/apache2/conf-available/remoteip.conf`:

```apache
# ==============================================
# RemoteIP Configuration for Traefik Proxy
# ==============================================

# Use X-Forwarded-For header to determine the real client IP
RemoteIPHeader X-Forwarded-For

# Trust requests from Docker networks
# These ranges cover typical Docker bridge networks
RemoteIPTrustedProxy 172.16.0.0/12
RemoteIPTrustedProxy 10.0.0.0/8
RemoteIPTrustedProxy 192.168.0.0/16

# Trust localhost (for local testing)
RemoteIPTrustedProxy 127.0.0.1
RemoteIPTrustedProxy ::1
```

#### Step 3: Enable the Configuration

```bash
sudo a2enconf remoteip
```

#### Step 4: Update Log Format (Recommended)

Edit `/etc/apache2/apache2.conf` and update the `LogFormat` directives to use `%a` (actual client IP after mod_remoteip processing) instead of `%h` (direct connection IP):

```apache
# Before (logs Docker proxy IP):
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined

# After (logs real client IP):
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

> [!TIP]
> The `%a` format specifier automatically uses the IP from `X-Forwarded-For` when `mod_remoteip` is configured, falling back to the direct connection IP if the header is not present.

#### Step 5: Restart Apache

```bash
sudo systemctl restart apache2
```

#### Verification

Check that real IPs are now appearing in logs:

```bash
tail -f /var/log/apache2/*access*.log
```

You should see external client IPs instead of Docker internal IPs (172.x.x.x).

### Apache Log Aggregation (Optional)

To include Apache host logs in the Grafana/Loki observability pipeline, the stack provides an optional `docker-compose-apache-logs.yml` file. This is automatically included by `start.sh` when `/var/log/apache2` exists on the host.

#### How It Works

1. **Automatic Detection**: `start.sh` checks for `/var/log/apache2` directory
2. **Volume Mount**: If found, mounts the logs into the Alloy container
3. **Log Parsing**: Alloy processes both access and error logs with proper label extraction

#### Parsed Labels

The following labels are automatically extracted and available in Grafana:

| Label | Description | Log Type |
|-------|-------------|----------|
| `job` | Always `apache-host` | Both |
| `log_type` | `access` or `error` | Both |
| `vhost` | Virtual host from filename | Both |
| `client_ip` | Client IP address | Both |
| `method` | HTTP method (GET, POST, etc.) | Access |
| `status` | HTTP status code | Access |
| `level` | Error level (error, warn, notice) | Error |
| `module` | Apache module (php, proxy_fcgi, etc.) | Error |

#### Querying Apache Logs in Grafana

Example LogQL queries for Apache host logs:

```logql
# All Apache host logs
{job="apache-host"}

# Only error logs
{job="apache-host", log_type="error"}

# Errors from a specific vhost
{job="apache-host", log_type="error", vhost="example.com"}

# 5xx errors from access logs
{job="apache-host", log_type="access", status=~"5.."}

# PHP errors
{job="apache-host", log_type="error", module="php"}
```

#### Manual Inclusion

If you need to manually control Apache log inclusion (instead of automatic detection), edit `start.sh` and modify the `COMPOSE_FILES` variable:

```bash
# Always include Apache logs
COMPOSE_FILES="$COMPOSE_FILES -f docker-compose-apache-logs.yml"

# Or remove the automatic detection block entirely
```

---

## Troubleshooting

### 502 Bad Gateway

- Verify the `service` name in `domains.csv` matches the container name.
- Ensure the backend container is on the `traefik` network.
- Check container logs: `docker logs <container_name>`.

### CrowdSec Connection Refused

- Verify `CROWDSEC_API_KEY` matches the registered bouncer.
- Check bouncer status: `docker exec crowdsec cscli bouncers list`.
- Regenerate key if needed:
  ```bash
  docker exec crowdsec cscli bouncers delete traefik-bouncer
  docker exec crowdsec cscli bouncers add traefik-bouncer
  ```

### Anubis Cookie Loops

- Ensure your browser accepts cookies.
- Verify DNS for auth subdomain points to the server.
- Check Anubis logs: `docker logs anubis-<tld>`.

### Certificate Not Renewing

- Check Traefik logs: `docker logs traefik`.
- Verify ACME email is correct in `.env`.
- For testing, use `TRAEFIK_ACME_ENV_TYPE=staging` to avoid rate limits.

---

## License

This project is licensed under the **MIT License**.
