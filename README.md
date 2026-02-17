# Ironclad Anti-DDoS & Anti-Bot Stack

**Traefik + CrowdSec + Anubis + Grafana (LGT Stack)**

> **Automated, resource-efficient protection for multi-domain Docker environments and legacy web servers.**

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Domain Management](#domain-management)
- [Configuration Reference](#configuration-reference)
- [Components (Technical Details)](#components-technical-details)
- [Operations Manual](#operations-manual)
- [Apache Legacy Configuration](#apache-legacy-configuration)
- [Trusted Local SSL (mkcert)](#trusted-local-ssl-mkcert)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Quick Start

Get the stack running in minutes. Choose the environment that matches your needs.

### Prerequisites

- **Docker Engine** & **Docker Compose** (v2.x+)
- **Make** (usually pre-installed, or via `build-essential`)
- **Python 3** (modules are auto-installed):
  ```bash
  # Debian/Ubuntu
  sudo apt install make python3-venv python3-pip
  
  # RHEL/Fedora
  sudo dnf install make python3-pip
  ```
- Ports `80` and `443` free on the host machine.

### Option A: Local Development

Best for testing on your machine with `.local` domains and browser-trusted certificates.

```bash
# 1. Install mkcert (one-time setup)
# Debian/Ubuntu:
sudo apt install mkcert
mkcert -install

# 2. Add domains to /etc/hosts
echo "127.0.0.1 myapp.local auth.myapp.local" | sudo tee -a /etc/hosts

# 3. Initialize the environment
make init
# When prompted for environment, choose: local

# 4. Start the stack
make start
```

> [!TIP]
> The stack automatically generates trusted certificates for all domains in `/etc/hosts` pointing to `127.0.0.1`.

### Option B: Staging (Recommended First Deploy)

Uses Let's Encrypt **staging** certificates. Safe for testing without hitting rate limits.

```bash
# 1. Point your domain DNS to this server's public IP

# 2. Initialize the environment
make init
# When prompted for environment, choose: staging

# 3. Start the stack
make start
```

> [!WARNING]
> Staging certificates will show browser warnings. This is expected—switch to `production` once everything works.

### Option C: Production

Uses real Let's Encrypt certificates. **Only use after successful staging test.**

```bash
# 1. Ensure DNS is correctly configured and staging worked

# 2. Edit .env and change:
TRAEFIK_ACME_ENV_TYPE=production

# 3. Clear old staging certificates
make clean

# 4. Restart the stack
make restart
```

### First Steps After Setup

All internal tools are accessible via your dashboard subdomain (default: `dashboard.<your-domain>`):

1. **Access Domain Manager**: `https://dashboard.<your-domain>` — Add your sites here.
2. **View Traefik Dashboard**: `https://dashboard.<your-domain>/traefik` — Routing overview.
3. **View Live Logs**: `https://dashboard.<your-domain>/dozzle` — Real-time container logs.
4. **Monitor Metrics**: `https://dashboard.<your-domain>/grafana` — Traffic dashboards.

> [!NOTE]
> The dashboard subdomain is configurable via `DASHBOARD_SUBDOMAIN` in `.env`.

---

## Architecture

The stack operates on a "Defense in Depth" principle, filtering traffic through a precise middleware chain before it reaches your applications.

```mermaid
graph TD
    classDef user fill:#e0e0e0,stroke:#333,stroke-width:2px;
    classDef traefik fill:#8cb5ff,stroke:#333,stroke-width:2px;
    classDef security fill:#ff9999,stroke:#333,stroke-width:2px;
    classDef app fill:#99ff99,stroke:#333,stroke-width:2px;
    classDef observ fill:#ffffcc,stroke:#333,stroke-width:2px;

    User((User/Bot)):::user -->|HTTPS :443| T_Entry[Traefik EntryPoint]:::traefik

    subgraph "Traefik Middleware Chain"
        T_Entry --> MW_UA{1. UA Blacklist}:::security
        MW_UA -- Matched Bot --> Block[403 Forbidden]:::security
        MW_UA -- Allowed --> MW_CS{2. CrowdSec Check}:::security
        MW_CS -- Blocked IP --> Block
        MW_CS -- Allowed --> MW_Sec["3. Security Headers"]:::traefik
        MW_Sec --> MW_RL["4. Rate Limiting"]:::traefik
        MW_RL --> MW_Comp["5. Compression"]:::traefik
        MW_Comp --> MW_Auth{6. Auth Required?}:::traefik
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

### Key Benefits

- **🛡️ Multi-Layered Defense**: Combines IP reputation (CrowdSec), Layer 7 protection (Anubis PoW), and strict rate limiting.
- **⚡ Performance First**: Optimized middleware chain designed for zero latency overhead.
- **🤖 Fully Automated**: Configuration is dynamically generated from containers and a simple CSV file.
- **📊 Complete Visibility**: Full observability stack with Grafana, Loki, and real-time log viewing.
- **🏠 Hybrid Ready**: Protect Docker containers and legacy host-based services (like Apache/PHP) simultaneously.
- **🔐 No-Hassle SSL**: Automated Let's Encrypt certificates or locally trusted certs for development.

---

## Domain Management

Define which websites the stack will protect and how they should behave.

### The Domain Inventory (`domains.csv`)

The heart of the configuration is the `domains.csv` file. You can manage it manually or via the **Domain Manager** UI.

| Column | Description | Mandatory |
|:---|:---|:---:|
| **domain** | The full domain (e.g., `shop.example.com`). | Yes |
| **redirection** | Target URL if you want to redirect (e.g., `another-site.com`). | No |
| **service** | Docker service name or `apache-host` for legacy servers. | Yes |
| **anubis_sub** | Subdomain for the bot protection portal (e.g., `auth`). | No |
| **rate_limit** | Max requests/sec for this specific domain. | No |
| **burst** | Max peak requests for this specific domain. | No |
| **concurrency** | Max active connections for this specific domain. | No |

### Domain Manager UI

Access the management interface at `https://domains.<your-domain>`.

- **Live Preview**: See which Docker containers are currently running and selectable.
- **Visual Grouping**: Domains are automatically grouped by their root (TLD) for easier management.
- **Safety Defaults**: The UI enforces safe defaults to prevent accidental misconfiguration.

---

## Configuration Reference

### Environment Variables (`.env`)

#### General

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMAIN` | Your primary/base domain (required for dashboards). | - |
| `PROJECT_NAME` | Prefix for all Docker containers. Prevents conflicts with other projects. | `stack` |
| `TZ` | Server timezone for logs and scheduled tasks. | `Europe/Madrid` |

#### Anubis (Bot Defense)

| Variable | Description | Default |
|----------|-------------|---------|
| `ANUBIS_DIFFICULTY` | Complexity of the Proof-of-Work challenge (1-5). Higher = more CPU for clients. | `4` |
| `ANUBIS_REDIS_PRIVATE_KEY` | Hex key for session signing. | *Auto-generated* |
| `ANUBIS_CPU_LIMIT` | Host CPU limit per Anubis instance (to prevent resource exhaustion). | `0.10` |
| `ANUBIS_MEM_LIMIT` | RAM limit per Anubis instance. | `32M` |

#### Redis & Security Layer

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_PASSWORD` | Password for the session store. | *Auto-generated* |
| `CROWDSEC_DISABLE` | Set to `true` to completely disable the IPS (firewall). | `false` |
| `CROWDSEC_API_KEY` | Secure key for the Traefik-CrowdSec communication. | *Auto-generated* |
| `CROWDSEC_WHITELIST_IPS` | Comma-separated IPs/CIDRs that bypass all security checks. | - |
| `CROWDSEC_UPDATE_INTERVAL` | How often (seconds) to download the global blacklist. | `60` |
| `CROWDSEC_COLLECTIONS` | List of security scenarios to load (Traefik, SSH, DDoS, etc.). | *Defaults included* |
| `CROWDSEC_ENROLLMENT_KEY` | Optional key to connect to the [CrowdSec Console](https://app.crowdsec.net). | - |

#### Traefik (Edge Routing)

| Variable | Description | Default |
|----------|-------------|---------|
| `TRAEFIK_LISTEN_IP` | Host IP to bind ports 80/443. Use `0.0.0.0` for all interfaces. | `0.0.0.0` |
| `TRAEFIK_ACME_EMAIL` | Email for Let's Encrypt certificate notices (required for SSL). | - |
| `TRAEFIK_ACME_ENV_TYPE` | `production`, `staging` (testing), or `local` (mkcert). | `staging` |
| `TRAEFIK_ACME_CA_SERVER` | Custom ACME server URL. Only used if `TRAEFIK_ACME_ENV_TYPE` is empty. | - |
| `TRAEFIK_GLOBAL_RATE_AVG` | Default requests per second allowed per IP. | `60` |
| `TRAEFIK_GLOBAL_RATE_BURST` | Peak requests allowed before blocking. | `120` |
| `TRAEFIK_GLOBAL_CONCURRENCY` | Max simultaneous connections per IP. | `25` |
| `TRAEFIK_HSTS_MAX_AGE` | HSTS header duration (seconds). | `31536000` |
| `TRAEFIK_BLOCKED_PATHS` | Comma-separated list of paths to block globally (e.g., `/wp-admin`). | - |
| `TRAEFIK_BAD_USER_AGENTS` | Comma-separated list of User-Agent regex patterns to block natively (e.g., `(?i).*curl.*`). | - |
| `TRAEFIK_ACCESS_LOG_BUFFER` | Number of log lines to buffer before writing to disk/stdout. | `1000` |
| `TRAEFIK_FRAME_ANCESTORS` | External domains allowed to embed your sites in iframes. | - |
| `APACHE_HOST_IP` | IP of the host machine as seen from Docker (docker0 bridge). | `172.17.0.1` |

#### When to adjust Log Buffering (`TRAEFIK_ACCESS_LOG_BUFFER`)

- **Value `1000` (Production)**: Batches log writes to improve performance and reduce I/O under high traffic.
- **Value `0` or `1` (Testing/Debugging)**: Disables buffering, making every request appear in the logs **instantly**. Use this while testing native blocking (User-Agent or Paths) to verify it's working.

#### Debugging Log Level

To see detailed ACME/Let's Encrypt generation logs, set `TRAEFIK_LOG_LEVEL=DEBUG` in your `.env` file and restart the stack. This will show validation challenges and certificate acquisition steps in the `make certs-watch` command.
DEFAULT: `INFO`

#### Traefik Timeouts

Legacy applications or slow backends (e.g., heavy PHP/WordPress) may require adjusted timeouts.

| Variable | Default | Function |
|----------|---------|----------|
| `TRAEFIK_TIMEOUT_ACTIVE` | `60` | **Execution Limit** (Seconds). Controls `readTimeout`, `writeTimeout` (EntryPoints) and `responseHeaderTimeout` (Transport). Max time allowed for the request to complete or headers to be received. |
| `TRAEFIK_TIMEOUT_IDLE` | `90` | **Connection Buffer** (Seconds). Controls `idleTimeout` (EntryPoints) and `idleConnTimeout` (Transport). Keep this value **higher** than the active timeout. |

> [!IMPORTANT]
> These variables update the configuration at **both ends** of the proxy. If your application takes 70 seconds to respond, you must increase `TRAEFIK_TIMEOUT_ACTIVE` to at least 75s.

#### Dashboard & SSO

| Variable | Description | Default |
|----------|-------------|---------|
| `DASHBOARD_SUBDOMAIN` | Subdomain where all internal tools are served. | `dashboard` |

All tools (Domain Manager, Traefik, Dozzle, Grafana) are served under `<DASHBOARD_SUBDOMAIN>.<DOMAIN>` with path-based routing. The Domain Manager acts as an SSO (Single Sign-On) provider for all internal services using Traefik's forward-auth middleware.

#### Dashboard Credentials

The stack uses independent credentials for each dashboard. These are synchronized automatically by `start.sh`.

| Variable | Service | Default |
|----------|---------|---------|
| `DOMAIN_MANAGER_ADMIN_USER` | Domain Manager / SSO Login | `admin` |
| `DOMAIN_MANAGER_ADMIN_PASSWORD` | Domain Manager / SSO Login | - |
| `GRAFANA_ADMIN_USER` | Grafana Admin (full admin access) | `admin` |
| `GRAFANA_ADMIN_PASSWORD` | Grafana Admin (full admin access) | - |

> [!NOTE]
> **Grafana Access Levels**: Users authenticated via SSO get **Viewer** access (read-only dashboards). Use the Grafana admin credentials above to log in with full admin privileges for configuration.

> [!NOTE]
> **Internal Variables**: Variables like `TRAEFIK_DASHBOARD_AUTH`, `DOZZLE_DASHBOARD_AUTH`, `DOMAIN_MANAGER_SECRET_KEY`, and `DOMAIN_MANAGER_APP_PATH_HOST` are managed automatically. You don't need to edit them manually.

#### Stack-Watchdog Alerts

| Variable | Description | Default |
|----------|-------------|---------|
| `WATCHDOG_TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | - |
| `WATCHDOG_TELEGRAM_RECIPIENT_ID` | Chat/group ID for alerts | - |
| `WATCHDOG_CERT_DAYS_WARNING` | Certificate expiration threshold (days) | `10` |
| `WATCHDOG_DNS_CHECK_INTERVAL` | DNS verification interval (seconds) | `21600` (6h) |
| `WATCHDOG_CROWDSEC_CHECK_INTERVAL` | CrowdSec check interval (seconds) | `3600` (1h) |

---

## Components (Technical Details)

### Traefik (Edge Router)

Traefik serves as the ingress controller and the first line of defense.

- **SSL Termination**: Automatically handles Let's Encrypt certificates (staging or production).
- **Bouncer Integration**: Uses the CrowdSec Traefik Bouncer plugin to enforce IP bans at the edge.
- **Dynamic Configuration**: Reloads rules on-the-fly without downtime.

### The Golden Chain (Middleware Pipeline)

Every request passes through a sequential chain of middlewares designed to filter, protect, and optimize traffic.

| Order | Middleware | Purpose | Security Benefit |
|:---:|:---|:---|:---|
| 1 | **CrowdSec Check** | Consults the local CrowdSec database for the client IP. | **Instant Mitigation**: Blocks known malicious IPs at the entry point. |
| 2 | **Global Buffering** | Reads the entire request into memory before passing it to the backend. | **Slowloris Defense**: Prevents attackers from exhausting server sockets. |
| 3 | **Security Headers** | Injects recommended browser security headers (HSTS, XSS, Frame-Options). | **Client Hardening**: Protects users from clickjacking and protocol downgrade attacks. |
| 4 | **Rate Limiting** | Throttles requests based on average and burst thresholds. | **Flood Protection**: Mitigates automated scraping and brute-force attempts. |
| 5 | **Concurrency** | Limits the number of simultaneous active connections per client. | **Resource Preservation**: Ensures one heavy/malicious user cannot consume all backend threads. |
| 6 | **ForwardAuth (Anubis)** | (Optional) Intercepts requests to verify or challenge the session. | **Bot Defense**: Forces suspicious traffic to solve a Proof-of-Work challenge. |
| 7 | **Compression** | Dynamically compresses response bodies (Gzip) for supported clients. | **Performance**: Reduces bandwidth usage and improves load times. |

> [!NOTE]
> **UA Blacklist** operates separately via a dedicated path-blocking router with higher priority, not as part of this chain.

#### Specialized Middlewares

- **`apache-forward-headers`**: Injects `X-Forwarded-Proto: https` headers. Critical for legacy apps like WordPress to detect they are behind an SSL proxy.
- **`redirect-regex`**: Handles 301/302 redirections defined in `domains.csv` with optimized regex matching.
- **`anubis-assets-stripper`**: Internal helper to clean request paths for Anubis static assets.

### CrowdSec (IPS)

CrowdSec is a collaborative Intrusion Prevention System that analyzes behavior to detect attacks.

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

To enable it, provide your enrollment key during setup or set `CROWDSEC_ENROLLMENT_KEY` in `.env`.

### Anubis (Bot Defense)

Anubis is a specialized "ForwardAuth" middleware for mitigating bots.

- **Mechanism**: When a user accesses a protected route without a valid session, Anubis intercepts the request.
- **Challenge**: Presents a cryptographic Proof-of-Work (PoW) challenge the client must solve.
- **Isolation**: One Anubis instance is deployed per TLD to respect "Same-Site" cookie policies.

#### Custom Assets

Anubis supports custom styling and images. Default assets (with `.dist` extension) are automatically used if you don't provide custom versions.

| File | Location | Description |
|------|----------|-------------|
| `custom.css` | `config/anubis/assets/` | Custom stylesheet for the challenge page |
| `happy.webp` | `config/anubis/assets/static/img/` | Image shown on successful challenge |
| `pensive.webp` | `config/anubis/assets/static/img/` | Image shown while solving challenge |
| `reject.webp` | `config/anubis/assets/static/img/` | Image shown on failed challenge |

**To customize:**

```bash
# Create custom CSS
cp config/anubis/assets/custom.css.dist config/anubis/assets/custom.css
# Edit config/anubis/assets/custom.css with your changes

# Use custom images
cp /path/to/your/happy.webp config/anubis/assets/static/img/happy.webp
```

> [!TIP]
> Your custom assets are git-ignored, so they won't be overwritten by project updates.

### Redis (State Management)

A high-performance Valkey (Redis-compatible) instance acts as the session store for Anubis.

- **Configuration**: Tuned for cache usage (`allkeys-lru`).
- **Persistence**: Uses AOF with per-second synchronization.

### Domain Manager (Admin UI)

The Domain Manager provides a user-friendly web interface to manage the `domains.csv` inventory.

- **Real-time Updates**: Changes are applied immediately to the infrastructure.
- **Root Domain Grouping**: Automatically identifies and color-codes services by their root domain.
- **Strict Service Selection**: Dropdown automatically lists running Docker containers and detects `apache-host` availability.
- **Security Defaults**: Enforces safe defaults for rate-limiting and Anubis protection.

### Observability Stack (Alloy, Loki, Grafana)

- **Alloy**: OpenTelemetry-compatible agent that discovers Docker containers and forwards logs to Loki.
- **Loki**: Log aggregation system optimized for efficiency.
- **Grafana**: Visual dashboards for traffic analysis and attack monitoring.

### Watchdog (Monitoring)

A lightweight utility service that monitors the stack and sends Telegram alerts.

| Script | Interval | Function |
|--------|----------|----------|
| `check-certs.sh` | 24 hours | Scans `acme.json` for certificates close to expiration |
| `check-dns.sh` | 6 hours (configurable) | Verifies all domains point to the correct IP |
| `check-crowdsec.sh` | 1 hour (configurable) | Monitors CrowdSec health, LAPI status, and bouncer connectivity |

### Auxiliary Tools

- **Dozzle**: Real-time log viewer for all containers (`https://dozzle.<domain>`).
- **ctop**: Interactive container monitoring (run `make ctop`).
- **Anubis-Assets**: Nginx server for local Anubis static assets.

---

## Operations Manual

### Common Commands

| Action | Command |
|--------|---------|
| **Initialize Env** | `make init` |
| **Start/Update Stack** | `make start` |
| **Stop Stack** | `make stop` |
| **Restart Stack** | `make restart` |
| **Rebuild Services** | `make rebuild` (rebuilds custom images) |
| **Pull Images** | `make pull` |
| **List Services** | `make services` |
| **Service Status** | `make status` |
| **Monitor Containers** | `make ctop` |
| **Follow Logs** | `make logs [service]` |
| **Open Shell** | `make shell [service]` |
| **Validate Environment** | `make validate` |
| **Sync Environment** | `make sync` |
| **Clean Artifacts** | `make clean` (Interactive) |
| **Watch Certificates** | `make certs-watch` (Requires `DEBUG` logs) |
| **Certificates Info**| `make certs-info` (Summary) |
| **Inspect Certificates** | `make certs-inspect` (Detailed) |
| **Generate Local Certs** | `make certs-create-local` (Local mode only) |
| **Traefik Health** | `make traefik-health` |
| **Redis Stats** | `make redis-info` / `make redis-monitor` |
| **Show Help** | `make help` |

### Security First Boot Sequence

When you run `make start`, the stack follows a strict "Defense First" order:

1. **Environment Sync**: Validates your `.env` and ensures no critical settings are missing.
2. **Security Layer**: Boots **CrowdSec** and **Redis** first.
3. **Health Check**: Traefik **will not start** until CrowdSec is fully healthy.
4. **Bouncer Sync**: Automatically registers the security keys between Traefik and CrowdSec.
5. **Application Layer**: Finally, boots your apps and the routing engine.

### Smart Credentials & Auto-Sync

The stack manages security hashes for you. You don't need to manually generate `htpasswd` strings.

1. **Manual Edit**: You can change any `_ADMIN_USER` or `_ADMIN_PASSWORD` directly in the `.env` file.
2. **Auto-Detection**: When you run `make start`, the script detects the change.
3. **Instant Sync**: It regenerates the secure hashes and updates your `.env` and running containers immediately.

### Monitoring Dashboards

All dashboards are served under `https://<DASHBOARD_SUBDOMAIN>.<DOMAIN>` (default: `dashboard`).

| Dashboard | Path | Auth |
|-----------|------|------|
| Domain Manager | `/` (root) | SSO Login |
| Traefik | `/traefik` | SSO Login |
| Grafana | `/grafana` | SSO (Viewer) / Admin login |
| Dozzle | `/dozzle` | SSO Login |
| Certificates | `/certs` | SSO Login |

### Watchdog Alerts

The watchdog sends Telegram notifications for:

- ⚠️ **SSL Alerts**: Certificate expiring within threshold.
- 🌐 **DNS Alerts**: Domain not resolving to the expected host IP.
- 🛡️ **CrowdSec Alerts**: LAPI down, no bouncers, or bouncer connection issues.

### CrowdSec Operations

The easiest way to interact with CrowdSec is using the `Makefile` shortcuts.

#### Inspection & Lists

```bash
# View active decisions (bans)
make crowdsec-decisions

# List recent alerts
make crowdsec-alerts

# View real-time metrics
make crowdsec-metrics
```

#### Advanced Management (Manual)

For complex operations (like adding bans with specific reasons), execute `cscli` directly inside the container:

```bash
# Access the CrowdSec shell
make shell crowdsec
# Then run: cscli decisions add ...

# Or run one-off commands directly
make shell crowdsec -- cscli decisions add --ip <IP> --duration 24h --reason "Manual Ban"
```

> [!TIP]
> Use `make shell crowdsec -- cscli <command> --help` for detailed options on any command.

---

## Apache Legacy Configuration

This section covers the configuration required for legacy Apache installations running directly on the host (not in Docker containers). When using the `apache-host` service type in `domains.csv`, Traefik proxies requests to Apache on `<APACHE_HOST_IP>:8080` (default: `172.17.0.1`, the docker0 bridge on Linux).

> [!TIP]
> If you're running Docker Desktop (macOS/Windows), set `APACHE_HOST_IP=host.docker.internal` in your `.env`.

### Real Client IP Forwarding

By default, Apache will log Docker's internal IP instead of the real client IP. To restore real client IPs, configure `mod_remoteip`.

#### Step 1: Enable the RemoteIP Module

```bash
sudo a2enmod remoteip
```

#### Step 2: Create the RemoteIP Configuration

Create or edit `/etc/apache2/conf-available/remoteip.conf`:

```apache
# RemoteIP Configuration for Traefik Proxy
RemoteIPHeader X-Forwarded-For

# Trust requests from Docker networks
RemoteIPTrustedProxy 172.16.0.0/12
RemoteIPTrustedProxy 10.0.0.0/8
RemoteIPTrustedProxy 192.168.0.0/16

# Trust localhost
RemoteIPTrustedProxy 127.0.0.1
RemoteIPTrustedProxy ::1
```

#### Step 3: Enable the Configuration

```bash
sudo a2enconf remoteip
```

#### Step 4: Update Log Format (Recommended)

Edit `/etc/apache2/apache2.conf` and update the `LogFormat` to use `%a` instead of `%h`:

```apache
# Before (logs Docker proxy IP):
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined

# After (logs real client IP):
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

#### Step 5: Restart Apache

```bash
sudo systemctl restart apache2
```

### Apache Log Aggregation (Optional)

To include Apache host logs in the Grafana/Loki observability pipeline, the stack provides `docker-compose-apache-logs.yaml`. This is automatically included by `start.sh` when `/var/log/apache2` exists on the host.

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

```logql
# All Apache host logs
{job="apache-host"}

# Only error logs
{job="apache-host", log_type="error"}

# 5xx errors from access logs
{job="apache-host", log_type="access", status=~"5.."}

# PHP errors
{job="apache-host", log_type="error", module="php"}
```

---

## Trusted Local SSL (mkcert)

This stack supports locally trusted certificates to prevent browser security warnings during development.

### Prerequisites

1. Install [mkcert](https://github.com/FiloSottile/mkcert) on your host machine.
2. Run `mkcert -install` to add the local CA to your system's trust store.

### Setup Instructions

1. **Configure Environment**: Set `TRAEFIK_ACME_ENV_TYPE=local` in your `.env` file.

2. **Generate Certificates**: When you run `make start` with `TRAEFIK_ACME_ENV_TYPE=local`, the system will:
    - Automatically scan your `/etc/hosts` for domains pointing to `127.0.0.1`.
    - Filter out defaults like `localhost` and `broadcasthost`.
    - Invoke `mkcert` to generate a single certificate covering all discovered domains.
    - Store the results in `config/traefik/certs-local-dev/`.
    - Dynamically configure Traefik to use these certificates.

    > [!TIP]
    > **Manual execution**: If you add new entries to `/etc/hosts` and want to refresh the certificate without a full restart, run `make certs-create-local`.

3. **Start the Stack**:
    ```bash
    make start
    ```
    You will see: `🔐 Local Mode detected. Automating certificate generation...`

---

## Project Structure

```
.
├── .env.dist                              # Environment template
├── domains.csv.dist                       # Domain inventory template
├── Makefile                               # Project management commands
├── scripts/                               # Core logic scripts
│   ├── compose-files.sh                   # Shared compose file list builder
│   ├── generate-config.py                 # Dynamic Traefik config generator
│   ├── initialize-env.sh                  # Interactive .env setup wizard
│   ├── validate-env.py                    # .env validation & sync tool
│   ├── inspect-certs.py                   # Certificate inspection utility
│   ├── create-local-certs.sh              # Local mkcert certificate generator
│   ├── start.sh                           # Full stack startup orchestrator
│   ├── stop.sh                            # Graceful stack shutdown
│   ├── requirements.txt                   # Python dependencies
│   └── make/                              # Conditional Makefile includes
│       ├── certs.mk                       # Local cert targets
│       └── crowdsec.mk                    # CrowdSec management targets
│
├── config/
│   ├── alloy/                             # Alloy log collector config
│   │   └── config.alloy
│   ├── anubis/                            # Anubis bot defense
│   │   ├── botPolicy.yaml                 # Bot policy template
│   │   └── assets/                        # Static assets (images, CSS)
│   ├── crowdsec/                          # CrowdSec IPS
│   │   ├── acquis.yaml
│   │   ├── profiles.yaml
│   │   └── parsers/                       # Custom parsers (IP whitelist)
│   ├── domain-manager/                    # Admin UI backend (Python/Flask)
│   │   ├── app.py
│   │   ├── Dockerfile
│   │   ├── static/
│   │   └── templates/
│   ├── grafana/                           # Grafana datasources
│   │   └── config.yaml
│   ├── loki/                              # Loki log storage
│   │   └── config.yaml
│   ├── redis/                             # Redis/Valkey session store
│   │   └── redis.conf
│   ├── watchdog/                          # Monitoring scripts
│   │   ├── Dockerfile
│   │   ├── check-certs.sh
│   │   ├── check-crowdsec.sh
│   │   └── check-dns.sh
│   └── traefik/                           # Traefik configuration
│       ├── traefik.yaml.template          # Static config template
│       ├── certs-local-dev/               # Local mkcert certificates
│       └── dynamic-config/                # Generated routers/middlewares
│
└── Docker Compose Files:
    ├── docker-compose-traefik-crowdsec-redis.yaml   # Core infrastructure
    ├── docker-compose-tools.yaml                    # Tools & monitoring
    ├── docker-compose-grafana-loki-alloy.yaml       # Observability stack
    ├── docker-compose-domain-manager.yaml           # Admin UI service
    ├── docker-compose-anubis-base.yaml              # Anubis template
    ├── docker-compose-anubis-generated.yaml         # Auto-generated Anubis instances
    └── docker-compose-apache-logs.yaml              # Apache log aggregation (optional)
```

---

## Troubleshooting

### 502 Bad Gateway

- **Naming**: Verify the `service` name in `domains.csv` matches the container `container_name` or `service` key.
- **Network**: Ensure the backend container is on the `traefik` network (`external: true`).
- **Internal Ports**: If your service listens on a non-standard port (not 80), you must add individual Traefik labels for `loadbalancer.server.port`.

### 504 Gateway Timeout

- **Network Isolation**: This usually means Traefik cannot reach the backend. Ensure your backend container is connected to the `traefik` network:
    ```yaml
    networks:
      - traefik
    ```
- **Firewall/Internal**: Check if the container itself is running and healthy.

### Service "X" does not exist

- **Dynamic Config**: If using `generate-config.py`, this error means the service defined in `domains.csv` does not match any running Docker container.
- **Tip**: Run `docker ps` to see the actual names of your containers.

### Credentials sync failed

- If your `.env` gets corrupted, delete the `_ADMIN_CREDS_SYNC` variables and the `_DASHBOARD_AUTH` hashes. Run `make start` and the system will repair/regenerate them.

### Anubis Cookie Issues

- **Same-Site**: Chrome and modern browsers require HTTPS for `SameSite=None` cookies. Ensure you are accessing via HTTPS.
- **Root Domain Mismatch**: Ensure `domains.csv` uses the correct `anubis_sub`. If you protect `a.com` but your auth subdomain is `auth.b.com`, the cookie will be rejected.

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
