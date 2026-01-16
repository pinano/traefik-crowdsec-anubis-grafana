import tldextract
import yaml
import os
import csv
import re
from collections import defaultdict

# =============================================================================
# CONSTANTS & FILE PATHS
# =============================================================================

INPUT_FILE = 'domains.csv'
BASE_FILENAME = 'docker-compose-anubis-base.yaml'
OUTPUT_COMPOSE = 'docker-compose-anubis-generated.yaml'
OUTPUT_TRAEFIK = 'config/traefik/dynamic-config/routers-generated.yaml'

# =============================================================================
# ENVIRONMENT VARIABLES
# =============================================================================

CROWDSEC_API_KEY = os.getenv('CROWDSEC_API_KEY')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
CROWDSEC_DISABLE = os.getenv('CROWDSEC_DISABLE', 'false').lower() == 'true'
TRAEFIK_ENV_TYPE = os.getenv('TRAEFIK_ACME_ENV_TYPE', 'staging')
IS_LOCAL_DEV = (TRAEFIK_ENV_TYPE == 'local')

# Blocked Paths (Comma-separated list of regex patterns)
BLOCKED_PATHS_STR = os.getenv('TRAEFIK_BLOCKED_PATHS', '').strip()

# Frame Ancestors (for iframes)
FRAME_ANCESTORS = os.getenv('TRAEFIK_FRAME_ANCESTORS', '').strip()

# Robust stripping of surrounding quotes
if (BLOCKED_PATHS_STR.startswith('"') and BLOCKED_PATHS_STR.endswith('"')) or \
   (BLOCKED_PATHS_STR.startswith("'") and BLOCKED_PATHS_STR.endswith("'")):
    BLOCKED_PATHS_STR = BLOCKED_PATHS_STR[1:-1]

BLOCKED_PATHS = [p.strip().strip('"').strip("'") for p in BLOCKED_PATHS_STR.split(',') if p.strip()]

# TLS Chunking Limit (Let's Encrypt max is 100)
TLS_BATCH_SIZE = 90

# CrowdSec & Traefik Settings (with defaults)
try:
    CS_UPDATE_INTERVAL = int(os.getenv('CROWDSEC_UPDATE_INTERVAL', 60))
    T_ACTIVE = int(os.getenv('TRAEFIK_TIMEOUT_ACTIVE', 60))
    T_IDLE = int(os.getenv('TRAEFIK_TIMEOUT_IDLE', 90))
    G_RATE_AVG = int(os.getenv('TRAEFIK_GLOBAL_RATE_AVG', 60))
    G_RATE_BURST = int(os.getenv('TRAEFIK_GLOBAL_RATE_BURST', 120))
    G_CONCURRENCY = int(os.getenv('TRAEFIK_GLOBAL_CONCURRENCY', 25))
    HSTS_SECONDS = int(os.getenv('TRAEFIK_HSTS_MAX_AGE', 31536000))
except ValueError:
    # Fallback defaults if parsing fails
    CS_UPDATE_INTERVAL = 60
    T_ACTIVE = 60
    T_IDLE = 90
    G_RATE_AVG = 60
    G_RATE_BURST = 120
    G_CONCURRENCY = 25
    HSTS_SECONDS = 31536000

# Regex for validating Docker/Traefik service names
VALID_SERVICE_NAME_REGEX = re.compile(r'^[a-z0-9-]+$')

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

if not CROWDSEC_API_KEY:
    print("    ❌ FATAL ERROR: CROWDSEC_API_KEY environment variable not found.")
    exit(1)

if not REDIS_PASSWORD:
    print("    ❌ FATAL ERROR: REDIS_PASSWORD environment variable not found.")
    exit(1)

# =============================================================================
# HELPER CLASSES & FUNCTIONS
# =============================================================================

# Custom Dumper to avoid excessive indentation
class IndentDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(IndentDumper, self).increase_indent(flow, False)

# Extract root domains
def get_root_domain(domain):
    extracted = tldextract.extract(domain)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain

# This is only for router/middleware naming internally in Traefik, less strict than service naming
def sanitize_name(name):
    return name.replace('.', '-').replace('_', '-').lower()

def process_router(entry, http_section, domain_to_cert_def):
    domain = entry['domain']
    service = entry['service']
    anubis_sub = entry['anubis_sub']
    extra = entry['extra']
    root = entry['root']

    safe_domain = sanitize_name(domain)
    router_name = f"router-{safe_domain}"

    mw_list = []
    if not CROWDSEC_DISABLE:
        mw_list.append('crowdsec-check')
    
    # Protecting against Slowloris ASAP
    mw_list.append('global-buffering')
    
    mw_list.append('security-headers')

    if 'rate' in extra or 'burst' in extra:
        custom_rl_name = f"rl-{safe_domain}"
        avg = extra.get('rate', G_RATE_AVG)
        burst = extra.get('burst', G_RATE_BURST)
        http_section['middlewares'][custom_rl_name] = {
            'rateLimit': {'average': avg, 'burst': burst}
        }
        mw_list.append(custom_rl_name)
    else:
        mw_list.append('global-ratelimit')

    if 'concurrency' in extra:
        custom_conc_name = f"conc-{safe_domain}"
        http_section['middlewares'][custom_conc_name] = {
            'inFlightReq': {'amount': extra['concurrency']}
        }
        mw_list.append(custom_conc_name)
    else:
        mw_list.append('global-concurrency')

    if anubis_sub:
        safe_root = sanitize_name(root)
        safe_auth = sanitize_name(anubis_sub)
        mw_auth_name = f"anubis-mw-{safe_root}-{safe_auth}"
        mw_list.append(mw_auth_name)

    # Compression and Protocol headers last
    mw_list.append('global-compress')

    # -------------------------------------------------------------------------
    # Redirection Middleware
    # -------------------------------------------------------------------------
    redirection = entry.get('redirection')
    if redirection:
        redirect_mw_name = f"redirect-{safe_domain}"
        
        # Normalize target to have protocol
        target = redirection
        if not target.startswith("http"):
            target = f"https://{target}"
            
        http_section['middlewares'][redirect_mw_name] = {
            'redirectRegex': {
                'regex': f"^https?://{domain}/(.*)",
                'replacement': f"{target}/${{1}}",
                'permanent': True
            }
        }
        mw_list.append(redirect_mw_name)

    if service == 'apache-host':
        mw_list.append('apache-forward-headers')
        target_service = 'apache-host-8080@file'
    else:
        target_service = f"{service}@docker"

    # Router config
    router_conf = {
        'rule': f"Host(`{domain}`)",
        'entryPoints': ["websecure"],
        'service': target_service,
        'tls': {}, # Default to empty TLS (self-signed)
        'middlewares': mw_list
    }
    
    # Only use Let's Encrypt if NOT in local dev mode
    if not IS_LOCAL_DEV:
        router_conf['tls']['certResolver'] = os.getenv('TRAEFIK_CERT_RESOLVER', 'le')

    
    # Inject TLS domains if specific batch exists
    if domain in domain_to_cert_def:
        router_conf['tls']['domains'] = [domain_to_cert_def[domain]]

    http_section['routers'][router_name] = router_conf

    # -------------------------------------------------------------------------
    # Path Blocking Router (Per-Domain)
    # -------------------------------------------------------------------------
    # Creates a higher priority router to intercept blocked paths
    if BLOCKED_PATHS:
        block_router_name = f"blocker-{safe_domain}"
        paths_rule = " || ".join([f"PathRegexp(`.*{p}.*`)" for p in BLOCKED_PATHS])
        http_section['routers'][block_router_name] = {
            'rule': f"Host(`{domain}`) && ({paths_rule})",
            'entryPoints': ["websecure"],
            'service': "api@internal",
            'priority': 11000,
            'tls': router_conf.get('tls', {}),
            'middlewares': ["block-unwanted-paths"]
        }

# =============================================================================
# MAIN LOGIC
# =============================================================================

def generate_configs():
    if not os.path.exists(INPUT_FILE):
        print(f"    ❌ FATAL ERROR: {INPUT_FILE} not found.")
        return

    raw_entries = []
    error_count = 0

    print(f"    📂 Reading {INPUT_FILE}...")
    try:
        with open(INPUT_FILE, 'r') as f:
            reader = csv.reader(f, skipinitialspace=True)
            for line_num, row in enumerate(reader, 1):
                if not row or row[0].strip().startswith('#'):
                    continue

                if len(row) < 3:
                    print(f"    ⚠️ WARN [Line {line_num}] Ignored: Insufficient data.")
                    error_count += 1
                    continue

                domain = row[0].strip()
                redirection = row[1].strip()
                service = row[2].strip().lower() 
                anubis_sub = row[3].strip().lower() if len(row) > 3 else ""

                # --- Robustness Check: Docker Service Name Format ---
                if service != 'apache-host' and not VALID_SERVICE_NAME_REGEX.match(service):
                    print(f"    ❌ [Line {line_num}] Error: Service name '{service}' must only contain lowercase letters, numbers, and hyphens ('-'). Entry skipped.")
                    error_count += 1
                    continue

                extra = {}
                def get_int(idx):
                    if len(row) > idx and row[idx].strip():
                        try: return int(row[idx].strip())
                        except ValueError: return None
                    return None

                rate = get_int(4)
                if rate: extra['rate'] = rate
                burst = get_int(5)
                if burst: extra['burst'] = burst
                concurrency = get_int(6)
                if concurrency: extra['concurrency'] = concurrency

                raw_entries.append({
                    'domain': domain,
                    'redirection': redirection,
                    'service': service,
                    'anubis_sub': anubis_sub,
                    'extra': extra,
                    'root': get_root_domain(domain)
                })

    except Exception as e:
        print(f"    ❌ Error reading CSV: {e}")
        return

    if not raw_entries:
        print("    ℹ️  No valid entries found (domains.csv is empty or comments only). Generating empty configs.")
        
    else:
        print(f"    ✅ Successfully processed {len(raw_entries)} domains.")

    if error_count > 0:
        print(f"    ⚠️ WARN: {error_count} lines were skipped due to format errors.")

    print(f"    ⚙️ Global Config: Rate={G_RATE_AVG}/{G_RATE_BURST}, HSTS={HSTS_SECONDS}s")

    services = {}

    # -------------------------------------------------------------------------
    # Traefik Dynamic Configuration (HTTP & TLS)
    # -------------------------------------------------------------------------
    traefik_dynamic_conf = {
        'http': {
            # Timeouts for legacy backends
            'serversTransports': {
                'legacy-transport': {
                    'forwardingTimeouts': {
                        'responseHeaderTimeout': f"{T_ACTIVE}s", # Wait T_ACTIVE (default 60s) for the first byte
                        'idleConnTimeout': f"{T_IDLE}s"          # Keep idle connection a bit longer (default 90s)
                    }
                }
            },
            'middlewares': {
                # 1. Browser Security (Parameterized Headers)
                'security-headers': {
                    'headers': {
                        'frameDeny': not bool(FRAME_ANCESTORS),
                        'sslRedirect': True,
                        'browserXssFilter': True,
                        'contentTypeNosniff': True,
                        'stsIncludeSubdomains': True,
                        'stsPreload': True,
                        'stsSeconds': HSTS_SECONDS,
                        'customFrameOptionsValue': 'SAMEORIGIN' if not FRAME_ANCESTORS else '',
                        'contentSecurityPolicy': f"frame-ancestors 'self' {FRAME_ANCESTORS.replace(',', ' ')}" if FRAME_ANCESTORS else None
                    }
                },
                # 3. Global Compression
                'global-compress': {
                    'compress': {'minResponseBodyBytes': 1024}
                },
                # 4. Traefik Rate Limit
                'global-ratelimit': {
                    'rateLimit': {
                        'average': G_RATE_AVG,
                        'burst': G_RATE_BURST
                    }
                },
                # 5. Traefik Concurrency
                'global-concurrency': {
                    'inFlightReq': {'amount': G_CONCURRENCY}
                },
                # 6. Protocol Forwarder (For Apache/WordPress HTTP->HTTPS redirect fix)
                'apache-forward-headers': {
                    'headers': {
                        'customRequestHeaders': {
                            'X-Forwarded-Proto': 'https'
                        }
                    }
                },
                # 7. Anubis Assets Stripper
                # Cleans the internal Go path so Nginx receives a clean path.
                'anubis-assets-stripper': {
                    'stripPrefix': {
                        'prefixes': ['/.within.website/x/cmd/anubis']
                    }
                },
                # 8. Anubis CSS Replacement
                # Transforms the unusual Go request into your local file name
                'anubis-css-replace': {
                    'replacePath': {
                        'path': '/custom.css'
                    }
                },
                # 9. DDoS Protection: Buffering
                # Protects against Slowloris attacks
                'global-buffering': {
                    'buffering': {
                        'maxRequestBodyBytes': 0, # No limit for body (handled by other layers)
                        'memRequestBodyBytes': 2097152, # 2MB in memory
                        'maxResponseBodyBytes': 0,
                        'memResponseBodyBytes': 2097152 # 2MB in memory
                    }
                },
            },
            'routers': {},
            'services': {
                # 1. External Backend Service (Host Apache on 8080)
                'apache-host-8080': {
                    'loadBalancer': {
                        'serversTransport': 'legacy-transport',
                        # Fixed IP for Linux environments where host.docker.internal may vary
                        'servers': [{'url': 'http://172.17.0.1:8080'}],
                        'passHostHeader': True
                    }
                }
            }
        }
    }

    # Blocked Paths Middleware (If configured)
    if BLOCKED_PATHS:
        traefik_dynamic_conf['http']['middlewares']['block-unwanted-paths'] = {
            'ipAllowList': {
                'sourceRange': ['127.0.0.1/32']
            }
        }

    # 10. CrowdSec API Check Plugin (Only if enabled)
    if not CROWDSEC_DISABLE:
        traefik_dynamic_conf['http']['middlewares']['crowdsec-check'] = {
            'plugin': {
                'crowdsec': {
                    'enabled': True,
                    'crowdsecLapiScheme': 'http',
                    'crowdsecLapiHost': 'crowdsec:8080',
                    'crowdsecLapiKey': CROWDSEC_API_KEY,
                    'crowdsecMode': 'stream',
                    'updateIntervalSeconds': CS_UPDATE_INTERVAL
                }
            }
        }

    # -------------------------------------------------------------------------
    # TLS Grouping Logic (SAN / Chunking) - SKIPPED IN LOCAL DEV
    # -------------------------------------------------------------------------
    domain_to_cert_def = {}
    tls_configs = []

    if not IS_LOCAL_DEV:
        # 1. Group all domains by their root
        domains_by_root = defaultdict(list)
        for entry in raw_entries:
            domains_by_root[entry['root']].append(entry['domain'])

            if entry['anubis_sub']:
                full_anubis_url = f"{entry['anubis_sub']}.{entry['root']}"
                domains_by_root[entry['root']].append(full_anubis_url)

        # 2. Generate the chunked 'tls.domains' configuration
        for root_domain, subdomains in domains_by_root.items():
            # Deduplicate preserving order (Python 3.7+ dicts preserve insertion order)
            subs_unicos = list(dict.fromkeys(subdomains))
            
            # Chunking loop in batches of TLS_BATCH_SIZE
            for i in range(0, len(subs_unicos), TLS_BATCH_SIZE):
                batch = subs_unicos[i:i + TLS_BATCH_SIZE]
                
                # The first one is Main, the rest are SANs
                cert_def = {"main": batch[0]}
                if len(batch) > 1:
                    cert_def["sans"] = batch[1:]
                
                tls_configs.append(cert_def)

        # Map domain -> certificate definition (batch)
        for batch in tls_configs:
            domains_in_batch = [batch['main']] + batch.get('sans', [])
            for d in domains_in_batch:
                domain_to_cert_def[d] = batch
                
        print(f"    🔐 TLS Config: Generated {len(tls_configs)} certificates grouped (Batch size: {TLS_BATCH_SIZE}).")
    else:
        print("    🏠 Local Dev Mode: Skipping Let's Encrypt TLS grouping (Self-Signed).")

    protected_groups = {}
    anubis_service_names = set() 

    for entry in raw_entries:
        if entry['anubis_sub']:
            key = (entry['root'], entry['anubis_sub'])
            if key not in protected_groups:
                protected_groups[key] = []
            protected_groups[key].append(entry)

        # Pass the reference to the HTTP section of the config AND the cert map
        process_router(entry, traefik_dynamic_conf['http'], domain_to_cert_def)

    # -------------------------------------------------------------------------
    # Anubis Services & Routers Generation
    # -------------------------------------------------------------------------
    for (root, auth_sub), entries in protected_groups.items():
        safe_root = sanitize_name(root)
        safe_auth = sanitize_name(auth_sub)

        anubis_service_name = f"anubis-{safe_root}-{safe_auth}"
        anubis_service_names.add(anubis_service_name)

        all_subdomains = [e['domain'] for e in entries]
        redirect_domains_str = ",".join(all_subdomains)
        public_url = f"https://{auth_sub}.{root}"

        services[anubis_service_name] = {
            'extends': {
                'file': BASE_FILENAME,
                'service': 'anubis-base'
            },
            'environment': [
                f"PUBLIC_URL={public_url}",
                f"REDIRECT_DOMAINS={redirect_domains_str}",
                f"COOKIE_PREFIX={safe_root}"
            ],
            'labels': [
                "traefik.enable=true",
                "traefik.docker.network=traefik",
                f"traefik.http.services.{anubis_service_name}.loadbalancer.server.port=8080"
            ],
            'networks': [
                "traefik",
                "anubis-backend"
            ]
        }

        # Middleware for Anubis
        mw_auth_name = f"anubis-mw-{safe_root}-{safe_auth}"
        traefik_dynamic_conf['http']['middlewares'][mw_auth_name] = {
            'forwardAuth': {
                'address': f"http://{anubis_service_name}:8080/.within.website/x/cmd/anubis/api/check",
                'trustForwardHeader': True,
                'authResponseHeaders': ["X-Anubis-Ray-Id"]
            }
        }

        # 1. Anubis: Router for Images
        assets_router_name = f"anubis-assets-img-{safe_root}-{safe_auth}"
        traefik_dynamic_conf['http']['routers'][assets_router_name] = {
            'rule': f"Host(`{auth_sub}.{root}`) && (Path(`/.within.website/x/cmd/anubis/static/img/pensive.webp`) || Path(`/.within.website/x/cmd/anubis/static/img/reject.webp`))",
            'entryPoints': ["websecure"],
            'service': "anubis-assets@docker", 
            'priority': 2000, 
            'tls': {},
            'middlewares': ["security-headers", "anubis-assets-stripper", "global-compress"]
        }
        
        # Configure TLS
        if not IS_LOCAL_DEV:
             traefik_dynamic_conf['http']['routers'][assets_router_name]['tls']['certResolver'] = os.getenv('TRAEFIK_CERT_RESOLVER', 'le')

        
        # Inject TLS domains if specific batch exists
        auth_domain = f"{auth_sub}.{root}"
        if not IS_LOCAL_DEV and auth_domain in domain_to_cert_def:
             traefik_dynamic_conf['http']['routers'][assets_router_name]['tls']['domains'] = [domain_to_cert_def[auth_domain]]

        # 2. Anubis: Router for CSS
        css_router_name = f"anubis-assets-css-{safe_root}-{safe_auth}"
        traefik_dynamic_conf['http']['routers'][css_router_name] = {
            'rule': f"Host(`{auth_sub}.{root}`) && Path(`/.within.website/x/xess/xess.min.css`)",
            'entryPoints': ["websecure"],
            'service': "anubis-assets@docker", 
            'priority': 2000, 
            'tls': {},
            'middlewares': ["security-headers", "anubis-css-replace", "global-compress"]
        }

        # Configure TLS
        if not IS_LOCAL_DEV:
             traefik_dynamic_conf['http']['routers'][css_router_name]['tls']['certResolver'] = os.getenv('TRAEFIK_CERT_RESOLVER', 'le')


        if not IS_LOCAL_DEV and auth_domain in domain_to_cert_def:
             traefik_dynamic_conf['http']['routers'][css_router_name]['tls']['domains'] = [domain_to_cert_def[auth_domain]]

        # 3. Anubis: Main Router
        panel_router_name = f"anubis-panel-{safe_root}-{safe_auth}"
        traefik_dynamic_conf['http']['routers'][panel_router_name] = {
            'rule': f"Host(`{auth_sub}.{root}`)",
            'entryPoints': ["websecure"],
            'service': f"{anubis_service_name}@docker",
            'tls': {}, 
            'middlewares': ["security-headers"]
        }

        # Configure TLS
        if not IS_LOCAL_DEV:
             traefik_dynamic_conf['http']['routers'][panel_router_name]['tls']['certResolver'] = os.getenv('TRAEFIK_CERT_RESOLVER', 'le')


        if not IS_LOCAL_DEV and auth_domain in domain_to_cert_def:
             traefik_dynamic_conf['http']['routers'][panel_router_name]['tls']['domains'] = [domain_to_cert_def[auth_domain]]

    if services:
        compose_yaml = { 'services': services }
        with open(OUTPUT_COMPOSE, 'w') as f:
            f.write("# AUTOMATICALLY GENERATED BY PYTHON\n")
            yaml.dump(compose_yaml, f, Dumper=IndentDumper, default_flow_style=False, sort_keys=False)
        print(f"    ✅ Docker Compose generated with {len(services)} Anubis instances.")
    else:
        with open(OUTPUT_COMPOSE, 'w') as f:
            f.write("# NO PROTECTED SERVICES FOUND\n")
        print("    ℹ️ No Anubis protected domains found.")

    os.makedirs(os.path.dirname(OUTPUT_TRAEFIK), exist_ok=True)
    with open(OUTPUT_TRAEFIK, 'w') as f:
        f.write("# AUTOMATICALLY GENERATED BY PYTHON\n")
        yaml.dump(traefik_dynamic_conf, f, Dumper=IndentDumper, default_flow_style=False, sort_keys=False)

    print("    ✅ Traefik dynamic configuration generated successfully.")

def generate_policy_file():
    input_policy = 'config/anubis/botPolicy.yaml'
    output_policy = 'config/anubis/botPolicy-generated.yaml'

    if not os.path.exists(input_policy):
        print(f"    ⚠️ WARN: {input_policy} not found, skipping policy generation.")
        return

    print(f"    🛡️ Generating security policy in {output_policy}...")

    try:
        with open(input_policy, 'r') as f:
            policy_data = yaml.safe_load(f)

        if REDIS_PASSWORD:
            policy_data['store']['parameters']['url'] = f"redis://:{REDIS_PASSWORD}@redis:6379/0"
        else:
            print("    ⚠️ WARN: REDIS_PASSWORD not set. Redis will be exposed.")
            policy_data['store']['parameters']['url'] = "redis://redis:6379/0"

        with open(output_policy, 'w') as f:
            f.write("# AUTOMATICALLY GENERATED - DO NOT EDIT\n")
            yaml.dump(policy_data, f, Dumper=IndentDumper, default_flow_style=False, sort_keys=False)

    except Exception as e:
        print(f"    ❌ Error generating policy: {e}")

if __name__ == "__main__":
    generate_configs()
    generate_policy_file()