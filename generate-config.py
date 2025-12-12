import tldextract
import yaml
import os
import csv
import re
from collections import defaultdict  # <--- To group domains

# ================= CONFIGURATION =================
INPUT_FILE = 'domains.csv'
BASE_FILENAME = 'docker-compose-anubis-base.yml'
OUTPUT_COMPOSE = 'docker-compose-anubis-generated.yml'
OUTPUT_TRAEFIK = 'config-traefik/dynamic-config/routers-generated.yml'

# ============= ENVIRONMENT VARIABLES =============
CROWDSEC_API_KEY = os.getenv('CROWDSEC_API_KEY')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
# LOGO_URL ya no es necesaria como variable de entorno para el redirect, 
# pero la dejamos por si la usas en otro sitio, aunque la logica de assets ahora es local.
LOGO_URL = os.getenv('ANUBIS_LOGO_URL', 'https://mydomain.com/anubis-loading.gif')

# TLS Chunking Limit (Let's Encrypt max is 100, we use a smaller amount for safety)
TLS_BATCH_SIZE = 90

# CrowdSec Update Interval
try:
    CS_UPDATE_INTERVAL = int(os.getenv('CROWDSEC_UPDATE_INTERVAL', 60))
except ValueError:
    CS_UPDATE_INTERVAL = 60

# Global Rate Limits
try:
    G_RATE_AVG = int(os.getenv('GLOBAL_RATE_AVG', 60))
    G_RATE_BURST = int(os.getenv('GLOBAL_RATE_BURST', 120))
except ValueError:
    G_RATE_AVG = 60
    G_RATE_BURST = 120

# Global Concurrency
try:
    G_CONCURRENCY = int(os.getenv('GLOBAL_CONCURRENCY', 25))
except ValueError:
    G_CONCURRENCY = 25

# HSTS Configuration
try:
    HSTS_SECONDS = int(os.getenv('HSTS_MAX_AGE', 31536000))
except ValueError:
    HSTS_SECONDS = 31536000

# Regex for validating Docker/Traefik service names (alphanumeric and hyphens only)
VALID_SERVICE_NAME_REGEX = re.compile(r'^[a-z0-9-]+$')

if not CROWDSEC_API_KEY:
    print("    ❌ FATAL ERROR: CROWDSEC_API_KEY environment variable not found.")
    exit(1)

if not REDIS_PASSWORD:
    print("    ❌ FATAL ERROR: REDIS_PASSWORD environment variable not found.")
    exit(1)

# Custom Dumper to avoid excessive indentation (KISS principle applied to YAML structure)
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

                if len(row) < 2:
                    print(f"    ⚠️ WARN [Line {line_num}] Ignored: Insufficient data.")
                    error_count += 1
                    continue

                domain = row[0].strip()
                service = row[1].strip().lower() # Standardize service name to lowercase
                anubis_sub = row[2].strip().lower() if len(row) > 2 else ""

                # --- ROBUSTNESS CHECK: Docker Service Name Format ---
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

                rate = get_int(3)
                if rate: extra['rate'] = rate
                burst = get_int(4)
                if burst: extra['burst'] = burst
                concurrency = get_int(5)
                if concurrency: extra['concurrency'] = concurrency

                raw_entries.append({
                    'domain': domain,
                    'service': service,
                    'anubis_sub': anubis_sub,
                    'extra': extra,
                    'root': get_root_domain(domain)
                })

    except Exception as e:
        print(f"    ❌ Error reading CSV: {e}")
        return

    if not raw_entries:
        print("    ❌ No valid entries found.")
        return

    print(f"    ✅ Successfully processed {len(raw_entries)} domains.")
    if error_count > 0:
        print(f"    ⚠️ WARN: {error_count} lines were skipped due to format errors.")
    print(f"    ⚙️ Global Config: Rate={G_RATE_AVG}/{G_RATE_BURST}, HSTS={HSTS_SECONDS}s")

    services = {}

    # === TRAEFIK DYNAMIC CONFIGURATION ===
    # Main structure that will contain 'http' and 'tls'
    traefik_dynamic_conf = {
        'http': {
            'middlewares': {
                # 1. BROWSER SECURITY (PARAMETERIZED HEADERS)
                'security-headers': {
                    'headers': {
                        'frameDeny': True,
                        'sslRedirect': True,
                        'browserXssFilter': True,
                        'contentTypeNosniff': True,
                        'stsIncludeSubdomains': True,
                        'stsPreload': True,
                        'stsSeconds': HSTS_SECONDS,
                        'customFrameOptionsValue': 'SAMEORIGIN'
                    }
                },
                # 2. CROWDSEC API CHECK PLUGIN
                'crowdsec-check': {
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
                },
                # 3. GLOBAL COMPRESSION
                'global-compress': {
                    'compress': {'minResponseBodyBytes': 1024}
                },
                # 4. TRAEFIK RATE LIMIT
                'global-ratelimit': {
                    'rateLimit': {
                        'average': G_RATE_AVG,
                        'burst': G_RATE_BURST
                    }
                },
                # 5. TRAEFIK CONCURRENCY
                'global-concurrency': {
                    'inFlightReq': {'amount': G_CONCURRENCY}
                },
                # 6. PROTOCOL FORWARDER (For Apache/WordPress HTTP->HTTPS redirect fix)
                'apache-forward-headers': {
                    'headers': {
                        'customRequestHeaders': {
                            'X-Forwarded-Proto': 'https'
                        }
                    }
                },
                # 7. ANUBIS ASSETS STRIPPER
                # Limpia la ruta interna de Go para que Nginx reciba una ruta limpia.
                # Elimina "/.within.website/x/cmd/anubis" para dejar "/static/img/..."
                'anubis-assets-stripper': {
                    'stripPrefix': {
                        'prefixes': ['/.within.website/x/cmd/anubis']
                    }
                },
            },
            'routers': {},
            'services': {
                # 1. EXTERNAL BACKEND SERVICE CONFIGURATION (HOST APACHE ON 8080)
                # This service is defined statically here (@file) and will be referenced
                # by routers if the 'docker_service' column in domains.csv is 'apache-host'.
                'apache-host-8080': {
                    'loadBalancer': {
                        # Fixed IP used since host.docker.internal failed in the user's Linux environment
                        # NOTE: '172.17.0.1' is the default bridge gateway on Linux. 
                        # For macOS/Windows Docker Desktop, this IP will NOT work (logic requires 'host.docker.internal').
                        'servers': [{'url': 'http://172.17.0.1:8080'}],
                        'passHostHeader': True
                    }
                }
            }
        }
    }

    # =========================================================================
    # TLS GROUPING LOGIC (SAN GROUPING / CHUNKING)
    # =========================================================================
    # 1. Group all domains by their root
    domains_by_root = defaultdict(list)
    for entry in raw_entries:
        domains_by_root[entry['root']].append(entry['domain'])

        # We also add the Anubis subdomain to the certificate if it exists
        if entry['anubis_sub']:
            full_anubis_url = f"{entry['anubis_sub']}.{entry['root']}"
            domains_by_root[entry['root']].append(full_anubis_url)

    # 2. Generate the chunked 'tls.domains' configuration
    tls_configs = []
    
    for root_domain, subdomains in domains_by_root.items():
        # Deduplicate and sort for consistency
        subs_unicos = sorted(list(set(subdomains)))
        
        # Chunking loop in batches of TLS_BATCH_SIZE
        for i in range(0, len(subs_unicos), TLS_BATCH_SIZE):
            batch = subs_unicos[i:i + TLS_BATCH_SIZE]
            
            # The first one is Main, the rest are SANs
            cert_def = {"main": batch[0]}
            if len(batch) > 1:
                cert_def["sans"] = batch[1:]
            
            tls_configs.append(cert_def)

    # Map domain -> certificate definition (batch)
    domain_to_cert_def = {}
    for batch in tls_configs:
         domains_in_batch = [batch['main']] + batch.get('sans', [])
         for d in domains_in_batch:
             domain_to_cert_def[d] = batch
             
    print(f"    🔐 TLS Config: Generated {len(tls_configs)} certificates grouped (Batch size: {TLS_BATCH_SIZE}).")
    # =========================================================================


    protected_groups = {}
    anubis_service_names = set() # To track generated Anubis service names

    for entry in raw_entries:
        if entry['anubis_sub']:
            key = (entry['root'], entry['anubis_sub'])
            if key not in protected_groups:
                protected_groups[key] = []
            protected_groups[key].append(entry)

        # Pass the reference to the HTTP section of the config AND the cert map
        process_router(entry, traefik_dynamic_conf['http'], domain_to_cert_def)

    # GENERATE ANUBIS SERVICES
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
            'container_name': anubis_service_name,
            'environment': [
                f"PUBLIC_URL={public_url}",
                f"REDIRECT_DOMAINS={redirect_domains_str}"
            ],
            # Minimal labels required for Traefik to discover the Anubis container
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

        # --- ANUBIS ASSETS ROUTER (OPTIMIZATION) ---
        # Intercepts requests for logo/reject image and serves them via Nginx local container
        assets_router_name = f"anubis-assets-{safe_root}-{safe_auth}"
        traefik_dynamic_conf['http']['routers'][assets_router_name] = {
            # Matches Anubis subdomain AND specific image paths
            'rule': f"Host(`{auth_sub}.{root}`) && (Path(`/.within.website/x/cmd/anubis/static/img/pensive.webp`) || Path(`/.within.website/x/cmd/anubis/static/img/reject.webp`))",
            'entryPoints': ["websecure"],
            'service': "anubis-assets@docker", # Defined in global docker-compose
            'priority': 2000, # High priority to override the general Anubis router
            'tls': {'certResolver': 'le', 'domains': [domain_to_cert_def.get(f"{auth_sub}.{root}", {})]},
            'middlewares': ["security-headers", "anubis-assets-stripper", "global-compress"]
        }

        # Router for Anubis Portal (Standard)
        panel_router_name = f"anubis-panel-{safe_root}-{safe_auth}"
        traefik_dynamic_conf['http']['routers'][panel_router_name] = {
            'rule': f"Host(`{auth_sub}.{root}`)",
            'entryPoints': ["websecure"],
            'service': f"{anubis_service_name}@docker",
            'tls': {'certResolver': 'le', 'domains': [domain_to_cert_def.get(f"{auth_sub}.{root}", {})]}, 
            'middlewares': ["security-headers"] # No longer using 'anubis-custom-logo'
        }

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

def process_router(entry, http_section, domain_to_cert_def):
    domain = entry['domain']
    service = entry['service']
    anubis_sub = entry['anubis_sub']
    extra = entry['extra']
    root = entry['root']

    safe_domain = sanitize_name(domain)
    router_name = f"router-{safe_domain}"

    mw_list = ['crowdsec-check', 'security-headers']

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

    mw_list.append('global-compress')

    if anubis_sub:
        safe_root = sanitize_name(root)
        safe_auth = sanitize_name(anubis_sub)
        mw_auth_name = f"anubis-mw-{safe_root}-{safe_auth}"
        mw_list.append(mw_auth_name)

    if service == 'apache-host':
        mw_list.append('apache-forward-headers')

    if service == 'apache-host':
        target_service = 'apache-host-8080@file'
    else:
        target_service = f"{service}@docker"

    # Router config
    router_conf = {
        'rule': f"Host(`{domain}`)",
        'entryPoints': ["websecure"],
        'service': target_service,
        'tls': {'certResolver': 'le'},
        'middlewares': mw_list
    }
    
    # Inject TLS domains if we have a specific batch for this domain
    if domain in domain_to_cert_def:
        router_conf['tls']['domains'] = [domain_to_cert_def[domain]]

    http_section['routers'][router_name] = router_conf

def generate_policy_file():
    input_policy = 'config-anubis/botPolicy.yaml'
    output_policy = 'config-anubis/botPolicy-generated.yaml'

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