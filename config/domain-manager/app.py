
import os
import csv
import subprocess
import secrets
import re
import socket
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import json
import base64
import datetime
import tldextract
from collections import defaultdict
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get('DOMAIN_MANAGER_SECRET_KEY', secrets.token_hex(32))

# --- Hardened Session Settings ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # In production via Traefik HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800, # 30 minutes
    SESSION_COOKIE_PATH='/' # Ensure cookie is valid for all subpaths
)

# Apply ProxyFix to handle X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-Prefix
# x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- Rate Limiter Setup ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

ADMIN_USER = os.environ.get('DOMAIN_MANAGER_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('DOMAIN_MANAGER_ADMIN_PASSWORD', 'admin')

# Mirror the host path inside the container
BASE_DIR = os.environ.get('DOMAIN_MANAGER_APP_PATH_HOST', os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
CSV_PATH = os.path.join(BASE_DIR, 'domains.csv')
START_SCRIPT = os.path.join(BASE_DIR, 'scripts/start.sh')
ACME_FILE = os.path.join(BASE_DIR, 'config/traefik/acme.json')

print(f"DEBUG: BASE_DIR={BASE_DIR}")
print(f"DEBUG: CSV_PATH={CSV_PATH}")
print(f"DEBUG: START_SCRIPT={START_SCRIPT}")

DOMAIN = os.environ.get('DOMAIN', 'localhost')
TRAEFIK_RATE_AVG = os.environ.get('TRAEFIK_GLOBAL_RATE_AVG', '60')
TRAEFIK_RATE_BURST = os.environ.get('TRAEFIK_GLOBAL_RATE_BURST', '120')
TRAEFIK_CONCURRENCY = os.environ.get('TRAEFIK_GLOBAL_CONCURRENCY', '25')
TRAEFIK_ACME_ENV_TYPE = os.environ.get('TRAEFIK_ACME_ENV_TYPE', 'production')
DASHBOARD_SUBDOMAIN = os.environ.get('DASHBOARD_SUBDOMAIN', 'dashboard')
ENV = os.environ.copy()
ENV['TERM'] = 'xterm'

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/dm-api/') or request.path == '/dm-api/restart-stream':
                return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def check_csrf():
    if request.path == '/':
         print(f"DEBUG: app.view_functions keys: {list(app.view_functions.keys())}")

    if request.endpoint == 'login':
        return
    
    # Standard POST check
    if request.method == "POST":
        token = request.headers.get('X-CSRFToken')
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'CSRF token missing or invalid'}), 403

    # Special check for restart-stream (GET side-effect)
    if request.endpoint == 'restart_stream':
        token = request.args.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'CSRF token missing or invalid'}), 403

def validate_domain_data(entry):
    # Strict validation to ensure no malicious content in CSV or shell injection
    # We restrict characters to alphanumeric, basic domain/path symbols
    allowed_pattern = re.compile(r'^[a-zA-Z0-9\.\-\_\/]+$')
    
    # Text fields that shouldn't contain weird characters
    fields_to_check = ['domain', 'redirection', 'service_name', 'anubis_subdomain']
    
    if not entry.get('domain') or not entry.get('service_name'): 
        return False # Domain and Service are mandatory
        
    for field in fields_to_check:
        val = entry.get(field, '')
        if val and not allowed_pattern.match(str(val)):
            return False
            
    # Numeric fields
    for field in ['rate', 'burst', 'concurrency']:
        val = entry.get(field, '')
        if val and not str(val).isdigit():
            return False
            
    return True

def get_root_domain(domain):
    extracted = tldextract.extract(domain)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain

# Parse certificate details (CN, SANs, Expiration) using OpenSSL
def parse_certificate_data(cert_b64):
    try:
        # Decode base64 to get PEM
        cert_pem = base64.b64decode(cert_b64).decode('utf-8')
        
        # Use openssl to extract info
        # -subject: extracts Subject (Owner)
        # -enddate: extracts Expiration
        # -ext subjectAltName: extracts SANs
        cmd = ['openssl', 'x509', '-noout', '-subject', '-enddate', '-ext', 'subjectAltName']
        process = subprocess.Popen(
            cmd, 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input=cert_pem)
        
        if process.returncode != 0:
            return {
                'error': f"Error: {stderr.strip()}",
                'valid_days': -1,
                'expiration_text': "Error",
                'cn': "Unknown",
                'sans': []
            }

        # Defaults
        data = {
            'error': None,
            'valid_days': -1,
            'expiration_timestamp': 0, # For precise sorting
            'expiration_text': "",
            'cn': "",
            'sans': []
        }

        # Parse Line by Line
        for line in stdout.splitlines():
            line = line.strip()
            # 1. Subject/CN
            # format: subject=CN = softest2023.sailti.com
            if line.startswith('subject='):
                # Extract CN
                match = re.search(r'CN\s*=\s*([^,]+)', line)
                if match:
                    data['cn'] = match.group(1).strip()
            
            # 2. Expiration
            # format: notAfter=May 17 12:14:44 2026 GMT
            if line.startswith('notAfter='):
                date_str = line.split('=', 1)[1]
                try:
                    dt = datetime.datetime.strptime(date_str, '%b %d %H:%M:%S %Y GMT')
                    formatted = dt.strftime('%Y-%m-%d %H:%M:%S')
                    now = datetime.datetime.utcnow()
                    delta = dt - now
                    data['valid_days'] = delta.days
                    data['expiration_timestamp'] = dt.timestamp()
                    data['expiration_text'] = f"{formatted} ({delta.days} days left)"
                except:
                    data['expiration_text'] = date_str
            
            # 3. SANs
            # format: DNS:domain1.com, DNS:domain2.com, ...
            # it might be on the line following "X509v3 Subject Alternative Name:" or inline depending on openssl version/format
            # But with -ext subjectAltName, typically output starts with the header then the content
            if line.startswith('DNS:'):
                 # Splitting by comma
                 parts = [p.strip().replace('DNS:', '') for p in line.split(',')]
                 data['sans'].extend(parts)

        # Fallback if SANs were on a new line (common in some openssl versions)
        # output of -ext is usually:
        # X509v3 Subject Alternative Name: 
        #    DNS:a.com, DNS:b.com
        if not data['sans'] and 'Subject Alternative Name' in stdout:
             # Find the block
             # Check distinct lines again or regex the whole blob
             sans_match = re.search(r'Subject Alternative Name:\s*\n\s*(.*)', stdout, re.MULTILINE)
             if sans_match:
                 san_line = sans_match.group(1).strip()
                 parts = [p.strip().replace('DNS:', '') for p in san_line.split(',')]
                 data['sans'].extend(parts)
        
        return data

    except Exception as e:
         return {
                'error': f"Exception: {e}",
                'valid_days': -1,
                'expiration_timestamp': 0,
                'expiration_text': str(e),
                'cn': "Error",
                'sans': []
            }


def read_csv():
    data = []
    if not os.path.exists(CSV_PATH):
        return data
    with open(CSV_PATH, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue

            # Determine if enabled (not commented) or disabled (commented)
            enabled = True
            first_col = row[0].strip()
            
            # 1. Handle Commented Lines (Disabled Domains OR Pure Comments)
            if first_col.startswith('#'):
                # Remove the leading # and whitespace
                clean_content = first_col.lstrip('#').strip()
                
                # A. Detect Header: matches "domain" and "redirection"
                #    (Checking row[1] index safely requires checking length first)
                if 'domain' in clean_content.lower() and len(row) > 1 and 'redirection' in row[1].lower():
                    continue

                # B. Detect Pure Comments / Separators (e.g. "---", "Section Title")
                #    If it doesn't look like a domain (has spaces, no dots, etc), skip it.
                #    Simple heuristic: valid domains don't usually have spaces.
                if ' ' in clean_content or not clean_content:
                    continue

                # C. It's a disabled domain
                enabled = False
                row[0] = clean_content
            
            # 2. Ensure row has enough columns (pad if necessary)
            # domain, redirection, service_name, anubis_subdomain, rate, burst, concurrency
            while len(row) < 7:
                row.append('')
            
            # 3. Create Entry Object
            entry = {
                'domain': row[0].strip(),
                'redirection': row[1].strip(),
                'service_name': row[2].strip(),
                'anubis_subdomain': row[3].strip(),
                'rate': row[4].strip(),
                'burst': row[5].strip(),
                'concurrency': row[6].strip(),
                'enabled': enabled
            }
            
            # 4. Final Validation (Skip garbage that might have slipped through)
            #    We reuse the same validation logic we use for writing.
            #    This prevents "----------------" or other junk from breaking the UI.
            if validate_domain_data(entry):
                data.append(entry)

    return data

def write_csv(data):
    # Preserving comments is hard with simple csv writer.
    # We will overwrite but try to keep the header.
    header = "# domain, redirection, service_name, anubis_subdomain, rate, burst, concurrency"
    
    with open(CSV_PATH, mode='w', encoding='utf-8', newline='') as f:
        f.write(header + '\n\n')
        writer = csv.writer(f)
        for entry in data:
            if not validate_domain_data(entry):
                print(f"Skipping invalid entry: {entry}")
                continue
            
            domain_val = entry['domain']
            if not entry.get('enabled', True):
                domain_val = f"# {domain_val}"
            
            writer.writerow([
                domain_val,
                entry['redirection'],
                entry['service_name'],
                entry['anubis_subdomain'],
                entry['rate'],
                entry['burst'],
                entry['concurrency']
            ])

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def check_host_file(domain):
    try:
        with open('/etc/hosts', 'r') as f:
            for line in f:
                if domain in line and not line.strip().startswith('#'):
                    return True
    except:
        pass
    return False

def get_external_services():
    try:
        # Per user request: strictly use container names.
        # This allows selecting specific containers like 'ib1-api' vs 'ib2-api'.
        # NOTE: This means for stack services you must use the full container name (e.g. stack-traefik-1)
        cmd = ["docker", "ps", "--format", "{{.Names}}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            services = result.stdout.strip().split('\n')
            unique_services = sorted(list(set([s.strip() for s in services if s.strip()])))
            print(f"DEBUG: Found containers: {unique_services}")
            return unique_services
        
        print(f"DEBUG: Error running docker ps: {result.stderr}")
        return []
    except Exception as e:
        print(f"Error getting services: {e}")
        return []

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # Debug: Print headers to see what Traefik sends
    # print(f"DEBUG LOGIN HEADERS: {request.headers}")
    
    if request.method == 'POST':
        # Simple prevention of empty submissions
        user = request.form.get('username', '')
        pw = request.form.get('password', '')
        
        # Priority for next_url: Form data > X-Replaced-Path (Traefik Error Page) > Referrer (Direct Access)
        next_url = request.form.get('next')
        if not next_url:
            next_url = request.headers.get('X-Replaced-Path')
        
        # If still empty, check Referrer (this happens when user is on /dozzle and clicks Sign In)
        if not next_url and request.referrer:
            referrer = request.referrer
            # Extract path from referrer if it belongs to our domain
            if DOMAIN in referrer:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(referrer)
                    if parsed.path and parsed.path != '/login':
                        next_url = parsed.path
                except:
                    pass
        
        print(f"DEBUG LOGIN POST: User={user}, Next={next_url}")

        if user == ADMIN_USER and pw == ADMIN_PASS:
            session.clear() # Clear any existing session to prevent fixation
            session['logged_in'] = True
            session.permanent = True
            
            # Helper to validate next_url (prevent open redirects)
            if next_url and next_url.startswith('/'):
                 print(f"DEBUG: Redirecting to {next_url}")
                 return redirect(next_url)
            
            print("DEBUG: Redirecting to dashboard")
            return redirect(url_for('dashboard'))
        
        # Log failure (useful for external monitoring or security logs)
        print(f"SECURITY: Failed login attempt for user '{user}' from {request.remote_addr}")
        return render_template('login.html', error='Invalid credentials', domain=DOMAIN, next=next_url)
    
    # GET: Capture 'next' from query or Referer or X-Replaced-Path
    next_url = request.args.get('next') or request.headers.get('X-Replaced-Path') or request.referrer
    
    # Ensure we don't redirect back to login itself
    if next_url and '/login' in next_url:
        next_url = None
    
    print(f"DEBUG LOGIN GET: Next={next_url}")
    return render_template('login.html', domain=DOMAIN, next=next_url)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))
@app.route('/auth-check')
@limiter.exempt
def auth_check():
    """
    Forward Auth endpoint for Traefik.
    Returns 200 if user is logged in, 401 otherwise.
    """
    if session.get('logged_in'):
        return Response("OK", status=200)
    return Response("Unauthorized", status=401)

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', domain=DOMAIN)

@app.route('/domains')
@login_required
def index():
    return render_template('index.html', 
                           domain=DOMAIN,
                           rate_avg=TRAEFIK_RATE_AVG,
                           rate_burst=TRAEFIK_RATE_BURST,
                           concurrency=TRAEFIK_CONCURRENCY)

@app.route('/certs')
@login_required
def certs_view():
    # 1. Load Expected Domains from CSV
    expected_domains = set()
    csv_data = read_csv()
    for row in csv_data:
        if row.get('enabled', True): # Only check enabled domains? Or all? User said "all domains.csv are generated"
             d = row.get('domain', '').strip().lower()
             if d:
                 expected_domains.add(d)
             
             # Check for Anubis subdomain
             anubis = row.get('anubis_subdomain', '').strip()
             if anubis and d:
                 root = get_root_domain(d)
                 expected_domains.add(f"{anubis}.{root}".lower())

    # 2. Load Certificates from acme.json
    acme_data = {}
    if os.path.exists(ACME_FILE) and os.path.getsize(ACME_FILE) > 0:
        try:
            with open(ACME_FILE, 'r') as f:
                acme_data = json.load(f)
        except Exception as e:
            print(f"Error loading acme.json: {e}")

    covered_domains = set()
    certificates_details = []

    # Iterate resolvers
    for resolver_name, resolver_data in acme_data.items():
        if isinstance(resolver_data, dict) and 'Certificates' in resolver_data:
            for cert in resolver_data['Certificates']:
                if 'domain' in cert:
                    # Ignore the 'main' and 'sans' from JSON keys as they might be stale
                    # Parse REAL data from the certificate
                    if cert.get('certificate'):
                        cert_info = parse_certificate_data(cert['certificate'])
                        
                        real_main = cert_info['cn'].lower() if cert_info['cn'] else "unknown"
                        real_sans = [s.lower() for s in cert_info['sans']]
                        
                        # Filter out main from SANs for display
                        real_sans_cleaned = [s for s in real_sans if s != real_main]
                        
                        # Update stats coverage
                        if real_main != 'unknown':
                            covered_domains.add(real_main)
                            for s in real_sans_cleaned:
                                covered_domains.add(s)

                        status = 'expired'
                        if cert_info['valid_days'] > 30:
                            status = 'valid'
                        elif cert_info['valid_days'] > 0:
                            status = 'warning'
                        
                        certificates_details.append({
                            'main': real_main,
                            'sans': real_sans_cleaned,
                            'root': get_root_domain(real_main) if real_main != 'unknown' else 'Unknown',
                            'expiration': cert_info['expiration_text'],
                            'valid_days': cert_info['valid_days'], # Needed for sorting context if visual
                            'expiration_timestamp': cert_info.get('expiration_timestamp', 0),
                            'status': status,
                            'superseded': False # Default
                        })
                    else:
                        # Fallback if no certificate data (shouldn't happen for valid entries)
                        continue

    # 3. Post-process to identify superseded certificates
    # Group by Main Domain (CN)
    certs_by_main = defaultdict(list)
    for cert in certificates_details:
        certs_by_main[cert['main']].append(cert)
    
    final_certificates = []
    
    for main_domain, certs in certs_by_main.items():
        # If multiple certs for same CN, sort by precise expiration timestamp (more future = newer)
        if len(certs) > 1:
            # Sort descending by expiration_timestamp
            certs.sort(key=lambda x: x.get('expiration_timestamp', 0), reverse=True)
            
            # The first one is active (furthest future expiration), rest are superseded
            for i in range(1, len(certs)):
                certs[i]['superseded'] = True
                certs[i]['status'] = 'superseded' # Override status for display logic if needed
        
        final_certificates.extend(certs)
    
    # Sort final list by root domain then main domain for display
    final_certificates.sort(key=lambda x: (x['root'], x['main']))

    # 4. Calculate Stats (using final list)
    total_certs = len(final_certificates)
    # Count unique active SANs only? Or all? Let's count all to be safe, or just active.
    # User asked for visual indication, not necessarily removing them from stats.
    # But let's keep stats based on what's visible.
    total_sans = sum(len(c['sans']) for c in final_certificates)
    
    missing_domains = expected_domains - covered_domains
    missing_count = len(missing_domains)
    
    # 5. Prepare data for template
    return render_template('certs.html', 
                           domain=DOMAIN,
                           certificates=final_certificates,
                           total_certs=total_certs,
                           total_sans=total_sans,
                           missing_count=missing_count,
                           missing_domains=sorted(list(missing_domains)))


@app.route('/dm-api/domains', methods=['GET', 'POST'])
@login_required
def api_domains():
    if request.method == 'GET':
        return jsonify(read_csv())
    
    if request.method == 'POST':
        data = request.json
        
        # Check for duplicates (only for enabled records)
        seen_domains = {}
        duplicates = []
        for entry in data:
            if not entry.get('enabled', True):
                continue
            domain = entry.get('domain', '').strip().lower()
            if not domain:
                continue
            if domain in seen_domains:
                if domain not in duplicates:
                    duplicates.append(domain)
            seen_domains[domain] = True
        
        if duplicates:
            return jsonify({
                'status': 'error', 
                'message': f'Duplicate domains found: {", ".join(duplicates)}',
                'duplicates': duplicates
            }), 400
            
        # --- MERGE STRATEGY: Preserve Order & Append New ---
        
        # 1. Read existing CSV to get current order
        current_data = read_csv()
        
        # 2. Index new data by domain for fast lookup
        # Key: domain (lowercase), Value: entry dict
        incoming_map = {}
        for entry in data:
            d = entry.get('domain', '').strip().lower()
            if d:
                incoming_map[d] = entry

        # 3. Construct new list
        final_list = []
        processed_domains = set()

        # 3a. Update existing entries in their original order
        for existing_entry in current_data:
            d_existing = existing_entry.get('domain', '').strip().lower()
            
            # If this valid domain exists in internal map (even if commented out in CSV)
            if d_existing in incoming_map:
                # Update it with new values from UI
                # We replace the entire text content with the new one
                final_list.append(incoming_map[d_existing])
                processed_domains.add(d_existing)
            else:
                # It's not in the new list -> It was deleted in UI
                pass 
        
        # 3b. Append NEW entries (those in incoming_map but not in processed_domains)
        # We iterate over the 'data' list from UI to respect the user's *new* addition order among themselves
        for entry in data:
            d = entry.get('domain', '').strip().lower()
            if d and d not in processed_domains:
                final_list.append(entry)
                processed_domains.add(d)
        
        write_csv(final_list)
        return jsonify({'status': 'success'})

@app.route('/dm-api/services', methods=['GET'])
@login_required
def api_services():
    try:
        final_list = get_external_services()
        return jsonify(final_list)
    except Exception as e:
        print(f"Error getting external services: {e}")
        return jsonify([])

# ... (omitted helper funcs) ...

@app.route('/dm-api/check-domain', methods=['POST'])
@limiter.exempt
@login_required 
def check_domain():
    # ... (function body same as before, just route changed)
    data = request.json
    domain_to_check = data.get('domain', '').strip()
    redirection_to_check = data.get('redirection', '').strip()
    service_to_check = data.get('service_name', '').strip()
    anubis_subdomain = data.get('anubis_subdomain', '').strip()
    
    status_response = {
        'status': 'match', # Pessimistic default, starts match, changes on error
        'domain': {'status': 'match'},
        'redirection': {'status': 'skipped'},
        'service': {'status': 'found'},
        'anubis': {'status': 'skipped'}
    }
    
    # 0. Global Host IP
    # We resolve the full dashboard domain using the configurable subdomain
    host_domain = f"{DASHBOARD_SUBDOMAIN}.{os.environ.get('DOMAIN')}"
    expected_ip = resolve_domain(host_domain)
    
    # In local development, the container might not be able to resolve the host domain
    # (e.g. dev.local defined in host /etc/hosts but not in container DNS).
    # If we are in local mode, we relax this check but verify against /etc/hosts via mount
    if not expected_ip:
        TRAEFIK_ACME_ENV_TYPE = os.environ.get('TRAEFIK_ACME_ENV_TYPE', 'local')
        if TRAEFIK_ACME_ENV_TYPE == 'local':
             if check_host_file(host_domain):
                 expected_ip = '127.0.0.1' # Dummy fallback for comparison logic
             else:
                 status_response['status'] = 'error'
                 status_response['domain'] = {'status': 'error', 'message': f'Could not resolve host domain ({host_domain}) locally or in /etc/hosts'}
                 return jsonify(status_response)
        else:
            status_response['status'] = 'error'
            status_response['domain'] = {'status': 'error', 'message': f'Could not resolve host domain ({host_domain})'}
            return jsonify(status_response)
    
    # 1. Domain Check
    if not domain_to_check:
         status_response['domain'] = {'status': 'error', 'message': 'Empty domain'}
         status_response['status'] = 'mismatch'
    else:
        actual_ip = resolve_domain(domain_to_check)
        if not actual_ip:
             if TRAEFIK_ACME_ENV_TYPE == 'local' and check_host_file(domain_to_check):
                 actual_ip = expected_ip
             else:
                 status_response['domain'] = {'status': 'error', 'message': 'Resolution failed'}
                 status_response['status'] = 'mismatch'
        elif actual_ip != expected_ip:
             status_response['domain'] = {
                 'status': 'mismatch', 
                 'expected': expected_ip, 
                 'actual': actual_ip
             }
             status_response['status'] = 'mismatch'
        else:
            status_response['domain']['status'] = 'match'

    # 2. Redirection Check
    if redirection_to_check:
        redir_ip = resolve_domain(redirection_to_check)
        if not redir_ip:
             if TRAEFIK_ACME_ENV_TYPE == 'local' and check_host_file(redirection_to_check):
                 redir_ip = expected_ip
             else:
                 status_response['redirection'] = {'status': 'error', 'message': 'Resolution failed'}
                 status_response['status'] = 'mismatch'
        elif redir_ip != expected_ip:
             status_response['redirection'] = {
                 'status': 'mismatch',
                 'expected': expected_ip,
                 'actual': redir_ip
             }
             status_response['status'] = 'mismatch'
        else:
             status_response['redirection']['status'] = 'match'
    
    # 2.5. Anubis Check
    if anubis_subdomain and domain_to_check:
        # Get root domain from domain_to_check
        parts = domain_to_check.split('.')
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
            anubis_full_domain = f"{anubis_subdomain}.{root_domain}"
            anubis_ip = resolve_domain(anubis_full_domain)
            
            if not anubis_ip:
                # For Anubis, we generally expect the subdomain to be resolvable if the root is.
                # However, if root is local, Anubis subdomain might also be in /etc/hosts
                if TRAEFIK_ACME_ENV_TYPE == 'local' and check_host_file(anubis_full_domain):
                    anubis_ip = expected_ip
                else:
                    status_response['anubis'] = {'status': 'error', 'message': f'Resolution failed for {anubis_full_domain}'}
                    status_response['status'] = 'mismatch'
            elif anubis_ip != expected_ip:
                status_response['anubis'] = {
                    'status': 'mismatch',
                    'expected': expected_ip,
                    'actual': anubis_ip
                }
                status_response['status'] = 'mismatch'
            else:
                status_response['anubis']['status'] = 'match'
        else:
             status_response['anubis'] = {'status': 'error', 'message': 'Invalid domain for Anubis check'}
             status_response['status'] = 'mismatch'
    
    # 3. Service Check
    if service_to_check:
        try:
             services = get_external_services()
             if service_to_check not in services:
                 # Check if the service name might be slightly different or internal?
                 # Assuming exact match required based on api_services
                 status_response['service'] = {'status': 'missing'}
                 status_response['status'] = 'mismatch'
             else:
                 status_response['service']['status'] = 'found'
        except Exception:
             status_response['service'] = {'status': 'error'}
             # Don't fail the whole row just for internal error if possible? 
             # But request asks to check existence.
             status_response['status'] = 'mismatch'

    return jsonify(status_response)

@app.route('/dm-api/restart', methods=['POST'])
@login_required
def restart_stack():
    # We still keep the old restart for compatibility or simple trigger
    try:
        subprocess.Popen(['bash', START_SCRIPT], cwd=BASE_DIR, env=ENV)
        return jsonify({'status': 'success', 'message': 'Stack restart initiated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dm-api/restart-stream')
@login_required
def restart_stream():
    def generate():
        # Using bash explicitly and passing current environment
        process = subprocess.Popen(
            ['bash', START_SCRIPT],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=ENV
        )
        
        for line in process.stdout:
            # SSE format: "data: <content>\n\n"
            yield f"data: {line}\n\n"
        
        process.stdout.close()
        return_code = process.wait()
        yield f"data: \n[Process finished with code {return_code}]\n\n"

    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

print(f"DEBUG: Startup - URL Map: {app.url_map}", flush=True)
