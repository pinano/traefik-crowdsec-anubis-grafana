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

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# --- Hardened Session Settings ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # In production via Traefik HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800 # 30 minutes
)

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
START_SCRIPT = os.path.join(BASE_DIR, 'start.sh')

print(f"DEBUG: BASE_DIR={BASE_DIR}")
print(f"DEBUG: CSV_PATH={CSV_PATH}")
print(f"DEBUG: START_SCRIPT={START_SCRIPT}")

DOMAIN = os.environ.get('DOMAIN', 'localhost')
TRAEFIK_RATE_AVG = os.environ.get('TRAEFIK_GLOBAL_RATE_AVG', '60')
TRAEFIK_RATE_BURST = os.environ.get('TRAEFIK_GLOBAL_RATE_BURST', '120')
TRAEFIK_CONCURRENCY = os.environ.get('TRAEFIK_GLOBAL_CONCURRENCY', '25')
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
            if request.path.startswith('/api/') or request.path == '/api/restart-stream':
                return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def check_csrf():
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
            
            # Skip pure comments that are not data (e.g. the header or actual comments)
            # We assume a data row has at least domain info.
            # Our header starts with "# domain", so we should ideally skip that specific line or generic comments.
            # However, a commented row looks like "# example.com".
            
            if first_col.startswith('#'):
                # Check if it looks like a data row (has CSV structure)
                # This is tricky because csv.reader already split it.
                # If it's a "soft deleted" row, the first cell has the #.
                clean_domain = first_col.lstrip('#').strip()
                if not clean_domain: 
                    # specific check for the header line or empty comments
                    continue
                
                # Check if this line is likely our header
                if 'domain' in clean_domain and 'redirection' in row[1]:
                    continue
                    
                enabled = False
                row[0] = clean_domain
            
            # Ensure row has enough columns (7 based on template)
            # domain, redirection, service_name, anubis_subdomain, rate, burst, concurrency
            # pad if necessary
            while len(row) < 7:
                row.append('')
            
            data.append({
                'domain': row[0].strip(),
                'redirection': row[1].strip(),
                'service_name': row[2].strip(),
                'anubis_subdomain': row[3].strip(),
                'rate': row[4].strip(),
                'burst': row[5].strip(),
                'concurrency': row[6].strip(),
                'enabled': enabled
            })
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

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        # Simple prevention of empty submissions
        user = request.form.get('username', '')
        pw = request.form.get('password', '')
        
        if user == ADMIN_USER and pw == ADMIN_PASS:
            session.clear() # Clear any existing session to prevent fixation
            session['logged_in'] = True
            session.permanent = True
            return redirect(url_for('index'))
        
        # Log failure (useful for external monitoring or security logs)
        print(f"SECURITY: Failed login attempt for user '{user}' from {request.remote_addr}")
        return render_template('login.html', error='Invalid credentials', domain=DOMAIN)
    return render_template('login.html', domain=DOMAIN)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', 
                           domain=DOMAIN,
                           rate_avg=TRAEFIK_RATE_AVG,
                           rate_burst=TRAEFIK_RATE_BURST,
                           concurrency=TRAEFIK_CONCURRENCY)

@app.route('/api/domains', methods=['GET', 'POST'])
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
            
        write_csv(data)
        return jsonify({'status': 'success'})

@app.route('/api/services', methods=['GET'])
@login_required
def api_services():
    try:
        final_list = get_external_services()
        return jsonify(final_list)
    except Exception as e:
        print(f"Error getting external services: {e}")
        return jsonify([])

def get_external_services():
    # Get the current project name to exclude its containers
    current_project = os.environ.get('PROJECT_NAME', '')
    # If not set, it defaults to the directory name of the project
    if not current_project:
        current_project = os.path.basename(BASE_DIR)

    # Get all running containers and their project label
    # format: name|project
    cmd = ["docker", "ps", "--format", "{{.Names}}|{{.Label \"com.docker.compose.project\"}}"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True, env=ENV)
    
    all_containers = result.stdout.splitlines()
    external_services = []
    
    for line in all_containers:
        if '|' not in line:
            continue
        name, project = line.split('|', 1)
        
        # Exclude if it belongs to the current project
        if project == current_project:
            continue
        
        # Also exclude the domain-manager itself just in case
        if name == "domain-manager":
            continue
            
        external_services.append(name)
        
    final_list = sorted(list(set(external_services)))

    # Append 'apache-host' if legacy installation is detected
    if os.path.exists("/var/log/apache2"):
        # Put it at the beginning of the list for easy access if it exists
        final_list.insert(0, "apache-host")
        
    return final_list

def resolve_domain(domain):
    try:
        if not domain:
            return None
        # Get the IP address of the domain
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return None

@app.route('/api/check-domain', methods=['POST'])
@limiter.exempt
@login_required 
def check_domain():
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
    host_domain = os.environ.get('DOMAIN')
    expected_ip = resolve_domain(host_domain)
    
    if not expected_ip:
        return jsonify({'status': 'error', 'message': 'Could not resolve host domain'})
    
    # 1. Domain Check
    if not domain_to_check:
         status_response['domain'] = {'status': 'error', 'message': 'Empty domain'}
         status_response['status'] = 'mismatch'
    else:
        actual_ip = resolve_domain(domain_to_check)
        if not actual_ip:
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

@app.route('/api/restart', methods=['POST'])
@login_required
def restart_stack():
    # We still keep the old restart for compatibility or simple trigger
    try:
        subprocess.Popen(['bash', START_SCRIPT], cwd=BASE_DIR, env=ENV)
        return jsonify({'status': 'success', 'message': 'Stack restart initiated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/restart-stream')
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
