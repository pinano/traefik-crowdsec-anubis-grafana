import os
import csv
import subprocess
import secrets
import re
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

ADMIN_USER = os.environ.get('DOMAIN_MANAGER_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('DOMAIN_MANAGER_ADMIN_PASSWORD', 'admin')

# Mirror the host path inside the container
BASE_DIR = os.environ.get('APP_PATH_HOST', os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
CSV_PATH = os.path.join(BASE_DIR, 'domains.csv')
START_SCRIPT = os.path.join(BASE_DIR, 'start.sh')

print(f"DEBUG: BASE_DIR={BASE_DIR}")
print(f"DEBUG: CSV_PATH={CSV_PATH}")
print(f"DEBUG: START_SCRIPT={START_SCRIPT}")

DOMAIN = os.environ.get('DOMAIN', 'localhost')
ENV = os.environ.copy()
ENV['TERM'] = 'xterm'

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

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
    # Basic validation to ensure no malicious content in CSV
    # We allow alphanumeric, dot, dash, underscore, slash, colon (for ports/protocols)
    # This is a loose check but prevents completely arbitrary text
    allowed_pattern = re.compile(r'^[a-zA-Z0-9\.\-\_\:\/]+$')
    
    # Text fields that shouldn't contain weird characters
    fields_to_check = ['domain', 'redirection', 'docker_service', 'anubis_subdomain']
    
    if not entry.get('domain'): 
        return False # Domain is mandatory
        
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
            # Skip empty lines and comments for the UI
            if not row or (row and row[0].strip().startswith('#')):
                continue
            # Ensure row has enough columns (7 based on template)
            # domain, redirection, docker_service, anubis_subdomain, rate, burst, concurrency
            # pad if necessary
            while len(row) < 7:
                row.append('')
            data.append({
                'domain': row[0].strip(),
                'redirection': row[1].strip(),
                'docker_service': row[2].strip(),
                'anubis_subdomain': row[3].strip(),
                'rate': row[4].strip(),
                'burst': row[5].strip(),
                'concurrency': row[6].strip()
            })
    return data

def write_csv(data):
    # Preserving comments is hard with simple csv writer.
    # We will overwrite but try to keep the header.
    header = "# domain, redirection, docker_service, anubis_subdomain, rate, burst, concurrency"
    
    with open(CSV_PATH, mode='w', encoding='utf-8', newline='') as f:
        f.write(header + '\n\n')
        writer = csv.writer(f)
        for entry in data:
            if not validate_domain_data(entry):
                print(f"Skipping invalid entry: {entry}")
                continue
            writer.writerow([
                entry['domain'],
                entry['redirection'],
                entry['docker_service'],
                entry['anubis_subdomain'],
                entry['rate'],
                entry['burst'],
                entry['concurrency']
            ])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Login is exempt from global CSRF check if handled via form, 
        # but let's check it if we were enforcing it globally. 
        # However, check_csrf applies to ALL POSTs. We need to handle login specifically or exempt it.
        # Since login comes from a form without JS usually, checking 'csrf_token' from form input is standard.
        # For simplicity here, we assume the global check runs. 
        # BUT wait, the global check looks for header X-CSRFToken. Forms usually send body.
        # Let's exempt login from the JSON header check and do form check if needed.
        pass # The global check will catch this if we don't handle it.
        # IMPORTANT: We need to exempt login from the global header check or update login.html.
        # Let's simply modify check_csrf to skip login endpoint.
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials', domain=DOMAIN)
    return render_template('login.html', domain=DOMAIN)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html', domain=DOMAIN)

@app.route('/api/domains', methods=['GET', 'POST'])
def api_domains():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if request.method == 'GET':
        return jsonify(read_csv())
    
    if request.method == 'POST':
        data = request.json
        write_csv(data)
        return jsonify({'status': 'success'})

@app.route('/api/services', methods=['GET'])
def api_services():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get the current project name to exclude its containers
        current_project = os.environ.get('COMPOSE_PROJECT_NAME', '')
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
            
        return jsonify(final_list)
    except Exception as e:
        print(f"Error getting external services: {e}")
        return jsonify([])

@app.route('/api/restart', methods=['POST'])
def restart_stack():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # We still keep the old restart for compatibility or simple trigger
    try:
        subprocess.Popen(['bash', START_SCRIPT], cwd=BASE_DIR, env=ENV)
        return jsonify({'status': 'success', 'message': 'Stack restart initiated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/restart-stream')
def restart_stream():
    if not session.get('logged_in'):
        return Response("Unauthorized", status=401)

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
