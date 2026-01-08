import os
import csv
import subprocess
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

ADMIN_USER = os.environ.get('DOMAIN_MANAGER_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('DOMAIN_MANAGER_ADMIN_PASSWORD', 'admin')
CSV_PATH = '/data/domains.csv'
START_SCRIPT = '/app/start.sh'

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
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')

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

@app.route('/api/restart', methods=['POST'])
def restart_stack():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Run start.sh in the background to avoid timeout
        subprocess.Popen([START_SCRIPT], cwd='/app')
        return jsonify({'status': 'success', 'message': 'Stack restart initiated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
