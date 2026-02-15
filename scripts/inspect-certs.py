import json
import csv
import os
import tldextract
from collections import defaultdict

ACME_FILE = 'config/traefik/acme.json'
DOMAINS_FILE = 'domains.csv'

def get_root_domain(domain):
    extracted = tldextract.extract(domain)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain

def load_expected_domains():
    expected = set()
    if not os.path.exists(DOMAINS_FILE):
        return expected
    
    try:
        with open(DOMAINS_FILE, 'r') as f:
            lines = [line for line in f if line.strip() and not line.strip().startswith('#')]
            reader = csv.reader(lines, skipinitialspace=True)
            for row in reader:
                if not row or len(row) < 1:
                    continue
                domain = row[0].strip()
                if domain:
                    expected.add(domain.lower())
                
                # Check for Anubis subdomain
                if len(row) > 3 and row[3].strip():
                    anubis_sub = row[3].strip()
                    root = get_root_domain(domain)
                    expected.add(f"{anubis_sub}.{root}".lower())
    except Exception as e:
        print(f"❌ Error reading {DOMAINS_FILE}: {e}")
    
    return expected

def inspect_certs():
    print(f"🔍 Inspecting Certificates in {ACME_FILE}...")
    
    if not os.path.exists(ACME_FILE) or os.path.getsize(ACME_FILE) == 0:
        print(f"⚠️  {ACME_FILE} is empty or missing. No certificates found.")
        acme_data = {}
    else:
        try:
            with open(ACME_FILE, 'r') as f:
                acme_data = json.load(f)
        except Exception as e:
            print(f"❌ Error parsing {ACME_FILE}: {e}")
            return

    covered_domains = set()
    cert_count = 0
    
    # Traefik acme.json structure: { "resolverName": { "Certificates": [...] } }
    for resolver_name, resolver_data in acme_data.items():
        if isinstance(resolver_data, dict) and 'Certificates' in resolver_data:
            certs = resolver_data['Certificates']
            cert_count += len(certs)
            for cert in certs:
                if 'domain' in cert:
                    main = cert['domain'].get('main')
                    if main:
                        covered_domains.add(main.lower())
                    sans = cert['domain'].get('sans', [])
                    for san in sans:
                        covered_domains.add(san.lower())

    print(f"✅ Found {cert_count} certificates covering {len(covered_domains)} unique domains.")
    
    expected_domains = load_expected_domains()
    if not expected_domains:
        print("ℹ️  No domains found in domains.csv to compare.")
        return

    missing = expected_domains - covered_domains
    
    print(f"\n📊 Summary vs {DOMAINS_FILE}:")
    print(f"   - Expected domains: {len(expected_domains)}")
    print(f"   - Covered domains:  {len(expected_domains - missing)}")
    print(f"   - Missing domains:  {len(missing)}")

    if missing:
        print("\n❌ MISSING DOMAINS (No certificate found):")
        for d in sorted(missing):
            print(f"   ➜ {d}")
    else:
        print("\n✨ All domains from domains.csv are covered by current certificates.")

if __name__ == "__main__":
    inspect_certs()
