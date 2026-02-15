import json
import csv
import os
import tldextract
import argparse
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

def inspect_certs(verbose=False):
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
    certificates_details = []
    
    # Traefik acme.json structure: { "resolverName": { "Certificates": [...] } }
    for resolver_name, resolver_data in acme_data.items():
        if isinstance(resolver_data, dict) and 'Certificates' in resolver_data:
            certs = resolver_data['Certificates']
            for cert in certs:
                if 'domain' in cert:
                    main = cert['domain'].get('main', '').lower()
                    sans = [s.lower() for s in cert['domain'].get('sans', [])]
                    
                    if main:
                        covered_domains.add(main)
                        for san in sans:
                            covered_domains.add(san)
                        
                        certificates_details.append({
                            'resolver': resolver_name,
                            'main': main,
                            'sans': sans,
                            'root': get_root_domain(main)
                        })

    print(f"✅ Found {len(certificates_details)} certificates covering {len(covered_domains)} unique domains.")
    
    if verbose and certificates_details:
        print("\n📜 DETAILED CERTIFICATE LIST:")
        # Group by root for better readability in verbose mode
        by_root = defaultdict(list)
        for cert in certificates_details:
            by_root[cert['root']].append(cert)
            
        for root, certs in sorted(by_root.items()):
            print(f"\n📂 Root Domain: {root}")
            for i, cert in enumerate(certs, 1):
                san_str = f" (+{len(cert['sans'])} SANs)" if cert['sans'] else ""
                print(f"   {i}. Main: {cert['main']}{san_str}")
                if cert['sans']:
                    for s in cert['sans']:
                        print(f"      - {s}")

    expected_domains = load_expected_domains()
    missing = expected_domains - covered_domains
    
    print(f"\n📊 Summary vs {DOMAINS_FILE}:")
    print(f"   - Expected domains: {len(expected_domains)}")
    print(f"   - Covered domains:  {len(expected_domains - missing)}")
    print(f"   - Missing domains:  {len(missing)}")

    if missing:
        print("\n❌ MISSING DOMAINS (No certificate found):")
        for d in sorted(missing):
            print(f"   ➜ {d}")
    elif expected_domains:
        print("\n✨ All domains from domains.csv are covered by current certificates.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inspect Traefik acme.json certificates.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed certificate information")
    args = parser.parse_args()
    
    inspect_certs(verbose=args.verbose)
