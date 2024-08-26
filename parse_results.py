import json
import subprocess
from urllib.parse import urlparse

def run_tlsx(url):
    
    command = ['tlsx', '-u', url, '--json']
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing the tlsx command for {url}: {e}")
    except json.JSONDecodeError as e:
        print(f"Decoding error JSON for {url}: {e}")
    return None

def run_subfinder(domain):

    command = ['subfinder', '-d', domain, '-silent', '-json']
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        fqdns = [json.loads(line)['host'] for line in result.stdout.splitlines()]
        return fqdns
    except subprocess.CalledProcessError as e:
        print(f"Error executing subfinder for {domain}: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"Decoding JSON error for {domain}: {e}")
        return []

def extract_domain_level_2(hostname):
    if '=' in hostname:
            hostname = hostname.split('=')[-1]
    if hostname:
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
    return None

def parse_tlsx_results(tlsx_data):
    
    domains = set()
    for field in ['subject_an', 'subject_dn', 'subject_cn']:
        if field in tlsx_data:
            items = tlsx_data[field] if isinstance(tlsx_data[field], list) else tlsx_data[field].split(',')
            for item in items:
                domain = extract_domain_level_2(item.strip())
                if domain:
                    domains.add(domain)
    return list(domains)

def load_urls_from_file(filename):
    
    with open(filename, 'r') as file:
        data = json.load(file)
        return [entry['url'] for entry in data]

def main():

    urls = load_urls_from_file('result.json')
    
    for url in urls:
        print(f"Processing URL: {url}")
        tlsx_data = run_tlsx(url)
        domains = parse_tlsx_results(tlsx_data)
        print(f"Second-level domain: {domains}")
        fqdns = set()
        for domain in domains:
            fqdns.update(run_subfinder(domain))
        print(f"FQDN: {fqdns}")
        

if __name__ == "__main__":
    main()
