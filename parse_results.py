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

def extract_domain_level_2(hostname):
     
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
        print(f"Second-level domains: {domains}")

if __name__ == "__main__":
    main()

