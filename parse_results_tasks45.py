import json
import subprocess
from urllib.parse import urlparse
import psycopg2
from config import host, user, password, db_name


def run_tlsx(entry):
    command = ['tlsx', '-u', entry, '--json']
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as _ex:
        print(f"Error executing the tlsx command for {entry}: {_ex}")
    except json.JSONDecodeError as _ex:
        print(f"Decoding error JSON for {entry}: {_ex}")
    return None


def run_subfinder(domain):
    command = ['subfinder', '-d', domain, '-silent', '-json']
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        fqdns = [json.loads(line)['host'] for line in result.stdout.splitlines()]
        return fqdns
    except subprocess.CalledProcessError as _ex:
        print(f"Error executing subfinder for {domain}: {_ex}")
        return []
    except json.JSONDecodeError as _ex:
        print(f"Decoding JSON error for {domain}: {_ex}")
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
        return data

def get_urls(data):
    return [entry['url'] for entry in data]

def save_to_db(data):
    try:
        # connect to exist database
        connection = psycopg2.connect(
            host=host,
            user=user,
            password=password,
            database=db_name,
        )
        connection.autocommit = True

        # the cursor for performing database operations
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT version()"
            )
            print(f"Server version^ {cursor.fetchone()}")

        # create a new table
        # with connection.cursor() as cursor:
        #     cursor.execute(
        #         """CREATE TABLE results(
        #             id SERIAL PRIMARY KEY,
        #             ip INET,
        #             port INTEGER,
        #             protocol VARCHAR(10),
        #             url TEXT,
        #             domains TEXT[],
        #             fqdns TEXT[],
        #             vuln VARCHAR(255),
        #             vendor VARCHAR(100),
        #             product VARCHAR(100));"""
        #     )
        #
        #     print(f"[INFO] Table created successfully")

        with connection.cursor() as cursor:
            for entry in data:
                cursor.execute(
                    """
                    INSERT INTO results (ip, port, protocol, url, domains, fqdns, vuln, vendor, product)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        entry['ip'],
                        entry['port'],
                        entry['protocol'],
                        entry['url'],
                        entry.get('domains', []),
                        entry.get('fqdns', []),
                        entry.get('vuln'),
                        entry.get('vendor'),
                        entry.get('product')
                    )
                )
        print("[INFO] Data saved to the database successfully")

    except Exception as _ex:
        print(f"[INFO] Error while working with PostgreSQL: {_ex}")

    finally:
        if connection:
            connection.close()
            print("[INFO] PostgreSQL connection closed")

def main():
    data = load_urls_from_file('result.json')
    urls = get_urls(data)
    enriched_data = []
    for entry in data:
        url = entry['url']
        print(f"Processing URL: {url}")
        tlsx_data = run_tlsx(url)
        domains = parse_tlsx_results(tlsx_data)
        print(f"Second-level domain: {domains}")
        fqdns = set()
        for domain in domains:
            fqdns.update(run_subfinder(domain))
        print(f"FQDN: {fqdns}")

        entry['domains'] = domains
        entry['fqdns'] = list(fqdns)

        enriched_data.append(entry)

    save_to_db(enriched_data)

    # Save enriched data to a JSON file
    with open('result_enriched.json', 'w') as f:
        json.dump(enriched_data, f, indent=4)
        print("[INFO] Enriched data saved to result_enriched.json")


if __name__ == "__main__":
    main()