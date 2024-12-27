import os
import subprocess
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored
import argparse
from googlesearch import search
import time

# Configure logging
logging.basicConfig(filename='info_gathering.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_error(message):
    logging.error(message)
    print(colored(f"[-] {message}", "red"))

def log_info(message):
    print(colored(f"[+] {message}", "green"))

def log_warning(message):
    print(colored(f"[*] {message}", "yellow"))

def check_tool_installed(tool_name):
    """Check if a required tool is installed."""
    if subprocess.call(['which', tool_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        log_error(f"{tool_name} is not installed. Please install it to proceed.")
        return False
    return True

def gather_subdomains(domain):
    log_warning(f"Gathering subdomains for {domain}")
    subdomains = set()

    if check_tool_installed('subfinder'):
        try:
            result = subprocess.run(['subfinder', '-d', domain], capture_output=True, text=True)
            subdomains.update(result.stdout.splitlines())
        except Exception as e:
            log_error(f"Error with subfinder: {e}")

    if check_tool_installed('assetfinder'):
        try:
            result = subprocess.run(['assetfinder', '--subs-only', domain], capture_output=True, text=True)
            subdomains.update(result.stdout.splitlines())
        except Exception as e:
            log_error(f"Error with assetfinder: {e}")

    log_info(f"Found {len(subdomains)} subdomains")
    return list(subdomains)

def gather_technology_stack(url):
    log_warning(f"Gathering technology stack for {url}")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        tech_stack = {}
        if 'wp-content' in response.text:
            tech_stack['WordPress'] = True

        if 'X-Powered-By' in response.headers:
            tech_stack['Server'] = response.headers['X-Powered-By']

        scripts = soup.find_all('script')
        js_libs = [script['src'] for script in scripts if 'src' in script.attrs]
        if js_libs:
            tech_stack['JavaScript Libraries'] = js_libs

        log_info(json.dumps(tech_stack, indent=4))
        return tech_stack
    except Exception as e:
        log_error(f"Error gathering technology stack: {e}")
        return {}

def gather_certificates(domain):
    log_warning(f"Gathering SSL/TLS certificates for {domain}")
    if not check_tool_installed('openssl'):
        return {}
    try:
        result = subprocess.run(['openssl', 's_client', '-connect', f'{domain}:443'], capture_output=True, text=True)
        log_info(result.stdout)
        return {'certificate_info': result.stdout}
    except Exception as e:
        log_error(f"Error gathering certificates: {e}")
        return {}

def gather_services_and_versions(domain):
    log_warning(f"Gathering services and versions for {domain}")
    if not check_tool_installed('nmap'):
        return {}
    try:
        result = subprocess.run(['nmap', '-sV', domain], capture_output=True, text=True)
        log_info(result.stdout)
        return {'nmap_scan': result.stdout}
    except Exception as e:
        log_error(f"Error with nmap: {e}")
        return {}

def gather_directory_scan(url):
    log_warning(f"Performing directory scan on {url}")
    if not check_tool_installed('dirsearch'):
        return {}
    try:
        report_file = f"dirsearch_report_{url.replace('://', '_').replace('/', '_')}.txt"
        subprocess.run(['dirsearch', '-u', url, '-e', '*', '-o', report_file], capture_output=True, text=True)
        with open(report_file, 'r') as f:
            report_content = f.read()
        log_info(f"Directory scan report saved to {report_file}")
        return {'directory_scan': report_content}
    except Exception as e:
        log_error(f"Error with dirsearch: {e}")
        return {}

def gather_retirejs_scan(url):
    log_warning(f"Scanning for retire.js vulnerabilities on {url}")
    if not check_tool_installed('retire'):
        return {}
    try:
        result = subprocess.run(['retire', '--jspath', url], capture_output=True, text=True)
        log_info(result.stdout)
        return {'retirejs_scan': result.stdout}
    except Exception as e:
        log_error(f"Error with retire.js: {e}")
        return {}

def gather_whois_info(domain):
    log_warning(f"Gathering WHOIS information for {domain}")
    try:
        whois_info = whois.query(domain)
        log_info(str(whois_info))
        return {'whois_info': str(whois_info)}
    except Exception as e:
        log_error(f"Error gathering WHOIS information: {e}")
        return {}

def gather_dns_records(domain):
    log_warning(f"Gathering DNS records for {domain}")
    try:
        records = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        dns_results = {}
        for record in records:
            try:
                answers = dns.resolver.resolve(domain, record)
                dns_results[record] = [str(answer) for answer in answers]
            except dns.resolver.NoAnswer:
                continue
        log_info(json.dumps(dns_results, indent=4))
        return dns_results
    except Exception as e:
        log_error(f"Error gathering DNS records: {e}")
        return {}

def gather_httpx_scan(url):
    log_warning(f"Running httpx scan on {url}")
    if not check_tool_installed('httpx'):
        return {}
    try:
        result = subprocess.run(['httpx', '-u', url], capture_output=True, text=True)
        log_info(result.stdout)
        return {'httpx_scan': result.stdout}
    except Exception as e:
        log_error(f"Error with httpx: {e}")
        return {}

def gather_nuclei_scan(url, templates):
    log_warning(f"Running nuclei scan on {url} with templates {templates}")
    if not check_tool_installed('nuclei'):
        return {}
    try:
        result = subprocess.run(['nuclei', '-u', url, '-t', templates], capture_output=True, text=True)
        log_info(result.stdout)
        return {'nuclei_scan': result.stdout}
    except Exception as e:
        log_error(f"Error with nuclei: {e}")
        return {}

def gather_naabu_scan(domain):
    log_warning(f"Running naabu scan on {domain}")
    if not check_tool_installed('naabu'):
        return {}
    try:
        result = subprocess.run(['naabu', '-host', domain], capture_output=True, text=True)
        log_info(result.stdout)
        return {'naabu_scan': result.stdout}
    except Exception as e:
        log_error(f"Error with naabu: {e}")
        return {}

def gather_dnsx_scan(domain):
    log_warning(f"Running dnsx scan on {domain}")
    if not check_tool_installed('dnsx'):
        return {}
    try:
        result = subprocess.run(['dnsx', '-d', domain], capture_output=True, text=True)
        log_info(result.stdout)
        return {'dnsx_scan': result.stdout}
    except Exception as e:
        log_error(f"Error with dnsx: {e}")
        return {}

def gather_katana_scan(url):
    log_warning(f"Running katana crawl on {url}")
    if not check_tool_installed('katana'):
        return {}
    try:
        result = subprocess.run(['katana', '-u', url], capture_output=True, text=True)
        log_info(result.stdout)
        return {'katana_scan': result.stdout}
    except Exception as e:
        log_error(f"Error with katana: {e}")
        return {}

def gather_google_dorks(domain):
    log_warning(f"Performing Google Dorking for {domain}")
    dorks = [
        f'site:{domain} filetype:sql',
        f'site:{domain} "api key"',
        f'site:{domain} "database"',
        f'site:{domain} "error log"',
        f'site:{domain} "index of /"',
        f'site:{domain} "password"',
        f'site:{domain} "username"',
        f'site:{domain} "admin"',
        f'site:{domain} "login"',
        f'site:{domain} "config"',
    ]
    results = {}
    for dork in dorks:
        try:
            log_info(f"Searching with dork: {dork}")
            search_results = list(search(dork, num_results=10, sleep_interval=5))  # Use num_results and sleep_interval
            results[dork] = search_results
        except Exception as e:
            log_error(f"Error with Google Dorking: {e}")
            if "429" in str(e):  # Handle rate limiting
                log_warning("Rate limited by Google. Waiting for 60 seconds before retrying.")
                time.sleep(60)
                try:
                    search_results = list(search(dork, num_results=10, sleep_interval=5))
                    results[dork] = search_results
                except Exception as e:
                    log_error(f"Error with Google Dorking after retry: {e}")
    return results

def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def run_concurrent_tasks(tasks):
    results = {}
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(task): task_name for task_name, task in tasks.items()}
        for future in as_completed(futures):
            task_name = futures[future]
            try:
                results[task_name] = future.result()
            except Exception as e:
                log_error(f"Error in task {task_name}: {e}")
    return results

def main():
    parser = argparse.ArgumentParser(description="Ultimate Information Gathering Tool")
    parser.add_argument('-d', '--domain', required=True, help="Target domain")
    parser.add_argument('-u', '--url', required=True, help="Target URL")
    parser.add_argument('-t', '--templates', required=True, help="Path to Nuclei templates")
    args = parser.parse_args()

    TARGET_DOMAIN = args.domain
    TARGET_URL = args.url
    NUCLEI_TEMPLATES = args.templates

    log_warning(f"Starting information gathering for {TARGET_DOMAIN}")

    tasks = {
        'subdomains': lambda: gather_subdomains(TARGET_DOMAIN),
        'technology_stack': lambda: gather_technology_stack(TARGET_URL),
        'certificates': lambda: gather_certificates(TARGET_DOMAIN),
        'services_and_versions': lambda: gather_services_and_versions(TARGET_DOMAIN),
        'directory_scan': lambda: gather_directory_scan(TARGET_URL),
        'retirejs_scan': lambda: gather_retirejs_scan(TARGET_URL),
        'whois_info': lambda: gather_whois_info(TARGET_DOMAIN),
        'dns_records': lambda: gather_dns_records(TARGET_DOMAIN),
        'httpx_scan': lambda: gather_httpx_scan(TARGET_URL),
        'nuclei_scan': lambda: gather_nuclei_scan(TARGET_URL, NUCLEI_TEMPLATES),
        'naabu_scan': lambda: gather_naabu_scan(TARGET_DOMAIN),
        'dnsx_scan': lambda: gather_dnsx_scan(TARGET_DOMAIN),
        'katana_scan': lambda: gather_katana_scan(TARGET_URL),
        'google_dorks': lambda: gather_google_dorks(TARGET_DOMAIN),
    }

    results = run_concurrent_tasks(tasks)

    # Save results to a file
    save_to_json(results, 'results.json')

    log_info("Information gathering completed")

if __name__ == "__main__":
    main()