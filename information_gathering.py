import os
import asyncio
import aiohttp
import subprocess
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import logging
import json
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from termcolor import colored
import argparse
from googlesearch import search
import time
from jinja2 import Template
import aiofiles
from fpdf import FPDF
import pandas as pd
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
import xml.etree.ElementTree as ET
import socket
from typing import List, Set
from subprocess import Popen, PIPE
from tenacity import retry, stop_after_attempt, wait_exponential
import ssl
from ssl import SSLContext, TLSVersion, PROTOCOL_TLS_CLIENT
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Set, Union
import yaml
import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor
import resource
import platform
import shutil
from subprocess import run, PIPE

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler("information_gathering.log", mode='w'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
console = Console()

# Add these constants after the logger setup
MAX_RETRIES = 3
RETRY_WAIT_MULTIPLIER = 2
RETRY_MAX_WAIT = 10
TIMEOUT = 10

# Add configuration class
@dataclass
class ScanConfig:
    """Configuration for the scanner"""
    max_threads: int = 10
    max_subdomains: int = 1000
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = False
    aggressive_scan: bool = False
    output_dir: str = "output"
    tools_config: Dict[str, Dict] = None

    @classmethod
    def from_yaml(cls, path: str) -> 'ScanConfig':
        """Load configuration from YAML file"""
        with open(path) as f:
            config = yaml.safe_load(f)
        return cls(**config)

class AsyncScanner:
    def __init__(self, domain, url, templates, config_path=None):
        self.domain = domain
        self.url = url
        self.templates = templates
        self.results = {}
        self.session = None
        self.subdomains = set()
        self.alive_domains = set()
        self.scraped_urls = set()
        
        # Load configuration
        if config_path and os.path.exists(config_path):
            self.config = ScanConfig.from_yaml(config_path)
        else:
            self.config = ScanConfig()  # Use default values
        
        # Create output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        # Setup wordlist path
        self.wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "wordlists",
            "subdomains-top1million-5000.txt"
        )

    async def setup(self):
        """Initialize async session"""
        self.session = aiohttp.ClientSession()

    async def cleanup(self):
        """Cleanup resources properly"""
        try:
            if self.session:
                await self.session.close()
            
            # Cleanup temporary files
            temp_files = [
                f"{self.domain}_subfinder.txt",
                f"{self.domain}_alive.txt",
                "temp_domains.txt",
                "results.txt"
            ]
            
            for file in temp_files:
                if os.path.exists(file):
                    try:
                        os.remove(file)
                    except Exception as e:
                        logger.debug(f"Failed to remove {file}: {e}")
                    
            # Cleanup temporary directories
            temp_dirs = ["paramspider_output", "results"]
            for directory in temp_dirs:
                if os.path.exists(directory):
                    try:
                        shutil.rmtree(directory)
                    except Exception as e:
                        logger.debug(f"Failed to remove directory {directory}: {e}")
                    
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    async def run_async_command(self, cmd, tool_name):
        """Run system commands asynchronously with better error handling"""
        try:
            # Check if the tool exists
            if not shutil.which(cmd[0]):
                logger.error(f"{tool_name} not found in PATH")
                return None

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minute timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"{tool_name} timed out after 300 seconds")
                return None

            if process.returncode != 0:
                logger.error(f"{tool_name} error: {stderr.decode()}")
                return None

            return stdout.decode()

        except Exception as e:
            logger.error(f"Error running {tool_name}: {str(e)}")
            return None

    async def run_async_command_with_timeout(self, cmd: List[str], tool_name: str, timeout: int = 300) -> Optional[str]:
        """Run an async command with improved timeout and error handling"""
        try:
            # Verify the command exists
            if not shutil.which(cmd[0]):
                logger.error(f"{tool_name}: Command '{cmd[0]}' not found")
                return None

            # Create process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                # Wait for process with timeout
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                # Check return code
                if process.returncode != 0:
                    error_msg = stderr.decode().strip()
                    logger.error(f"{tool_name} error: {error_msg}")
                    return None

                return stdout.decode()

            except asyncio.TimeoutError:
                logger.error(f"{tool_name} timed out after {timeout} seconds")
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5)
                except Exception as e:
                    logger.debug(f"Error terminating process: {e}")
                    try:
                        process.kill()
                    except Exception:
                        pass
                raise TimeoutError(f"{tool_name} timed out")

        except Exception as e:
            logger.error(f"{tool_name} execution error: {str(e)}")
            return None

    async def gather_subdomains_async(self):
        """Enhanced asynchronous subdomain enumeration"""
        all_subdomains = set()
        
        try:
            # Run Subfinder with better configuration
            subfinder_cmd = [
                'subfinder',
                '-d', self.domain,
                '-all',               # Use all sources
                '-recursive',         # Use recursive enumeration 
                '-silent',           # Silent output
                '-t', '50',          # Number of concurrent threads
                '-timeout', '30',     # Timeout in seconds
                '-o', f'subfinder_{self.domain}.txt'  # Output file
            ]
            
            logger.info(f"Running Subfinder on {self.domain}")
            await self.run_async_command(subfinder_cmd, 'subfinder')
            
            # Process Subfinder results
            if os.path.exists(f'subfinder_{self.domain}.txt'):
                with open(f'subfinder_{self.domain}.txt', 'r') as f:
                    subfinder_results = {line.strip() for line in f if line.strip()}
                logger.info(f"Subfinder found {len(subfinder_results)} subdomains")
                all_subdomains.update(subfinder_results)
                os.remove(f'subfinder_{self.domain}.txt')
            
            # Run Amass if available
            amass_cmd = [
                'amass', 'enum',
                '-d', self.domain,
                '-passive',          # Passive enumeration only
                '-timeout', '30',    # Timeout in minutes
                '-o', f'amass_{self.domain}.txt'
            ]
            
            logger.info(f"Running Amass on {self.domain}")
            await self.run_async_command(amass_cmd, 'amass')
            
            # Process Amass results
            if os.path.exists(f'amass_{self.domain}.txt'):
                with open(f'amass_{self.domain}.txt', 'r') as f:
                    amass_results = {line.strip() for line in f if line.strip()}
                logger.info(f"Amass found {len(amass_results)} subdomains")
                all_subdomains.update(amass_results)
                os.remove(f'amass_{self.domain}.txt')
            
            return list(all_subdomains)
            
        except Exception as e:
            logger.error(f"Subdomain enumeration error: {e}")
            return list(all_subdomains)

    async def scan_subdomain(self, subdomain):
        """Scan individual subdomain for vulnerabilities"""
        results = {}
        
        # Run various security checks on the subdomain
        tasks = [
            self.check_ssl(subdomain),
            self.check_headers(subdomain),
            self.check_ports(subdomain),
            self.check_vulnerabilities(subdomain)
        ]
        
        subdomain_results = await asyncio.gather(*tasks)
        results[subdomain] = {
            'ssl': subdomain_results[0],
            'headers': subdomain_results[1],
            'ports': subdomain_results[2],
            'vulnerabilities': subdomain_results[3]
        }
        
        return results

    @retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(multiplier=RETRY_WAIT_MULTIPLIER, max=RETRY_MAX_WAIT)
    )
    async def check_ssl(self, subdomain):
        """Check SSL/TLS configuration with improved error handling"""
        try:
            clean_subdomain = (
                subdomain.replace('https://', '')
                .replace('http://', '')
                .split('[')[0]
                .strip()
            )
            
            # Resolve domain first
            ips = await self.resolve_domain(clean_subdomain)
            if not ips:
                return {
                    'domain': clean_subdomain,
                    'error': 'Domain not resolvable',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'ips': []
                }
            
            ssl_results = {
                'domain': clean_subdomain,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'certificate': {},
                'protocols': {},
                'cipher_suites': [],
                'ips': ips
            }

            # Try each resolved IP
            for ip in ips:
                try:
                    context = SSLContext(PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.set_ciphers('DEFAULT@SECLEVEL=1')

                    with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
                        with context.wrap_socket(sock, server_hostname=clean_subdomain) as ssock:
                            cert = ssock.getpeercert(binary_form=True)
                            x509 = ssl.DER_cert_to_PEM_cert(cert)
                            ssl_results['certificate'] = {
                                'version': ssock.version(),
                                'cipher': ssock.cipher(),
                                'cert_pem': x509
                            }

                            # Check modern TLS versions
                            protocols = {
                                'TLSv1.3': TLSVersion.TLSv1_3,
                                'TLSv1.2': TLSVersion.TLSv1_2
                            }

                            for protocol_name, protocol_version in protocols.items():
                                try:
                                    ctx = SSLContext(PROTOCOL_TLS_CLIENT)
                                    ctx.minimum_version = protocol_version
                                    ctx.maximum_version = protocol_version
                                    ctx.check_hostname = False
                                    ctx.verify_mode = ssl.CERT_NONE
                                    ctx.set_ciphers('DEFAULT@SECLEVEL=1')

                                    with socket.create_connection((ip, 443), timeout=TIMEOUT) as test_sock:
                                        with ctx.wrap_socket(test_sock, server_hostname=clean_subdomain) as test_ssock:
                                            ssl_results['protocols'][protocol_name] = True
                                except (ssl.SSLError, socket.error) as e:
                                    ssl_results['protocols'][protocol_name] = False
                                    logger.debug(f"Protocol {protocol_name} not supported for {ip}: {str(e)}")

                            # Successfully connected to this IP, no need to try others
                            break
                except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
                    logger.warning(f"SSL connection failed for {clean_subdomain} ({ip}): {str(e)}")
                    continue

            if not ssl_results['certificate']:
                ssl_results['error'] = "Failed to establish SSL connection with any IP"

            return ssl_results

        except Exception as e:
            logger.error(f"SSL scan failed for {subdomain}: {e}")
            return {
                'domain': subdomain,
                'error': str(e),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'ips': []
            }

    @retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(multiplier=RETRY_WAIT_MULTIPLIER, max=RETRY_MAX_WAIT)
    )
    async def check_headers(self, subdomain):
        """Check security headers with improved error handling"""
        try:
            clean_subdomain = subdomain.replace('https://', '').replace('http://', '')
            
            # Resolve domain first
            ips = await self.resolve_domain(clean_subdomain)
            if not ips:
                return {
                    'status': None,
                    'headers': {},
                    'error': 'Domain not resolvable',
                    'ips': []
                }
            
            errors = []
            for protocol in ['https://', 'http://']:
                try:
                    url = f"{protocol}{clean_subdomain}"
                    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
                    
                    # Try connecting with each resolved IP
                    for ip in ips:
                        try:
                            conn = aiohttp.TCPConnector(ssl=False, force_close=True)
                            async with aiohttp.ClientSession(connector=conn) as session:
                                async with session.get(
                                    url,
                                    timeout=timeout,
                                    allow_redirects=True,
                                    headers={'Host': clean_subdomain}
                                ) as response:
                                    headers = dict(response.headers)
                                    return {
                                        'status': response.status,
                                        'headers': headers,
                                        'protocol': protocol,
                                        'ip': ip
                                    }
                        except aiohttp.ClientError as e:
                            errors.append(f"{protocol} ({ip}): {str(e)}")
                            continue
                except Exception as e:
                    errors.append(f"{protocol}: {str(e)}")
                    continue
            
            return {
                'status': None,
                'headers': {},
                'error': f"Failed all connection attempts: {'; '.join(errors)}",
                'ips': ips
            }
        
        except Exception as e:
            logger.error(f"Error checking headers for {subdomain}: {e}")
            return {
                'status': None,
                'headers': {},
                'error': str(e),
                'ips': []
            }

    async def check_ports(self, subdomain):
        """Enhanced port scanning with service detection"""
        # Basic scan for common ports
        common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
        
        basic_cmd = [
            'nmap',
            '-sV',              # Version detection
            '-p', common_ports,
            '--min-rate', '1000',
            '-T4',             # Aggressive timing
            '--version-intensity', '5',
            subdomain
        ]
        
        # Full scan if aggressive mode is enabled
        if self.config.aggressive_scan:
            full_cmd = [
                'nmap',
                '-sV',
                '-p-',         # All ports
                '--min-rate', '1000',
                '-T4',
                '--version-intensity', '5',
                '--script', 'vuln,default,discovery,version',
                subdomain
            ]
            return await self.run_async_command(full_cmd, 'nmap')
        
        return await self.run_async_command(basic_cmd, 'nmap')

    async def check_vulnerabilities(self, subdomain):
        """Enhanced vulnerability scanning with better error handling"""
        try:
            if not subdomain.startswith(('http://', 'https://')):
                target = f"https://{subdomain}"
            else:
                target = subdomain

            # Create unique output directory for this scan
            scan_id = int(time.time())
            output_dir = f"nuclei_output_{scan_id}"
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"nuclei_{subdomain.replace(':', '_').replace('/', '_')}.json")

            # Verify nuclei installation
            if not shutil.which('nuclei'):
                logger.error("Nuclei not found. Please install nuclei first.")
                return None

            # Update templates if needed
            try:
                update_cmd = ['nuclei', '-ut']
                await self.run_async_command(update_cmd, 'nuclei-update')
            except Exception as e:
                logger.warning(f"Template update failed: {e}")

            # Run Nuclei with updated configuration
            nuclei_cmd = [
                'nuclei',
                '-u', target,           # Updated from -target
                '-j',                   # Updated from -json
                '-o', output_file,
                '-silent',
                '-c', '25',            # Concurrent requests
                '-timeout', '5',        # Timeout in minutes
                '-retries', '2',        # Number of retries
                '-rl', '150',          # Updated from -rate-limit
                '-severity', 'critical,high,medium,low'
            ]

            logger.info(f"Starting Nuclei scan for {target}")
            
            try:
                result = await self.run_async_command_with_timeout(nuclei_cmd, 'nuclei', timeout=300)
                if result is None:
                    logger.error(f"Nuclei scan failed for {target}")
                    return None
            except TimeoutError:
                logger.error(f"Nuclei scan timed out for {target}")
                return None

            vulnerabilities = []
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                vuln = json.loads(line.strip())
                                vulnerabilities.append(vuln)
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    logger.error(f"Error reading Nuclei results: {e}")
                finally:
                    # Cleanup
                    try:
                        shutil.rmtree(output_dir)
                    except Exception as e:
                        logger.debug(f"Failed to remove output directory: {e}")

            return {
                'total_vulnerabilities': len(vulnerabilities),
                'findings': vulnerabilities,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
            } if vulnerabilities else None

        except Exception as e:
            logger.error(f"Vulnerability scanning failed for {subdomain}: {e}")
            return None

    async def check_js_vulnerabilities(self, urls):
        """Scan JavaScript libraries using RetireJS"""
        try:
            if not urls:
                logger.info("No URLs to scan for JavaScript vulnerabilities")
                return {"status": "skipped", "reason": "no_urls"}

            # Create temporary URL file
            temp_file = f'temp_urls_{self.domain}.txt'
            temp_output = f'retire_{self.domain}.json'
            
            try:
                # Write URLs to temporary file
                with open(temp_file, 'w') as f:
                    for url in urls:
                        f.write(f"{url}\n")

                # Check if RetireJS is installed
                retire_check = await self.run_async_command(['retire', '--version'], 'RetireJS version check')
                if not retire_check:
                    logger.warning("RetireJS not found or not working properly")
                    return {"status": "error", "reason": "retire_not_found"}

                # Run RetireJS with better error handling
                cmd = [
                    'retire',
                    '--outputformat', 'json',
                    '--outputpath', temp_output,
                    '--path', temp_file,
                    '--verbose'  # Add verbose output for better debugging
                ]
                
                result = await self.run_async_command(cmd, 'RetireJS')
                
                # Process results
                if os.path.exists(temp_output):
                    try:
                        with open(temp_output, 'r') as f:
                            retire_results = json.load(f)
                        return {
                            "status": "success",
                            "results": retire_results,
                            "scanned_urls": len(urls)
                        }
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse RetireJS output: {e}")
                        return {"status": "error", "reason": "invalid_output"}
                else:
                    logger.warning("RetireJS did not produce output file")
                    return {"status": "error", "reason": "no_output"}

            except Exception as e:
                logger.error(f"RetireJS scan error: {str(e)}")
                return {"status": "error", "reason": str(e)}
            
            finally:
                # Cleanup temporary files
                for temp in [temp_file, temp_output]:
                    try:
                        if os.path.exists(temp):
                            os.remove(temp)
                    except Exception as e:
                        logger.debug(f"Failed to remove temporary file {temp}: {e}")

        except Exception as e:
            logger.error(f"RetireJS scan error: {e}")
            return {
                "status": "error",
                "reason": str(e),
                "scanned_urls": len(urls) if urls else 0
            }

    def generate_html_report(self, results):
        """Generate HTML report from scanning results"""
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2, h3 { color: #333; }
                .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f5f5f5; }
                .urls-list { max-height: 300px; overflow-y: auto; }
                pre { white-space: pre-wrap; word-wrap: break-word; }
            </style>
        </head>
        <body>
            <h1>Security Scan Report for {{ domain }}</h1>
            
            <!-- Katana Crawl Results -->
            {% if 'katana_crawl' in results %}
            <div class="section">
                <h2>Katana Crawler Results</h2>
                <p>Total URLs discovered: {{ results['katana_crawl']|length }}</p>
                <div class="urls-list">
                    <ul>
                    {% for url in results['katana_crawl'] %}
                        <li>{{ url }}</li>
                    {% endfor %}
                    </ul>
                </div>
            </div>
            {% endif %}

            <!-- Subdomain Scan Results -->
            {% for subdomain, data in results.items() %}
                {% if subdomain != 'katana_crawl' %}
                <div class="section">
                    <h2>Subdomain: {{ subdomain }}</h2>
                    
                    {% if data.ssl %}
                    <h3>SSL/TLS Configuration</h3>
                    <pre>{{ data.ssl | format_json }}</pre>
                    {% endif %}
                    
                    {% if data.headers %}
                    <h3>Security Headers</h3>
                    <table>
                        <tr>
                            <th>Header</th>
                            <th>Value</th>
                        </tr>
                        {% for header, value in data.headers.items() %}
                        <tr>
                            <td>{{ header }}</td>
                            <td>{{ value }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if data.ports %}
                    <h3>Open Ports</h3>
                    <pre>{{ data.ports }}</pre>
                    {% endif %}
                    
                    {% if data.vulnerabilities %}
                    <h3>Vulnerabilities</h3>
                    <pre>{{ data.vulnerabilities }}</pre>
                    {% endif %}
                </div>
                {% endif %}
            {% endfor %}

            <!-- Add RetireJS Results Section -->
            {% if results.js_vulnerabilities %}
            <div class="section">
                <h2>JavaScript Library Vulnerabilities</h2>
                <pre>{{ results.js_vulnerabilities | format_json }}</pre>
            </div>
            {% endif %}
        </body>
        </html>
        """
        
        def format_json(value):
            """Custom filter to format JSON with indentation"""
            try:
                if isinstance(value, str):
                    # Try to parse string as JSON first
                    value = json.loads(value)
                return json.dumps(value, indent=2)
            except:
                # If parsing fails, return the original value
                return str(value)
        
        template = Template(template_str)
        # Add custom filter for JSON formatting
        template.environment.filters['format_json'] = format_json
        return template.render(domain=self.domain, results=results)

    def generate_pdf_report(self, results):
        """Generate PDF report from scanning results"""
        pdf = FPDF()
        pdf.add_page()
        
        # Add title
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, f'Security Scan Report for {self.domain}', 0, 1, 'C')
        
        # Add content
        pdf.set_font('Arial', '', 12)
        for subdomain, data in results.items():
            # Skip the katana_crawl results as they have a different structure
            if subdomain == 'katana_crawl':
                continue
            
            pdf.cell(0, 10, f'Subdomain: {subdomain}', 0, 1)
            
            # Add SSL/TLS info
            if isinstance(data, dict) and 'ssl' in data:
                pdf.cell(0, 10, 'SSL/TLS Configuration:', 0, 1)
                # Convert SSL data to string safely
                ssl_str = json.dumps(data['ssl'], indent=2) if data['ssl'] else "No SSL data available"
                pdf.multi_cell(0, 10, ssl_str)
            
            # Add headers info
            if isinstance(data, dict) and 'headers' in data and isinstance(data['headers'], dict):
                pdf.cell(0, 10, 'Security Headers:', 0, 1)
                for header, value in data['headers'].items():
                    # Ensure header and value are strings
                    header_str = str(header)[:50]  # Limit length to prevent overflow
                    value_str = str(value)[:100]   # Limit length to prevent overflow
                    pdf.multi_cell(0, 10, f'{header_str}: {value_str}')
            
            # Add ports info
            if isinstance(data, dict) and 'ports' in data:
                pdf.cell(0, 10, 'Open Ports:', 0, 1)
                ports_str = str(data['ports']) if data['ports'] else "No port data available"
                pdf.multi_cell(0, 10, ports_str)
            
            # Add vulnerabilities info
            if isinstance(data, dict) and 'vulnerabilities' in data:
                pdf.cell(0, 10, 'Vulnerabilities:', 0, 1)
                vuln_str = str(data['vulnerabilities']) if data['vulnerabilities'] else "No vulnerabilities found"
                pdf.multi_cell(0, 10, vuln_str)
            
            pdf.add_page()
        
        # Add Katana crawler results if available
        if 'katana_crawl' in results:
            pdf.cell(0, 10, 'Katana Crawler Results:', 0, 1)
            pdf.cell(0, 10, f'Total URLs discovered: {len(results["katana_crawl"])}', 0, 1)
            for url in results['katana_crawl']:
                pdf.multi_cell(0, 10, str(url))
        
        # Add RetireJS results
        if 'js_vulnerabilities' in results:
            pdf.add_page()
            pdf.cell(0, 10, 'JavaScript Library Vulnerabilities:', 0, 1)
            js_vuln_str = json.dumps(results['js_vulnerabilities'], indent=2)
            pdf.multi_cell(0, 10, js_vuln_str)
        
        return pdf

    async def find_alive_domains(self) -> Set[str]:
        """Find alive subdomains using subfinder and httpx"""
        try:
            # Run subfinder
            subfinder_cmd = ['subfinder', '-d', self.domain, '-silent', '-o', f'{self.domain}_subfinder.txt']
            await self.run_async_command(subfinder_cmd, 'subfinder')

            # Process subfinder output
            if os.path.exists(f'{self.domain}_subfinder.txt'):
                with open(f'{self.domain}_subfinder.txt', 'r') as f:
                    subdomains = {line.strip() for line in f}
                os.remove(f'{self.domain}_subfinder.txt')

                # Save domains for httpx
                with open('temp_domains.txt', 'w') as f:
                    f.write('\n'.join(subdomains))

                # Run httpx to check alive domains
                httpx_cmd = [
                    'httpx',
                    '-l', 'temp_domains.txt',
                    '-silent',
                    '-mc', '200,201,202,203,204,301,302,303,304',
                    '-follow-redirects',
                    '-no-color',
                    '-o', f'{self.domain}_alive.txt'
                ]
                await self.run_async_command(httpx_cmd, 'httpx')

                # Process alive domains
                if os.path.exists(f'{self.domain}_alive.txt'):
                    with open(f'{self.domain}_alive.txt', 'r') as f:
                        self.alive_domains = {
                            line.strip()
                            .replace('https://', '')
                            .replace('http://', '')
                            .split('[')[0]
                            .strip()
                            for line in f if line.strip()
                        }
                    os.remove(f'{self.domain}_alive.txt')

                os.remove('temp_domains.txt')
                logger.info(f"Found {len(self.alive_domains)} alive domains")
                return self.alive_domains

        except Exception as e:
            logger.error(f"Error finding alive domains: {e}")
            return set()

    async def run_katana_crawler(self, target: str) -> Set[str]:
        """Enhanced Katana crawler with additional features"""
        try:
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'
                
            output_file = f'katana_{self.domain}.txt'
            katana_cmd = [
                'katana',
                '-u', target,
                '-jc',  # Enable JS parsing
                '-kf', 'all',  # Crawl all form types
                '-d', '5',  # Depth of crawling
                '-silent',
                '-timeout', '30',
                '-o', output_file
            ]
            
            # Only add proxy if configured
            if hasattr(self.config, 'proxy') and self.config.proxy:
                katana_cmd.extend(['-proxy', self.config.proxy])
            
            await self.run_async_command(katana_cmd, 'katana')
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    urls = {line.strip() for line in f if line.strip()}
                os.remove(output_file)
                return urls
            return set()
            
        except Exception as e:
            logger.error(f"Katana crawler error: {e}")
            return set()

    async def run_paramspider(self, target: str) -> Set[str]:
        """Run ParamSpider with improved error handling"""
        try:
            output_dir = os.path.join(os.getcwd(), "paramspider_output")
            os.makedirs(output_dir, exist_ok=True)
            
            paramspider_dir = os.path.join(os.getcwd(), "tools", "ParamSpider")
            paramspider_script = os.path.join(paramspider_dir, "paramspider.py")
            
            if not os.path.exists(paramspider_script):
                logger.error("ParamSpider script not found. Attempting to reinstall...")
                await self.setup_tools()  # This will reinstall ParamSpider
                if not os.path.exists(paramspider_script):
                    return set()
            
            output_file = os.path.join(output_dir, f"{target}.txt")
            cmd = [
                'paramspider',
                '--domain', target,
                '--quiet',
                '--level', '3',
                '--output', output_file
            ]
            
            logger.info(f"Running ParamSpider on {target}")
            await self.run_async_command(cmd, 'ParamSpider')
            
            params = set()
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    params = {line.strip() for line in f if line.strip()}
                try:
                    os.remove(output_file)
                except Exception:
                    pass
            
            return params
            
        except Exception as e:
            logger.error(f"ParamSpider error: {e}")
            return set()

    async def run_gf_patterns(self, urls: Set[str]) -> Dict[str, Set[str]]:
        """Run GF patterns to identify potential vulnerabilities"""
        if not urls:
            logger.info("No URLs to analyze with GF patterns")
            return {}
        
        patterns = {
            'xss': 'xss.json',
            'ssrf': 'ssrf.json',
            'redirect': 'redirect.json',
            'rce': 'rce.json',
            'idor': 'idor.json',
            'lfi': 'lfi.json',
            'sqli': 'sqli.json'
        }
        
        results = {}
        
        try:
            # Write URLs to temporary file
            temp_file = f'urls_{self.domain}.txt'
            with open(temp_file, 'w') as f:
                f.write('\n'.join(urls))
            
            for pattern_name in patterns:
                try:
                    # Use gf with pattern name directly
                    cmd = ['gf', pattern_name, temp_file]
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
                    
                    if stdout:
                        matches = stdout.decode().splitlines()
                        if matches:
                            results[pattern_name] = set(matches)
                            logger.info(f"Found {len(matches)} matches for pattern {pattern_name}")
                
                except Exception as e:
                    logger.error(f"Error running GF pattern {pattern_name}: {e}")
            
            return results
            
        except Exception as e:
            logger.error(f"GF patterns error: {e}")
            return {}
        finally:
            # Cleanup
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                logger.debug(f"Failed to remove temporary file: {e}")

    async def run_full_scan(self):
        """Enhanced full scanning process"""
        try:
            await self.setup()
            await self.setup_dependencies()
            
            with console.status("[bold green]Running security scan...") as status:
                # Find alive domains
                status.update("[bold blue]Finding alive domains...")
                alive_domains = await self.find_alive_domains()
                
                if not alive_domains:
                    logger.warning("No alive domains found")
                    return
                
                all_urls = set()
                
                # Run Katana crawler
                status.update("[bold blue]Crawling domains with Katana...")
                for domain in alive_domains:
                    scraped = await self.run_katana_crawler(domain)
                    all_urls.update(scraped)
                    self.scraped_urls.update(scraped)
                    logger.info(f"Katana found {len(scraped)} URLs for {domain}")
                
                # Run ParamSpider
                status.update("[bold blue]Finding parameter URLs with ParamSpider...")
                for domain in alive_domains:
                    params = await self.run_paramspider(domain)
                    all_urls.update(params)
                    self.scraped_urls.update(params)
                    logger.info(f"ParamSpider found {len(params)} URLs for {domain}")
                
                # Run GF patterns only if we have URLs
                if all_urls:
                    status.update("[bold blue]Analyzing URLs with GF patterns...")
                    pattern_results = await self.run_gf_patterns(all_urls)
                    if pattern_results:
                        self.results['vulnerability_patterns'] = pattern_results
                
                # Run Nuclei scans on all alive domains
                status.update("[bold blue]Running Nuclei vulnerability scans...")
                for domain in alive_domains:
                    try:
                        vuln_results = await self.check_vulnerabilities(domain)
                        if vuln_results:
                            if domain not in self.results:
                                self.results[domain] = {}
                            self.results[domain]['vulnerabilities'] = vuln_results
                            logger.info(f"Completed Nuclei scan for {domain}")
                    except Exception as e:
                        logger.error(f"Failed to scan {domain} with Nuclei: {e}")
                
                # Run additional security checks
                status.update("[bold blue]Running security checks...")
                for domain in alive_domains:
                    try:
                        # SSL check
                        ssl_results = await self.check_ssl(domain)
                        if ssl_results:
                            if domain not in self.results:
                                self.results[domain] = {}
                            self.results[domain]['ssl'] = ssl_results
                        
                        # Headers check
                        header_results = await self.check_headers(domain)
                        if header_results:
                            if domain not in self.results:
                                self.results[domain] = {}
                            self.results[domain]['headers'] = header_results
                        
                        # Port scan
                        port_results = await self.check_ports(domain)
                        if port_results:
                            if domain not in self.results:
                                self.results[domain] = {}
                            self.results[domain]['ports'] = port_results
                            
                    except Exception as e:
                        logger.error(f"Security checks failed for {domain}: {e}")
                
                # Add subdomain takeover checks
                status.update("[bold blue]Checking for subdomain takeovers...")
                for domain in alive_domains:
                    takeover_results = await self.check_subdomain_takeover(domain)
                    if takeover_results.get('vulnerable'):
                        if domain not in self.results:
                            self.results[domain] = {}
                        self.results[domain]['takeover'] = takeover_results
                
                # Add directory fuzzing
                status.update("[bold blue]Running directory fuzzing...")
                for domain in alive_domains:
                    fuzzing_results = await self.run_directory_fuzzing(f"https://{domain}")
                    if fuzzing_results:
                        if domain not in self.results:
                            self.results[domain] = {}
                        self.results[domain]['directories'] = list(fuzzing_results)
                
                # Generate reports
                status.update("[bold blue]Generating reports...")
                try:
                    # Generate HTML report
                    html_report = self.generate_html_report(self.results)
                    with open('report.html', 'w') as f:
                        f.write(html_report)
                    logger.info("Generated HTML report")
                    
                    # Save raw results
                    with open('results.json', 'w') as f:
                        json.dump(self.results, f, indent=4)
                    logger.info("Saved raw results to JSON")
                    
                except Exception as e:
                    logger.error(f"Report generation failed: {e}")
                
            console.print("[bold green]Scan completed successfully!")
            
        except Exception as e:
            logger.error(f"Fatal error during scan: {e}")
            raise
        finally:
            await self.cleanup()

    async def is_domain_resolvable(self, domain):
        """Check if a domain is resolvable"""
        try:
            await asyncio.get_event_loop().getaddrinfo(domain, None)
            return True
        except socket.gaierror:
            return False

    async def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses with fallback"""
        try:
            # Try async DNS resolution first
            ips = await asyncio.get_event_loop().getaddrinfo(domain, None)
            return [ip[4][0] for ip in ips if ip[4][0]]
        except socket.gaierror:
            try:
                # Fallback to synchronous DNS resolution
                answers = dns.resolver.resolve(domain, 'A')
                return [str(rdata) for rdata in answers]
            except Exception:
                return []

    async def setup_tools(self):
        """Setup and verify required tools with better installation handling"""
        required_tools = {
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'amass': 'go install -v github.com/owasp-amass/amass/v4/...@master',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'ffuf': 'go install -v github.com/ffuf/ffuf/v2@latest'
        }
        
        missing_tools = []
        for tool, install_cmd in required_tools.items():
            if not shutil.which(tool):
                logger.warning(f"{tool} not found. Attempting to install...")
                if not await self.install_tool(tool, install_cmd):
                    missing_tools.append(tool)
        
        if missing_tools:
            raise RuntimeError(f"Missing required tools: {', '.join(missing_tools)}")
        
        # Setup ParamSpider separately
        paramspider_dir = os.path.join(os.getcwd(), "tools", "ParamSpider")
        if not os.path.exists(paramspider_dir):
            try:
                os.makedirs(os.path.dirname(paramspider_dir), exist_ok=True)
                clone_cmd = "git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git"
                process = await asyncio.create_subprocess_shell(
                    f"{clone_cmd} {paramspider_dir}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                if os.path.exists(os.path.join(paramspider_dir, "paramspider.py")):
                    # Install ParamSpider requirements
                    req_file = os.path.join(paramspider_dir, "requirements.txt")
                    if os.path.exists(req_file):
                        await self.install_tool("paramspider-deps", f"pip3 install -r {req_file}")
                else:
                    logger.error("Failed to clone ParamSpider repository")
            except Exception as e:
                logger.error(f"Error setting up ParamSpider: {e}")
        
        logger.info("All required tools are available")

    async def run_dns_brute(self):
        """DNS bruteforce using common subdomain wordlist"""
        discovered = set()
        
        # Check if wordlist exists, if not, create a minimal one
        if not os.path.exists(self.wordlist_path):
            os.makedirs(os.path.dirname(self.wordlist_path), exist_ok=True)
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test']
            with open(self.wordlist_path, 'w') as f:
                f.write('\n'.join(common_subdomains))
            logger.warning(f"Created minimal wordlist at {self.wordlist_path}")
        
        async def check_subdomain(word):
            subdomain = f"{word}.{self.domain}"
            try:
                if await self.is_domain_resolvable(subdomain):
                    discovered.add(subdomain)
            except Exception:
                pass
        
        try:
            with open(self.wordlist_path) as f:
                words = [line.strip() for line in f if line.strip()]
            
            # Use ThreadPoolExecutor for DNS queries
            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                loop = asyncio.get_event_loop()
                tasks = [
                    loop.run_in_executor(executor, lambda w=word: asyncio.run(check_subdomain(w)))
                    for word in words[:self.config.max_subdomains]  # Limit number of subdomains
                ]
                await asyncio.gather(*tasks)
        
        except Exception as e:
            logger.error(f"DNS bruteforce error: {e}")
        
        return discovered

    async def run_permutation_scan(self):
        """Scan domain permutations"""
        permutations = set()
        prefixes = ['dev', 'stage', 'test', 'admin', 'api']
        
        for prefix in prefixes:
            subdomain = f"{prefix}.{self.domain}"
            try:
                if await self.is_domain_resolvable(subdomain):
                    permutations.add(subdomain)
            except Exception:
                continue
        
        return permutations

    def validate_config(self):
        """Validate configuration settings with better error handling"""
        try:
            required_configs = {
                'nuclei': {
                    'required': ['rate_limit', 'timeout'],
                    'optional': ['severity']
                }
            }

            if not hasattr(self, 'config'):
                raise ValueError("Configuration not loaded")

            if not hasattr(self.config, 'tools_config'):
                raise ValueError("tools_config not found in configuration")

            for tool, settings in required_configs.items():
                if tool not in self.config.tools_config:
                    self.config.tools_config[tool] = {}
                    logger.warning(f"Missing configuration for {tool}, using defaults")
                    continue

                tool_config = self.config.tools_config[tool]
                
                # Check required fields
                for field in settings['required']:
                    if field not in tool_config:
                        raise ValueError(f"Missing required field '{field}' for {tool}")

        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise

    async def setup_dependencies(self):
        """Setup system dependencies for tools"""
        try:
            # Check system type first
            if platform.system() != 'Linux':
                logger.info("Not on Linux - skipping dependency installation")
                return

            # Check if we can use apt
            if not shutil.which('apt-get'):
                logger.info("apt-get not found - skipping dependency installation")
                return

            # Updated Chrome dependencies list with alternatives
            chrome_deps = {
                'libnss3': ['libnss3'],
                'libxss1': ['libxss1'],
                'libasound2': ['libasound2', 'alsa-lib'],  # Added alternative
                'libatk-bridge2.0-0': ['libatk-bridge2.0-0', 'at-spi2-atk'],  # Added alternative
                'libgtk-3-0': ['libgtk-3-0', 'gtk3'],  # Added alternative
                'libgbm1': ['libgbm1']
            }
            
            # First update package list
            try:
                update_cmd = ['sudo', 'apt-get', 'update']
                result = run(update_cmd, stdout=PIPE, stderr=PIPE, timeout=60)
                if result.returncode != 0:
                    logger.warning(f"Failed to update package list: {result.stderr.decode()}")
            except Exception as e:
                logger.warning(f"Failed to update package list: {e}")

            # Try to install each dependency
            for dep_name, alternatives in chrome_deps.items():
                installed = False
                for alt in alternatives:
                    try:
                        # Check if package is already installed
                        check_cmd = ['dpkg', '-s', alt]
                        result = run(check_cmd, stdout=PIPE, stderr=PIPE)
                        
                        if result.returncode == 0:
                            installed = True
                            break
                        
                        # Try to install the package
                        install_cmd = ['sudo', 'apt-get', 'install', '-y', alt]
                        result = run(install_cmd, stdout=PIPE, stderr=PIPE, timeout=60)
                        
                        if result.returncode == 0:
                            installed = True
                            break
                        
                    except Exception as e:
                        logger.debug(f"Failed to install {alt}: {e}")
                        continue
                
                if not installed:
                    logger.warning(f"Could not install {dep_name} or its alternatives")
                    # Continue with the scan even if some dependencies are missing
                    continue

            logger.info("Dependency setup completed")
            
        except Exception as e:
            logger.warning(f"Error during dependency setup: {e}")
            # Continue with the scan even if dependency setup fails
            return

    async def check_subdomain_takeover(self, subdomain: str) -> Dict:
        """Enhanced subdomain takeover check with better error handling"""
        try:
            if not subdomain.startswith(('http://', 'https://')):
                target = f"https://{subdomain}"
            else:
                target = subdomain

            # Create unique output directory
            scan_id = int(time.time())
            output_dir = f"takeover_output_{scan_id}"
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"takeover_{subdomain.replace(':', '_').replace('/', '_')}.json")

            # Verify nuclei installation
            if not shutil.which('nuclei'):
                logger.error("Nuclei not found for takeover check")
                return {'vulnerable': False, 'error': 'nuclei_not_found'}

            # Use built-in takeover templates
            cmd = [
                'nuclei',
                '-u', target,          # Updated from -target
                '-t', 'takeovers',     # Updated template path
                '-j',                  # Updated from -json
                '-o', output_file,
                '-silent',
                '-timeout', '5',       # 5 minute timeout
                '-retries', '1',       # Single retry
                '-rl', '10'           # Updated from -rate-limit
            ]

            try:
                result = await self.run_async_command_with_timeout(cmd, 'nuclei-takeover', timeout=60)
                if result is None:
                    logger.error(f"Takeover check failed for {target}")
                    return {'vulnerable': False, 'error': 'scan_failed'}
            except TimeoutError:
                logger.error(f"Takeover check timed out for {target}")
                return {'vulnerable': False, 'error': 'timeout'}

            results = []
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                result = json.loads(line.strip())
                                results.append(result)
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    logger.error(f"Error reading takeover results: {e}")
                finally:
                    # Cleanup
                    try:
                        shutil.rmtree(output_dir)
                    except Exception:
                        pass

            return {
                'vulnerable': bool(results),
                'findings': results,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }

        except Exception as e:
            logger.error(f"Subdomain takeover check failed for {subdomain}: {e}")
            return {
                'vulnerable': False,
                'error': str(e),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }

    async def run_directory_fuzzing(self, target: str) -> Set[str]:
        """Perform directory fuzzing using ffuf"""
        try:
            output_file = f"ffuf_{target.replace(':', '_').replace('/', '_')}.json"
            
            # Create and use a custom wordlist if default doesn't exist
            wordlist_path = '/usr/share/wordlists/dirb/common.txt'
            if not os.path.exists(wordlist_path):
                wordlist_path = os.path.join(os.getcwd(), 'wordlists', 'common.txt')
                os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
                
                # Create a basic wordlist if it doesn't exist
                if not os.path.exists(wordlist_path):
                    basic_paths = [
                        'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
                        'dashboard', 'api', 'v1', 'v2', 'console', 'portal',
                        'test', 'dev', 'development', 'staging', 'prod', 'production',
                        'backup', 'backups', 'wp-content', 'wp-includes', 'images',
                        'css', 'js', 'static', 'assets', 'uploads', 'media'
                    ]
                    with open(wordlist_path, 'w') as f:
                        f.write('\n'.join(basic_paths))
                    logger.info(f"Created basic wordlist at {wordlist_path}")
            
            cmd = [
                'ffuf',
                '-u', f"{target}/FUZZ",
                '-w', wordlist_path,
                '-mc', '200,204,301,302,307,401,403',
                '-o', output_file,
                '-of', 'json',
                '-t', '50',          # Number of concurrent threads
                '-timeout', '5',     # Timeout per request
                '-c'                 # Color output
            ]
            
            logger.info(f"Starting directory fuzzing for {target}")
            await self.run_async_command(cmd, 'ffuf')
            
            discovered = set()
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        results = json.load(f)
                        for result in results.get('results', []):
                            if 'url' in result:
                                discovered.add(result['url'])
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse ffuf output for {target}")
                finally:
                    try:
                        os.remove(output_file)
                    except Exception:
                        pass
            
            return discovered
            
        except Exception as e:
            logger.error(f"Directory fuzzing failed for {target}: {e}")
            return set()

    async def install_tool(self, tool_name: str, install_cmd: str) -> bool:
        """Install a tool using the provided command"""
        try:
            logger.info(f"Installing {tool_name}...")
            process = await asyncio.create_subprocess_shell(
                install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"Successfully installed {tool_name}")
                return True
            else:
                logger.error(f"Failed to install {tool_name}: {stderr.decode()}")
                return False
        except Exception as e:
            logger.error(f"Error installing {tool_name}: {e}")
            return False

async def main():
    parser = argparse.ArgumentParser(description="Advanced Information Gathering Tool")
    parser.add_argument('-d', '--domain', required=True, help="Target domain")
    parser.add_argument('-u', '--url', required=True, help="Target URL")
    parser.add_argument('-t', '--templates', required=True, help="Path to Nuclei templates")
    parser.add_argument('-c', '--config', default='config.yaml', help="Path to configuration file")
    args = parser.parse_args()

    # Verify templates directory exists
    if not os.path.exists(args.templates):
        print(f"Error: Templates directory not found: {args.templates}")
        return

    # Create scanner instance with configuration
    scanner = AsyncScanner(args.domain, args.url, args.templates, args.config)
    
    try:
        # Verify tools first
        await scanner.setup_tools()
        
        # Validate configuration
        scanner.validate_config()
        
        # Run the full scan
        await scanner.run_full_scan()
    except RuntimeError as e:
        logger.error(f"Tool setup error: {e}")
        logger.info("Please install missing tools before running the scan")
        return
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")