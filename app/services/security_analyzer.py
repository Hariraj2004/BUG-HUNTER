"""
SecurityAnalyzer — Rule-based security analysis engine.
Reads scan output lines and generates attack vectors + remediation advice.
"""

import re
from typing import Dict, Any, List


class SecurityAnalyzer:
    """Pattern-match scan output to identify security risks, possible attacks, and solutions."""

    # ── Port Knowledge Base ──
    PORT_ANALYSIS = {
        21: {
            "service": "FTP",
            "severity": "HIGH",
            "description": "FTP service is exposed. FTP transmits credentials in plaintext.",
            "attacks": [
                "Credential sniffing via packet capture",
                "Brute-force login attack",
                "Anonymous FTP access exploitation",
                "FTP bounce attack for port scanning"
            ],
            "solutions": [
                "Replace FTP with SFTP or SCP",
                "If FTP is required, enforce TLS (FTPS)",
                "Disable anonymous login",
                "Restrict access via firewall rules to trusted IPs"
            ]
        },
        22: {
            "service": "SSH",
            "severity": "MEDIUM",
            "description": "SSH port is publicly accessible. While encrypted, it's a common brute-force target.",
            "attacks": [
                "SSH brute-force / dictionary attack",
                "Exploitation of outdated SSH versions (e.g. CVE-2023-38408)",
                "Username enumeration",
                "Man-in-the-middle if host key not verified"
            ],
            "solutions": [
                "Use key-based authentication only (disable password login)",
                "Move SSH to a non-standard port",
                "Implement fail2ban or similar rate limiting",
                "Restrict SSH access to VPN / specific IP ranges",
                "Keep OpenSSH updated to the latest version"
            ]
        },
        23: {
            "service": "Telnet",
            "severity": "CRITICAL",
            "description": "Telnet transmits all data including credentials in plaintext. This is a critical security risk.",
            "attacks": [
                "Credential interception via network sniffing",
                "Session hijacking",
                "Brute-force authentication attacks",
                "Man-in-the-middle attacks"
            ],
            "solutions": [
                "Disable Telnet immediately and replace with SSH",
                "If Telnet is absolutely required, tunnel it over SSH/VPN",
                "Block port 23 at the firewall level",
                "Audit all Telnet-enabled devices and migrate"
            ]
        },
        25: {
            "service": "SMTP",
            "severity": "MEDIUM",
            "description": "SMTP mail server is exposed. May allow email relay or user enumeration.",
            "attacks": [
                "Open relay abuse for spam",
                "Email address enumeration (VRFY/EXPN)",
                "SMTP injection attacks",
                "Phishing via spoofed emails"
            ],
            "solutions": [
                "Disable open relay — require authentication",
                "Disable VRFY and EXPN commands",
                "Implement SPF, DKIM, and DMARC records",
                "Use STARTTLS for encrypted communication"
            ]
        },
        53: {
            "service": "DNS",
            "severity": "MEDIUM",
            "description": "DNS service is exposed. May be vulnerable to zone transfers or amplification attacks.",
            "attacks": [
                "DNS zone transfer (AXFR) to enumerate all records",
                "DNS amplification DDoS attack",
                "DNS cache poisoning",
                "Subdomain enumeration"
            ],
            "solutions": [
                "Restrict zone transfers to authorized servers only",
                "Implement DNS rate limiting",
                "Use DNSSEC to prevent cache poisoning",
                "Restrict recursive queries to internal clients"
            ]
        },
        80: {
            "service": "HTTP",
            "severity": "MEDIUM",
            "description": "Unencrypted HTTP service is running. Data is transmitted in plaintext.",
            "attacks": [
                "Man-in-the-middle traffic interception",
                "Session hijacking via cookie theft",
                "Content injection / modification",
                "Credential harvesting on login forms"
            ],
            "solutions": [
                "Redirect all HTTP traffic to HTTPS",
                "Implement HSTS (HTTP Strict Transport Security)",
                "Deploy a valid SSL/TLS certificate",
                "Set Secure flag on all cookies"
            ]
        },
        443: {
            "service": "HTTPS",
            "severity": "LOW",
            "description": "HTTPS is properly served. Verify SSL/TLS configuration strength.",
            "attacks": [
                "SSL stripping if HSTS is missing",
                "Exploiting weak cipher suites",
                "Certificate impersonation if pinning is absent",
                "POODLE/BEAST attacks on old TLS versions"
            ],
            "solutions": [
                "Enable HSTS with a long max-age and includeSubDomains",
                "Disable TLS 1.0/1.1 — use TLS 1.2+ only",
                "Use strong cipher suites (AES-GCM, ChaCha20)",
                "Implement certificate transparency monitoring"
            ]
        },
        3306: {
            "service": "MySQL",
            "severity": "CRITICAL",
            "description": "MySQL database is directly accessible from the internet. This is a critical exposure.",
            "attacks": [
                "Brute-force database credentials",
                "SQL injection via exposed service",
                "Data exfiltration",
                "Privilege escalation via known MySQL exploits"
            ],
            "solutions": [
                "Block port 3306 from external access immediately",
                "Bind MySQL to 127.0.0.1 or private network only",
                "Use SSH tunneling for remote DB access",
                "Enforce strong authentication and least-privilege principles"
            ]
        },
        5432: {
            "service": "PostgreSQL",
            "severity": "CRITICAL",
            "description": "PostgreSQL database is directly accessible from the internet.",
            "attacks": [
                "Brute-force database credentials",
                "Exploitation of trust-based authentication",
                "Data exfiltration and manipulation",
                "Privilege escalation attacks"
            ],
            "solutions": [
                "Restrict PostgreSQL to localhost or private network",
                "Use pg_hba.conf to enforce strict authentication",
                "Block port 5432 at the firewall level",
                "Enable SSL for all database connections"
            ]
        },
        27017: {
            "service": "MongoDB",
            "severity": "CRITICAL",
            "description": "MongoDB is publicly accessible. Many MongoDB instances lack authentication by default.",
            "attacks": [
                "Unauthenticated access to all databases",
                "Data theft and ransom attacks",
                "Remote code execution via server-side scripting",
                "Denial of service attacks"
            ],
            "solutions": [
                "Enable authentication immediately",
                "Bind MongoDB to localhost only",
                "Block port 27017 from external access",
                "Enable audit logging and TLS"
            ]
        },
        6379: {
            "service": "Redis",
            "severity": "CRITICAL",
            "description": "Redis is publicly accessible. Redis often runs without authentication.",
            "attacks": [
                "Unauthorized data access and manipulation",
                "Writing SSH keys for remote access (Redis RCE)",
                "Denial of service via FLUSHALL",
                "Config injection to write arbitrary files"
            ],
            "solutions": [
                "Set a strong requirepass password",
                "Bind Redis to 127.0.0.1 only",
                "Disable dangerous commands (FLUSHALL, CONFIG, DEBUG)",
                "Use firewall rules to block external access"
            ]
        },
        8080: {
            "service": "HTTP Proxy / Alt HTTP",
            "severity": "MEDIUM",
            "description": "Alternative HTTP service or proxy is exposed.",
            "attacks": [
                "Proxy abuse for anonymous browsing",
                "Application-level attacks on the service",
                "Information disclosure via default pages",
                "Server-side request forgery (SSRF)"
            ],
            "solutions": [
                "Restrict access to authorized users",
                "Remove default pages and error messages",
                "Implement authentication if it's an admin panel",
                "Use HTTPS and proper access controls"
            ]
        },
        445: {
            "service": "SMB",
            "severity": "CRITICAL",
            "description": "SMB file sharing is exposed to the internet. Highly targeted by ransomware.",
            "attacks": [
                "EternalBlue (MS17-010) exploitation",
                "SMB relay attacks for credential theft",
                "Ransomware propagation (WannaCry, NotPetya)",
                "Brute-force share access"
            ],
            "solutions": [
                "Block port 445 from external access immediately",
                "Apply all SMB security patches",
                "Disable SMBv1 completely",
                "Use VPN for remote file sharing access"
            ]
        },
        3389: {
            "service": "RDP",
            "severity": "HIGH",
            "description": "Remote Desktop Protocol is exposed. Primary target for ransomware operators.",
            "attacks": [
                "Brute-force RDP credentials",
                "BlueKeep (CVE-2019-0708) exploitation",
                "Credential stuffing attacks",
                "Session hijacking"
            ],
            "solutions": [
                "Place RDP behind a VPN or bastion host",
                "Enable Network Level Authentication (NLA)",
                "Use multi-factor authentication",
                "Limit login attempts and enable account lockout"
            ]
        },
        8443: {
            "service": "HTTPS Alt",
            "severity": "LOW",
            "description": "Alternative HTTPS service detected, often used by management interfaces.",
            "attacks": [
                "Default credential exploitation on admin panels",
                "Information disclosure via management interfaces",
                "Exploiting outdated management software"
            ],
            "solutions": [
                "Change default credentials immediately",
                "Restrict access to management interfaces by IP",
                "Keep management software up to date"
            ]
        },
        9200: {
            "service": "Elasticsearch",
            "severity": "CRITICAL",
            "description": "Elasticsearch is publicly accessible. Often runs without authentication.",
            "attacks": [
                "Unauthenticated data access and exfiltration",
                "Index deletion (data destruction)",
                "Remote code execution via scripting engine",
                "Sensitive data exposure (PII, credentials)"
            ],
            "solutions": [
                "Enable X-Pack Security or SearchGuard authentication",
                "Bind Elasticsearch to localhost or private network",
                "Block port 9200 at the firewall",
                "Disable dynamic scripting if not needed"
            ]
        },
    }

    # ── Web / Header Analysis Rules ──
    HEADER_RULES = [
        {
            "pattern": r"X-Frame-Options.*?missing|x-frame-options.*?not set",
            "severity": "MEDIUM",
            "title": "Missing X-Frame-Options Header",
            "description": "The site is vulnerable to clickjacking attacks.",
            "attacks": ["Clickjacking — tricking users into clicking hidden elements", "UI redressing attacks"],
            "solutions": ["Set X-Frame-Options: DENY or SAMEORIGIN", "Implement Content-Security-Policy frame-ancestors directive"]
        },
        {
            "pattern": r"Content-Security-Policy.*?missing|CSP.*?not set|content-security-policy.*?not found",
            "severity": "MEDIUM",
            "title": "Missing Content-Security-Policy Header",
            "description": "No CSP header found. The site is more vulnerable to XSS attacks.",
            "attacks": ["Cross-site scripting (XSS)", "Data injection attacks", "Content injection"],
            "solutions": ["Implement a strict Content-Security-Policy header", "Start with a report-only policy and iterate", "Use nonce-based CSP for inline scripts"]
        },
        {
            "pattern": r"Strict-Transport-Security.*?missing|HSTS.*?not set|strict-transport-security.*?not found",
            "severity": "HIGH",
            "title": "Missing HSTS Header",
            "description": "HTTP Strict Transport Security is not enforced.",
            "attacks": ["SSL stripping attacks", "Protocol downgrade attacks", "Man-in-the-middle via HTTP redirect"],
            "solutions": ["Add Strict-Transport-Security header with max-age >= 31536000", "Include the includeSubDomains directive", "Consider HSTS preloading"]
        },
        {
            "pattern": r"X-Content-Type-Options.*?missing|x-content-type-options.*?nosniff.*?not",
            "severity": "LOW",
            "title": "Missing X-Content-Type-Options Header",
            "description": "Browser may MIME-sniff responses, leading to security issues.",
            "attacks": ["MIME confusion attacks", "Drive-by download exploitation"],
            "solutions": ["Set X-Content-Type-Options: nosniff"]
        },
        {
            "pattern": r"X-XSS-Protection.*?missing|x-xss-protection.*?not set",
            "severity": "LOW",
            "title": "Missing X-XSS-Protection Header",
            "description": "Browser's built-in XSS filter is not explicitly enabled.",
            "attacks": ["Reflected XSS attacks"],
            "solutions": ["Set X-XSS-Protection: 1; mode=block", "Better yet, rely on a strong Content-Security-Policy"]
        },
        {
            "pattern": r"Server:.*?(Apache|nginx|IIS|LiteSpeed|Tomcat)[\s/]*([\d.]+)?",
            "severity": "LOW",
            "title": "Server Version Disclosure",
            "description": "The web server is disclosing its software name and version.",
            "attacks": ["Targeted exploitation of known vulnerabilities for the disclosed version", "Technology fingerprinting for attack planning"],
            "solutions": ["Remove or obscure the Server header", "Use ServerTokens Prod (Apache) or server_tokens off (Nginx)", "Keep web server software up to date"]
        },
    ]

    # ── DNS / Subdomain Rules ──
    DNS_RULES = [
        {
            "pattern": r"zone transfer|AXFR|axfr.*?successful|transfer.*?allowed",
            "severity": "HIGH",
            "title": "DNS Zone Transfer Allowed",
            "description": "The DNS server allows zone transfers, exposing all DNS records.",
            "attacks": ["Complete domain reconnaissance — all subdomains exposed", "Identification of internal hosts and services", "Attack surface mapping"],
            "solutions": ["Restrict AXFR to authorized secondary DNS servers", "Implement ACLs on the DNS server", "Monitor for unauthorized transfer attempts"]
        },
        {
            "pattern": r"CNAME.*?(?:s3|heroku|github|azure|cloudfront|shopify|fastly|pantheon|ghost|helpscout|cargo|surge|statuspage|readme|bitbucket|wordpress|tumblr|strikingly|feedpress|unbounce|ghost)",
            "severity": "HIGH",
            "title": "Potential Subdomain Takeover",
            "description": "A CNAME record points to an external service that may be unclaimed.",
            "attacks": ["Subdomain takeover — attacker can claim the external service and serve malicious content", "Phishing via trusted subdomain", "Cookie theft across the parent domain"],
            "solutions": ["Verify all CNAME targets are actively claimed", "Remove DNS records pointing to decommissioned services", "Monitor for dangling DNS records regularly"]
        },
        {
            "pattern": r"open resolver|recursion.*?enabled|allows recursive",
            "severity": "HIGH",
            "title": "Open DNS Resolver",
            "description": "The DNS server allows recursive queries from external sources.",
            "attacks": ["DNS amplification DDoS attacks", "DNS cache poisoning", "Information leakage via recursive resolution"],
            "solutions": ["Disable recursion for external queries", "Implement response rate limiting (RRL)", "Use ACLs to restrict recursive queries to internal clients"]
        },
    ]

    # ── SSL/TLS Rules ──
    SSL_RULES = [
        {
            "pattern": r"SSLv[23]|TLSv1\.0|TLSv1\.1|ssl.*?v[23]|tls.*?1\.0|tls.*?1\.1",
            "severity": "HIGH",
            "title": "Deprecated SSL/TLS Version Supported",
            "description": "The server supports deprecated SSL/TLS versions with known vulnerabilities.",
            "attacks": ["POODLE attack (SSLv3)", "BEAST attack (TLS 1.0)", "Protocol downgrade attacks", "Decryption of intercepted traffic"],
            "solutions": ["Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1", "Support only TLS 1.2 and TLS 1.3", "Update cipher suite configuration"]
        },
        {
            "pattern": r"expired|certificate.*?expir|cert.*?invalid|not yet valid",
            "severity": "CRITICAL",
            "title": "SSL Certificate Issue",
            "description": "The SSL certificate is expired, invalid, or not yet valid.",
            "attacks": ["Man-in-the-middle attacks — users may bypass certificate warnings", "Phishing via spoofed certificate", "Loss of user trust"],
            "solutions": ["Renew the SSL certificate immediately", "Set up automated certificate renewal (e.g., Let's Encrypt + certbot)", "Monitor certificate expiration dates"]
        },
        {
            "pattern": r"self.signed|self-signed|selfsigned",
            "severity": "HIGH",
            "title": "Self-Signed Certificate Detected",
            "description": "The server uses a self-signed certificate not trusted by browsers.",
            "attacks": ["Users trained to bypass certificate warnings", "Man-in-the-middle attacks", "Impersonation attacks"],
            "solutions": ["Replace with a certificate from a trusted CA", "Use Let's Encrypt for free, trusted certificates", "Never use self-signed certs in production"]
        },
        {
            "pattern": r"weak.*?cipher|RC4|DES|NULL|EXPORT|anon|MD5.*?cipher",
            "severity": "HIGH",
            "title": "Weak Cipher Suite Detected",
            "description": "The server supports weak or insecure cipher suites.",
            "attacks": ["Decryption of intercepted traffic", "SWEET32 attacks (3DES)", "RC4 bias attacks"],
            "solutions": ["Disable weak ciphers (RC4, DES, 3DES, NULL, EXPORT, anonymous)", "Use AES-GCM and ChaCha20-Poly1305 cipher suites", "Follow Mozilla's recommended TLS configuration"]
        },
    ]

    # ── General / Information Disclosure ──
    GENERAL_RULES = [
        {
            "pattern": r"directory.*?list|Index of /|directory.*?browsing.*?enabled",
            "severity": "MEDIUM",
            "title": "Directory Listing Enabled",
            "description": "Web server directories are browsable, exposing file structure.",
            "attacks": ["Discovery of sensitive files (backups, configs, source code)", "Information gathering for targeted attacks", "Access to unprotected resources"],
            "solutions": ["Disable directory listing (Options -Indexes in Apache)", "Add index files to all directories", "Review exposed file structure for sensitive data"]
        },
        {
            "pattern": r"admin.*?panel|/admin|/wp-admin|/administrator|/manager|/phpmyadmin|phpMyAdmin",
            "severity": "MEDIUM",
            "title": "Admin Panel Exposed",
            "description": "An administrative interface is publicly accessible.",
            "attacks": ["Brute-force admin credentials", "Exploitation of admin panel vulnerabilities", "Privilege escalation"],
            "solutions": ["Restrict admin panel access by IP whitelist", "Implement multi-factor authentication", "Use a non-standard URL for admin interfaces", "Implement account lockout after failed attempts"]
        },
        {
            "pattern": r"\.git|\.env|\.DS_Store|\.svn|\.hg|web\.config|wp-config|config\.php|\.bak|\.old|\.sql",
            "severity": "HIGH",
            "title": "Sensitive File Exposure",
            "description": "Potentially sensitive files or directories are accessible.",
            "attacks": ["Source code theft via .git exposure", "Credential extraction from .env or config files", "Database dump access from .sql or .bak files"],
            "solutions": ["Block access to sensitive files in web server config", "Remove backup and configuration files from web root", "Add rules to .htaccess or nginx config to deny access"]
        },
        {
            "pattern": r"WordPress|Joomla|Drupal|Magento|wp-content|wp-includes",
            "severity": "LOW",
            "title": "CMS Technology Detected",
            "description": "A content management system has been identified.",
            "attacks": ["Exploitation of known CMS vulnerabilities", "Plugin/theme vulnerability exploitation", "Default credential attacks"],
            "solutions": ["Keep the CMS and all plugins/themes updated", "Remove unused plugins and themes", "Use a Web Application Firewall (WAF)", "Implement security hardening specific to the CMS"]
        },
        {
            "pattern": r"X-Powered-By|x-powered-by|powered.by",
            "severity": "LOW",
            "title": "Technology Stack Disclosure",
            "description": "The X-Powered-By header reveals backend technology information.",
            "attacks": ["Targeted exploitation based on disclosed framework/version", "Attack surface identification"],
            "solutions": ["Remove the X-Powered-By header", "Configure the framework to suppress version headers"]
        },
    ]

    def analyze(self, output_lines: List[str], module_name: str = "") -> Dict[str, Any]:
        """
        Analyze scan output lines and return structured security findings.
        """
        findings: List[Dict[str, Any]] = []
        full_text = "\n".join(output_lines)

        # ── Port analysis ──
        # Match standard nmap format "22/tcp open" or direct text "port 22 is open"
        port_pattern = re.compile(r'\b(\d{1,5})/(?:tcp|udp)\s+(?:open|OPEN)\b')
        direct_port_pattern = re.compile(r'\b[Pp]ort\s+(\d{1,5})\s+is\s+(?:open|OPEN)\b')
        # Match our rich table format "| 22 | ssh |"
        table_port_pattern = re.compile(r'^\s*\|\s*(\d{1,5})\s*\|\s*[a-zA-Z0-9-]+\s*\|')

        found_ports = set()
        for line in output_lines:
            for p in [port_pattern, direct_port_pattern, table_port_pattern]:
                for m in p.finditer(line):
                    port = int(m.group(1))
                    if 1 <= port <= 65535:
                        found_ports.add(port)

        for port in sorted(found_ports):
            if port in self.PORT_ANALYSIS:
                info = self.PORT_ANALYSIS[port]
                findings.append({
                    "title": f"Open Port {port} ({info['service']})",
                    "severity": info["severity"],
                    "description": info["description"],
                    "attacks": info["attacks"],
                    "solutions": info["solutions"]
                })
            else:
                findings.append({
                    "title": f"Open Port {port}",
                    "severity": "INFO",
                    "description": f"Port {port} is open. Investigate what service is running and whether it needs to be public.",
                    "attacks": ["Service fingerprinting and version detection", "Exploitation of any vulnerabilities in the running service"],
                    "solutions": ["Identify the service running on this port", "Close the port if the service is unnecessary", "Apply firewall rules to restrict access"]
                })

        # ── Pattern-based rules ──
        all_rules = self.HEADER_RULES + self.DNS_RULES + self.SSL_RULES + self.GENERAL_RULES
        for rule in all_rules:
            if re.search(rule["pattern"], full_text, re.IGNORECASE):
                findings.append({
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "attacks": rule["attacks"],
                    "solutions": rule["solutions"]
                })

        # ── Subdomain count analysis ──
        subdomain_pattern = re.compile(r'(?:^|\s)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)', re.IGNORECASE)
        subdomains = set()
        for line in output_lines:
            for m in subdomain_pattern.finditer(line):
                host = m.group(1)
                if '.' in host and not host.replace('.', '').isdigit():
                    subdomains.add(host.lower())

        if len(subdomains) > 10:
            findings.append({
                "title": f"Large Attack Surface ({len(subdomains)} Subdomains Found)",
                "severity": "MEDIUM",
                "description": f"Discovered {len(subdomains)} subdomains, indicating a large attack surface.",
                "attacks": [
                    "Subdomain takeover on unused/misconfigured subdomains",
                    "Targeting less-maintained subdomains for exploitation",
                    "Lateral movement opportunities"
                ],
                "solutions": [
                    "Audit all discovered subdomains for active use",
                    "Remove DNS records for decommissioned services",
                    "Ensure consistent security policies across all subdomains",
                    "Implement wildcard certificates carefully"
                ]
            })

        # ── Compute overall risk level ──
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_severity = 0
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = f["severity"]
            counts[s] = counts.get(s, 0) + 1
            max_severity = max(max_severity, severity_order.get(s, 0))

        risk_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
        risk_level = risk_map.get(max_severity, "INFO") if findings else "CLEAR"

        # Build summary
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts[sev] > 0:
                parts.append(f"{counts[sev]} {sev.lower()}")
        summary = f"Found {', '.join(parts)} issue(s)" if parts else "No security issues detected in scan output"

        return {
            "risk_level": risk_level,
            "findings": findings,
            "summary": summary,
            "total_findings": len(findings)
        }
