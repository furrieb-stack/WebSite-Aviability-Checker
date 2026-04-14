import chalk from "chalk";
import Table from "cli-table3";
import boxen from "boxen";
import {
  checkAvailability,
  scanDirectories,
  scanHeaders,
  scanVulnerabilities,
  fullScan,
  printAvailabilityTable,
  printDirectoriesTable,
  printHeadersTable,
  printVulnsTable,
  printRating,
  VulnResult,
  DirScanResult,
} from "./scanner";
import { log, readLogs, openLogConsole, getLogPath, initLogger } from "./logger";
import { enToRu } from "./layout";
import { checkGeoAvailability, printGeoTable } from "./geocheck";
import { pushAttack, printPushResults } from "./push";
import { printVulnGuide, getAllVulnTypes } from "./vulndb";

interface Command {
  name: string;
  alias: string[];
  description: string;
  usage: string;
  ruHint: string;
  handler: (args: string[]) => Promise<void>;
}

let lastScanVulns: VulnResult[] = [];
let lastScanDirs: DirScanResult[] = [];

const commands: Command[] = [
  {
    name: "help",
    alias: ["h", "?", "commands"],
    description: "Show available commands",
    usage: "help",
    ruHint: enToRu("help"),
    handler: async () => printHelp(),
  },
  {
    name: "check",
    alias: ["c", "availability", "up"],
    description: "Check website availability (tech stack, WAF, SSL)",
    usage: "check <url>",
    ruHint: enToRu("check"),
    handler: async (args) => cmdCheck(args),
  },
  {
    name: "scan",
    alias: ["s", "fullscan"],
    description: "Full security scan (XSS, SQLi, LFI, SSRF, CMDi, PathTraversal, headers, dirs)",
    usage: "scan <url>",
    ruHint: enToRu("scan"),
    handler: async (args) => cmdScan(args),
  },
  {
    name: "dirs",
    alias: ["d", "dir", "directories", "paths"],
    description: "Directory/path enumeration (~160 paths)",
    usage: "dirs <url>",
    ruHint: enToRu("dirs"),
    handler: async (args) => cmdDirs(args),
  },
  {
    name: "headers",
    alias: ["hd", "header"],
    description: "Check security headers",
    usage: "headers <url>",
    ruHint: enToRu("headers"),
    handler: async (args) => cmdHeaders(args),
  },
  {
    name: "vuln",
    alias: ["v", "vulns", "vulnerability", "vulnerabilities"],
    description: "Vulnerability testing (XSS, SQLi, LFI, SSRF, CMDi, etc.)",
    usage: "vuln <url>",
    ruHint: enToRu("vuln"),
    handler: async (args) => cmdVuln(args),
  },
  {
    name: "push",
    alias: ["p", "push", "exploit", "attack"],
    description: "PUSH mode — aggressive auth bypass & exploitation",
    usage: "push <url>",
    ruHint: enToRu("push"),
    handler: async (args) => cmdPush(args),
  },
  {
    name: "geo",
    alias: ["g", "geocheck", "world", "global"],
    description: "Multi-region availability check (worldwide nodes)",
    usage: "geo <url> [ping|http|tcp]",
    ruHint: enToRu("geo"),
    handler: async (args) => cmdGeo(args),
  },
  {
    name: "guide",
    alias: ["gd", "info", "exploit-guide"],
    description: "Vulnerability exploitation guide & remediation",
    usage: "guide <type>",
    ruHint: enToRu("guide"),
    handler: async (args) => cmdGuide(args),
  },
  {
    name: "log",
    alias: ["l", "logs"],
    description: "View scan logs / open log console",
    usage: "log [open|path|clear]",
    ruHint: enToRu("log"),
    handler: async (args) => cmdLog(args),
  },
  {
    name: "clear",
    alias: ["cls", "clr"],
    description: "Clear console",
    usage: "clear",
    ruHint: enToRu("clear"),
    handler: async () => {
      process.stdout.write("\x1Bc");
    },
  },
  {
    name: "about",
    alias: ["info", "version", "ver"],
    description: "About SAC",
    usage: "about",
    ruHint: enToRu("about"),
    handler: async () => printAbout(),
  },
  {
    name: "exit",
    alias: ["quit", "q", "bye"],
    description: "Exit SAC",
    usage: "exit",
    ruHint: enToRu("exit"),
    handler: async () => {
      console.log(chalk.magenta("\n  Goodbye! made by .furrieb\n"));
      process.exit(0);
    },
  },
];

function printHelp(): void {
  const table = new Table({
    head: [
      chalk.cyan("Command"),
      chalk.cyan("Aliases"),
      chalk.cyan("Usage"),
      chalk.gray("RU Layout"),
    ],
    style: { head: [], border: ["cyan"] },
    colWidths: [12, 26, 26, 14],
  });

  for (const cmd of commands) {
    table.push([
      chalk.green(cmd.name),
      chalk.gray(cmd.alias.join(", ")),
      chalk.white(cmd.usage),
      chalk.magenta(cmd.ruHint),
    ]);
  }

  const tip = chalk.gray(
    "\n  Tip: Type in Russian layout — auto-recognized! рудз=help, ысфт=scan, зышщ=push\n" +
      "  Vuln types: XSS, SQLi, LFI, RFI, SSRF, CMDi, PathTraversal, OpenRedirect, InfoLeak, AuthBypass\n"
  );

  console.log(
    boxen(chalk.bold.cyan("  SAC Commands  "), {
      padding: { top: 0, bottom: 0, left: 2, right: 2 },
      borderStyle: "round",
      borderColor: "cyan",
      margin: { top: 1, bottom: 0, left: 0, right: 0 },
    })
  );
  console.log(table.toString());
  console.log(tip);
}

function printAbout(): void {
  const content = [
    "",
    chalk.cyan.bold("  SAC - Site Availability Checker"),
    chalk.gray("  Version 2.0 — PUSH Edition"),
    "",
    chalk.white("  Full-featured security audit & exploitation tool"),
    "",
    chalk.white("  Scanning:"),
    chalk.green("  ✓  Multi-region availability (check-host.net API)"),
    chalk.green("  ✓  Directory enumeration (160+ paths)"),
    chalk.green("  ✓  Security header analysis"),
    chalk.green("  ✓  XSS (30 payloads, multiple contexts)"),
    chalk.green("  ✓  SQL Injection (30+ payloads, error + time-based)"),
    chalk.green("  ✓  Local File Inclusion"),
    chalk.green("  ✓  Server-Side Request Forgery"),
    chalk.green("  ✓  Command Injection"),
    chalk.green("  ✓  Path Traversal"),
    chalk.green("  ✓  Open Redirect"),
    chalk.green("  ✓  Information Leak detection"),
    chalk.green("  ✓  WAF detection (15+ signatures)"),
    chalk.green("  ✓  Tech stack fingerprinting"),
    "",
    chalk.red.bold("  PUSH Mode:"),
    chalk.keyword("orange")("  ✓  Default credential brute-force (40+ combos)"),
    chalk.keyword("orange")("  ✓  SQL injection auth bypass"),
    chalk.keyword("orange")("  ✓  JWT alg=none bypass & role escalation"),
    chalk.keyword("orange")("  ✓  Header-based auth bypass (13 headers)"),
    chalk.keyword("orange")("  ✓  Path obfuscation bypass"),
    chalk.keyword("orange")("  ✓  HTTP method bypass"),
    chalk.keyword("orange")("  ✓  NoSQL injection auth bypass"),
    chalk.keyword("orange")("  ✓  Mass assignment / parameter pollution"),
    "",
    chalk.magenta.bold("  made by .furrieb"),
    "",
  ].join("\n");

  console.log(
    boxen(content, {
      padding: 0,
      borderStyle: "round",
      borderColor: "magenta",
      margin: { top: 1, bottom: 0, left: 0, right: 0 },
    })
  );
}

function requireUrl(args: string[]): string | null {
  if (args.length === 0) {
    log("ERROR", "URL is required. Usage: <command> <url>");
    return null;
  }
  return args[0];
}

async function cmdCheck(args: string[]): Promise<void> {
  const url = requireUrl(args);
  if (!url) return;
  log("INFO", `Checking availability: ${chalk.cyan(url)}`);
  const result = await checkAvailability(url);
  printAvailabilityTable(result);
  if (result.isUp) {
    log("OK", `${chalk.cyan(url)} is UP [${result.statusCode}] ${result.responseTime}ms | Tech: ${result.techStack.join(", ") || "?"} | WAF: ${result.wafName || "none"}`);
  } else {
    log("ERROR", `${chalk.cyan(url)} is DOWN`);
  }
}

async function cmdScan(args: string[]): Promise<void> {
  const url = requireUrl(args);
  if (!url) return;
  const result = await fullScan(url);
  lastScanVulns = result.vulnerabilities;
  lastScanDirs = result.directories;
}

async function cmdDirs(args: string[]): Promise<void> {
  const url = requireUrl(args);
  if (!url) return;
  log("INFO", `Enumerating paths on ${chalk.cyan(url)}`);
  const results = await scanDirectories(url);
  lastScanDirs = results;
  printDirectoriesTable(results);
  const found = results.filter((r) => r.found);
  log("INFO", `Found ${chalk.yellow(String(found.length))} accessible paths`);
}

async function cmdHeaders(args: string[]): Promise<void> {
  const url = requireUrl(args);
  if (!url) return;
  log("INFO", `Checking security headers on ${chalk.cyan(url)}`);
  const results = await scanHeaders(url);
  printHeadersTable(results);
  const missing = results.filter((h) => !h.present);
  log("INFO", `${chalk.yellow(String(missing.length))} security headers missing`);
}

async function cmdVuln(args: string[]): Promise<void> {
  const url = requireUrl(args);
  if (!url) return;
  log("INFO", `Testing vulnerabilities on ${chalk.cyan(url)}`);
  const vulns = await scanVulnerabilities(url);
  lastScanVulns = vulns;
  printVulnsTable(vulns);
  if (vulns.length > 0) {
    const types = [...new Set(vulns.map((v) => v.type))];
    log("WARN", `Found ${chalk.red(String(vulns.length))} vulns [${types.map((t) => chalk.red(t)).join(", ")}]`);
    log("INFO", `Use ${chalk.green("guide <type>")} for exploitation details`);
  } else {
    log("OK", "No vulnerabilities found");
  }
}

async function cmdPush(args: string[]): Promise<void> {
  const url = requireUrl(args);
  if (!url) return;

  console.log(chalk.red.bold(boxen(
    chalk.red.bold("  PUSH MODE  ") + "\n" +
    chalk.keyword("orange")("  Aggressive exploitation testing\n") +
    chalk.gray("  Auth bypass, SQLi, JWT, path tricks, NoSQL, mass assignment"),
    { padding: { top: 0, bottom: 0, left: 1, right: 1 }, borderStyle: "round", borderColor: "red", margin: { top: 1, bottom: 0, left: 0, right: 0 } }
  )));

  const pushResults = await pushAttack(url, lastScanVulns, lastScanDirs);
  printPushResults(pushResults);

  if (pushResults.filter((r) => r.success).length > 0) {
    const cats = [...new Set(pushResults.filter((r) => r.success).map((r) => r.category))];
    log("WARN", `Push attack found ${chalk.red(String(pushResults.filter((r) => r.success).length))} bypasses!`);
    log("INFO", `Categories: ${cats.map((c) => chalk.red(c)).join(", ")}`);
    log("INFO", `Run ${chalk.green("guide AuthBypass")} / ${chalk.green("guide SQLi")} for details`);
  } else {
    log("OK", "Target resistant to push attacks. No bypasses found.");
  }
}

async function cmdGeo(args: string[]): Promise<void> {
  const url = requireUrl(args);
  if (!url) return;
  const mode = (args[1] || "http").toLowerCase() as "ping" | "http" | "tcp";
  if (!["ping", "http", "tcp"].includes(mode)) {
    log("ERROR", "Mode must be ping, http, or tcp");
    return;
  }
  log("INFO", `Geo-checking ${chalk.cyan(url)} via ${mode.toUpperCase()}`);
  const results = await checkGeoAvailability(url, mode);
  printGeoTable(results);
}

async function cmdGuide(args: string[]): Promise<void> {
  const type = args[0];
  if (!type) {
    console.log(chalk.cyan("  Available vulnerability types:"));
    console.log(chalk.gray("  " + getAllVulnTypes().join(", ")));
    console.log(chalk.gray("\n  Usage: guide <type>"));
    return;
  }
  printVulnGuide(type);
}

async function cmdLog(args: string[]): Promise<void> {
  const sub = args[0]?.toLowerCase();

  if (sub === "open") {
    openLogConsole();
    return;
  }

  if (sub === "path") {
    console.log(chalk.cyan(`  Log file: ${getLogPath()}`));
    return;
  }

  if (sub === "clear") {
    initLogger();
    log("OK", "Log file cleared");
    return;
  }

  const logs = readLogs();
  if (logs.length === 0) {
    console.log(chalk.gray("  No logs yet"));
    return;
  }

  const recent = logs.slice(-50);
  console.log(chalk.cyan(`  Last ${recent.length} log entries:`));
  for (const entry of recent) {
    console.log(chalk.gray("  " + entry));
  }
  console.log(chalk.gray(`\n  Total: ${logs.length} entries | Use ${chalk.white("log open")} for live console`));
}

export function resolveCommand(input: string): Command | null {
  const parts = input.trim().split(/\s+/);
  const cmdName = parts[0].toLowerCase();
  const args = parts.slice(1);

  for (const cmd of commands) {
    if (cmd.name === cmdName || cmd.alias.includes(cmdName)) {
      return { ...cmd, handler: () => cmd.handler(args) };
    }
  }
  return null;
}

export { commands };
