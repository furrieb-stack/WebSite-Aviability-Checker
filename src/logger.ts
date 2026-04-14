import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";

const LOG_DIR = path.join(process.cwd(), "sac-logs");

let currentLogFile: string;

function ensureLogDir(): void {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function getTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function getTimeStr(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

export function initLogger(): string {
  ensureLogDir();
  currentLogFile = path.join(LOG_DIR, `sac-${getTimestamp()}.log`);
  fs.writeFileSync(currentLogFile, `[${getTimeStr}] SAC Logger initialized\n`);
  return currentLogFile;
}

export type LogLevel = "INFO" | "WARN" | "ERROR" | "FIND" | "OK";

function levelColor(level: LogLevel): chalk.Chalk {
  switch (level) {
    case "INFO":
      return chalk.blue;
    case "WARN":
      return chalk.yellow;
    case "ERROR":
      return chalk.red;
    case "FIND":
      return chalk.magenta;
    case "OK":
      return chalk.green;
  }
}

export function log(level: LogLevel, message: string): void {
  const time = getTimeStr();
  const line = `[${time}] [${level}] ${message}`;
  fs.appendFileSync(currentLogFile, line + "\n");
  const colored = `[${chalk.gray(time)}] [${levelColor(level)(level)}] ${message}`;
  console.log(colored);
}

export function logSilent(level: LogLevel, message: string): void {
  const time = getTimeStr();
  const line = `[${time}] [${level}] ${message}`;
  fs.appendFileSync(currentLogFile, line + "\n");
}

export function getLogPath(): string {
  return currentLogFile;
}

export function readLogs(): string[] {
  if (!fs.existsSync(currentLogFile)) return [];
  return fs.readFileSync(currentLogFile, "utf-8").split("\n").filter(Boolean);
}

export function openLogConsole(): void {
  const logFile = currentLogFile;
  const script = `@echo off && title SAC - Log Console && color 0A && echo ═══════════════════════════════════════════════════ && echo   SAC Log Viewer - made by .furrieb && echo   Log: ${logFile} && echo ═══════════════════════════════════════════════════ && echo. && powershell -Command "Get-Content '${logFile}' -Wait"`;
  const batPath = path.join(LOG_DIR, "log-viewer.bat");
  fs.writeFileSync(batPath, script);
  const { exec } = require("child_process");
  exec(`start cmd /k "${batPath}"`, (err: any) => {
    if (err) {
      log("ERROR", `Failed to open log console: ${err.message}`);
    } else {
      log("OK", "Log console opened in new window");
    }
  });
}
