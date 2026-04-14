import axios, { AxiosResponse } from "axios";
import chalk from "chalk";
import Table from "cli-table3";
import ora from "ora";
import { log, logSilent } from "./logger";

const CHECK_HOST_API = "https://check-host.net/check-tcp";
const CHECK_HOST_RESULT_API = "https://check-host.net/check-result/";
const CHECK_HOST_PING_API = "https://check-host.net/check-ping";
const CHECK_HOST_HTTP_API = "https://check-host.net/check-http";

const REGIONS: Record<string, string> = {
  "us1": "USA (East)",
  "us2": "USA (West)",
  "de1": "Germany",
  "fr1": "France",
  "nl1": "Netherlands",
  "gb1": "UK",
  "jp1": "Japan",
  "sg1": "Singapore",
  "au1": "Australia",
  "br1": "Brazil",
  "ru1": "Russia",
  "in1": "India",
  "ca1": "Canada",
  "se1": "Sweden",
  "pl1": "Poland",
};

export interface GeoCheckResult {
  node: string;
  location: string;
  success: boolean;
  responseTime: number | null;
  statusCode: number | null;
  detail: string;
}

export async function checkGeoAvailability(url: string, mode: "ping" | "http" | "tcp" = "http"): Promise<GeoCheckResult[]> {
  const spinner = ora(chalk.cyan(`Checking availability via ${mode.toUpperCase()} from ${Object.keys(REGIONS).length} nodes...`)).start();
  const results: GeoCheckResult[] = [];

  let target = url;
  if (!/^https?:\/\//i.test(target)) target = "https://" + target;

  try {
    const apiEndpoint = mode === "ping" ? CHECK_HOST_PING_API : mode === "http" ? CHECK_HOST_HTTP_API : CHECK_HOST_API;

    const checkRes = await axios.post(apiEndpoint, `host=${encodeURIComponent(target)}&max_nodes=20`, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
      timeout: 15000,
    });

    const checkId = checkRes.data?.id;
    if (!checkId) {
      spinner.stop();
      log("ERROR", "Failed to start geo-check: no check ID returned");
      return results;
    }

    logSilent("INFO", `Geo-check started, ID: ${checkId}`);

    await new Promise((r) => setTimeout(r, 5000));

    const resultRes = await axios.get(CHECK_HOST_RESULT_API + checkId, {
      headers: { Accept: "application/json" },
      timeout: 15000,
    });

    const nodeResults = resultRes.data || {};

    for (const [nodeKey, nodeData] of Object.entries(nodeResults)) {
      const nodeName = nodeKey.replace(/\.check-host\.net$/, "");
      const location = REGIONS[nodeName] || nodeName;

      const entries = nodeData as Array<Array<string | number>> | null;
      if (!entries || !Array.isArray(entries) || entries.length === 0) {
        results.push({
          node: nodeName,
          location,
          success: false,
          responseTime: null,
          statusCode: null,
          detail: "No response",
        });
        continue;
      }

      for (const entry of entries) {
        if (!entry || entry.length < 2) continue;
        const success = String(entry[0]) === "1" || String(entry[0]) === "ok";
        const responseTime = typeof entry[1] === "number" ? entry[1] : null;
        const statusCode = entry[2] ? Number(entry[2]) : null;

        results.push({
          node: nodeName,
          location,
          success,
          responseTime,
          statusCode,
          detail: success ? `OK${statusCode ? ` [${statusCode}]` : ""}${responseTime ? ` ${responseTime}ms` : ""}` : "Failed",
        });
      }
    }

    spinner.stop();
  } catch (err: any) {
    spinner.stop();
    log("WARN", `External API geo-check failed: ${err.message}. Falling back to direct multi-probe...`);

    const fallbackNodes = [
      { name: "direct-local", location: "Local (Direct)" },
    ];
    for (const node of fallbackNodes) {
      try {
        const start = Date.now();
        const res = await axios.get(target, {
          timeout: 10000,
          validateStatus: () => true,
        });
        const rtt = Date.now() - start;
        results.push({
          node: node.name,
          location: node.location,
          success: res.status < 500,
          responseTime: rtt,
          statusCode: res.status,
          detail: `OK [${res.status}] ${rtt}ms`,
        });
      } catch {
        results.push({
          node: node.name,
          location: node.location,
          success: false,
          responseTime: null,
          statusCode: null,
          detail: "Unreachable",
        });
      }
    }
  }

  return results;
}

export function printGeoTable(results: GeoCheckResult[]): void {
  if (results.length === 0) {
    console.log(chalk.yellow("  No geo-check results"));
    return;
  }

  const table = new Table({
    head: [chalk.cyan("Node"), chalk.cyan("Location"), chalk.cyan("Status"), chalk.cyan("Time"), chalk.cyan("Code"), chalk.cyan("Detail")],
    style: { head: [], border: ["cyan"] },
    colWidths: [14, 16, 10, 10, 8, 22],
  });

  for (const r of results) {
    const statusStr = r.success ? chalk.green("UP") : chalk.red("DOWN");
    const timeStr = r.responseTime ? `${r.responseTime}ms` : "-";
    const codeStr = r.statusCode ? String(r.statusCode) : "-";
    table.push([chalk.white(r.node), chalk.gray(r.location), statusStr, chalk.white(timeStr), chalk.white(codeStr), chalk.gray(r.detail)]);
  }

  console.log(table.toString());

  const upCount = results.filter((r) => r.success).length;
  const totalCount = results.length;
  const pct = Math.round((upCount / totalCount) * 100);
  console.log(chalk.cyan(`  Availability: ${upCount}/${totalCount} nodes (${pct}%)`));
}
