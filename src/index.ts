#!/usr/bin/env node
import * as readline from "readline";
import chalk from "chalk";
import boxen from "boxen";
import { getBanner } from "./banner";
import { resolveCommand as resolveLayoutCommand, hasRussian, ruToEn } from "./layout";
import { initLogger, log } from "./logger";
import { resolveCommand, commands } from "./commands";

function printWelcome(): void {
  console.log(getBanner());

  const welcome = [
    "",
    chalk.white("  Type") + chalk.green(" help ") + chalk.white("for commands |") + chalk.red(" push ") + chalk.white("for aggressive mode"),
    chalk.white("  RU layout: ") + chalk.magenta("рудз") + chalk.white("=help | ") + chalk.magenta("ысфт") + chalk.white("=scan | ") + chalk.magenta("зышщ") + chalk.white("=push | ") + chalk.magenta("пущ") + chalk.white("=geo"),
    "",
  ].join("\n");

  console.log(
    boxen(welcome, {
      padding: { top: 0, bottom: 0, left: 1, right: 1 },
      borderStyle: "round",
      borderColor: "gray",
      dimBorder: true,
      margin: { top: 0, bottom: 0, left: 0, right: 0 },
    })
  );
  console.log();
}

function getPrompt(): string {
  return chalk.cyan("sac") + chalk.gray("> ");
}

function processInput(input: string): void {
  const trimmed = input.trim();
  if (!trimmed) return;

  let resolvedInput = trimmed;
  if (hasRussian(trimmed.split(/\s+/)[0])) {
    const parts = trimmed.split(/\s+/);
    parts[0] = ruToEn(parts[0]);
    resolvedInput = parts.join(" ");
    log("INFO", `Resolved RU layout: "${chalk.magenta(trimmed.split(/\s+/)[0])}" → "${chalk.green(parts[0])}"`);
  }

  const cmd = resolveCommand(resolvedInput);
  if (cmd) {
    cmd.handler(trimmed.split(/\s+/).slice(1)).catch((err: Error) => {
      log("ERROR", `Command failed: ${err.message}`);
    });
  } else {
    const commandName = resolvedInput.split(/\s+/)[0];
    console.log(chalk.red(`  Unknown command: ${chalk.white(commandName)}`));
    console.log(chalk.gray(`  Type ${chalk.green("help")} for available commands`));
  }
}

function startREPL(): void {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: getPrompt(),
    completer: (line: string): [string[], string] => {
      const allNames = commands.flatMap((c) => [c.name, ...c.alias]);
      const hits = allNames.filter((n) => n.startsWith(line.toLowerCase()));
      return [hits.length ? hits : allNames, line];
    },
  });

  rl.prompt();

  rl.on("line", (line: string) => {
    processInput(line);
    rl.prompt();
  });

  rl.on("close", () => {
    console.log(chalk.magenta("\n  Goodbye! made by .furrieb\n"));
    process.exit(0);
  });

  rl.on("SIGINT", () => {
    console.log(chalk.yellow("\n  Use 'exit' to quit"));
    rl.prompt();
  });
}

function main(): void {
  initLogger();
  printWelcome();
  startREPL();
}

main();
