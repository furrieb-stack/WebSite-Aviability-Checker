import chalk from "chalk";
import boxen from "boxen";

export function getBanner(): string {
  const title = [
    "",
    chalk.cyan.bold("   ███████╗███████╗██╗  ██╗    ██╗   ██╗███████╗██████╗     "),
    chalk.cyan.bold("   ██╔════╝██╔════╝╚██╗██╔╝    ╚██╗ ██╔╝██╔════╝██╔══██╗    "),
    chalk.cyan.bold("   ███████╗█████╗   ╚███╔╝      ╚████╔╝ ███████╗██████╔╝     "),
    chalk.cyan.bold("   ╚════██║██╔══╝   ██╔██╗       ╚██╔╝  ╚════██║██╔═══╝      "),
    chalk.cyan.bold("   ███████║███████╗██╔╝ ╚██╗      ██║   ███████║██║          "),
    chalk.cyan.bold("   ╚══════╝╚══════╝╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝          "),
    "",
    chalk.gray("   ══════════════════════════════════════════════════════"),
    chalk.white("   Site Availability & Security Checker") + chalk.gray(" v1.0"),
    chalk.magenta.bold("   made by .furrieb"),
    chalk.gray("   ══════════════════════════════════════════════════════"),
    "",
  ].join("\n");

  return boxen(title, {
    padding: { top: 0, bottom: 0, left: 1, right: 1 },
    margin: 0,
    borderStyle: "round",
    borderColor: "cyan",
    dimBorder: false,
  });
}
