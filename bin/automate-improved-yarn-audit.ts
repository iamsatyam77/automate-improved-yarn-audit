#! /usr/bin/env node
import { spawn } from "node:child_process";
import Table from "cli-table";

export type YarnAdvisoryData = {
  advisory: {
    module_name: string;
    severity: string;
    title: string;
    patched_versions: string;
  };
  resolution: {
    path: string;
    dev: boolean;
    id: string;
  };
};

export type YarnAuditData = {
  type: string;
  data: YarnAdvisoryData;
};

export type YarnAuditSummary = {
  vulnerabilities: {
    info: number;
    low: number;
    moderate: number;
    high: number;
    critical: number;
  };
  dependencies: number;
  devDependencies: number;
  optionalDependencies: number;
  totalDependencies: number;
};

const enum Colors {
  FG_RED = "\x1b[31m",
  FG_GREEN = "\x1b[32m",
  FG_YELLOW = "\x1b[33m",
  FG_ORANGE = "\x1b[38;5;208m",
  RESET_COLOR = "\x1b[0m"
}

const table = new Table({
  style: { head: ["reset"] },
  colAligns: ["left", "left", "left"],
  head: []
});

export class YarnAuditCheck {
  private readonly AUDIT_ADVISORY: string = "auditAdvisory";
  private readonly AUDIT_SUMMARY: string = "auditSummary";
  private readonly NO_PATCH_PATCHED_VERSION: string = "<0.0.0";
  private readonly NO_PATCH_AVAILABLE: string = "No patch available";
  private readonly SEVERITY_LEVELS: string[] = [
    "critical",
    "high",
    "moderate",
    "low",
    "info"
  ];
  // If you want to add default packages
  private readonly excludePackageList: string[] = [];

  constructor(excludePackageList: string[]) {
    this.excludePackageList =
      excludePackageList.length === 0
        ? this.excludePackageList
        : excludePackageList;
  }

  private formatSeverity(severity: string): string {
    let formattedSeverity: string;

    switch (severity) {
      case "critical":
      case "high":
        formattedSeverity = `${Colors.FG_RED}${severity}${Colors.RESET_COLOR}`;
        break;
      case "moderate":
        formattedSeverity = `${Colors.FG_YELLOW}${severity}${Colors.RESET_COLOR}`;
        break;
      default:
        formattedSeverity = severity;
        break;
    }

    return formattedSeverity;
  }
  // Parse the yarn audit output and exclude packages
  private excludeAndDisplayPackageInfo(auditOutput: YarnAuditData[]): boolean {
    // filter only auditAdvisories and sort based on severity levels
    const auditAdvisories = auditOutput
      .filter((i) => i.type === this.AUDIT_ADVISORY)
      .sort(
        (a, b) =>
          this.SEVERITY_LEVELS.indexOf(a.data.advisory.severity) -
          this.SEVERITY_LEVELS.indexOf(b.data.advisory.severity)
      );

    const finalAuditPackages = auditAdvisories
      .filter(
        (advisory) =>
          !this.excludePackageList.includes(advisory.data.advisory.module_name)
      )
      .map((advisory) => {
        const patchedIn =
          advisory.data.advisory.patched_versions.replace(" ", "") ===
          this.NO_PATCH_PATCHED_VERSION
            ? this.NO_PATCH_AVAILABLE
            : advisory.data.advisory.patched_versions;

        const auditPackage = {
          Package: advisory.data.advisory.module_name,
          Severity: advisory.data.advisory.severity,
          Title: advisory.data.advisory.title,
          "Patched In": patchedIn,
          "Dependency of": `${advisory.data.resolution.path.split(">")[0]} ${
            advisory.data.resolution.dev ? "[dev]" : ""
          }`,
          Path: advisory.data.resolution.path.split(">").join(" > "),
          "More info": `https://www.npmjs.com/advisories/${advisory.data.resolution.id}`
        };

        // Display table for packages with vulnerabilities
        const tableRows: any[] = [
          ...Object.entries(auditPackage).map(([key, value]) => ({
            [key]: key === "Severity" ? this.formatSeverity(value) : value
          }))
        ];
        table.push(tableRows);

        return auditPackage;
      });

    const vulnerablePackages = finalAuditPackages.filter((i) =>
      this.SEVERITY_LEVELS.slice(0, 2).includes(i.Severity)
    );
    const pass = vulnerablePackages.length === 0;

    if (this.excludePackageList.length) {
      // eslint-disable-next-line no-console
      console.info(`\n ${this.excludePackageList.length} - Package excluded:`);
      const excludePackagesList: any[] = this.excludePackageList.map(
        (value) => ({
          [value]: `${Colors.FG_GREEN} EXCLUDED ${Colors.RESET_COLOR}`
        })
      );
      table.push(excludePackagesList);
    }

    this.printAuditSummary(auditOutput, finalAuditPackages);
    return pass;
  }

  private printAuditSummary(
    auditOutput: YarnAuditData[],
    finalAuditPackages: Record<string, any>[]
  ): void {
    // audit summary
    const auditSummary = auditOutput.filter(
      (i) => i.type === this.AUDIT_SUMMARY
    );
    const stringifyAuditSummary = JSON.stringify(auditSummary[0].data);
    const auditSummaryObject: YarnAuditSummary = JSON.parse(
      stringifyAuditSummary
    ) as YarnAuditSummary;
    const severity = this.SEVERITY_LEVELS.map((level) => ({ [level]: 0 }));
    const severityInfo = this.SEVERITY_LEVELS.map((level) => ({
      severity: level,
      label: `${level.charAt(0)}${level.slice(1)}`
    }));

    // eslint-disable-next-line no-console
    console.info(
      `\n${finalAuditPackages.length} vulnerabilities found - Packages audited: ${auditSummaryObject.totalDependencies}`
    );

    if (finalAuditPackages.length) {
      const severityCounts = finalAuditPackages.reduce((acc, item) => {
        const severity = item.Severity;
        acc[severity] = (acc[severity] || 0) + 1;
        return acc;
      }, severity);

      // Initialize counts for severity levels not present in the data
      this.SEVERITY_LEVELS.forEach((level) => {
        if (!severityCounts[level]) {
          severityCounts[level] = 0;
        }
      });

      const displayedCounts = severityInfo
        .map(({ severity, label }) =>
          severityCounts[severity] > 0
            ? `${severityCounts[severity]} ${label}`
            : null
        )
        .filter((severity) => severity !== null)
        .join(" | ");

      // eslint-disable-next-line no-console
      console.info(`Severity: ${displayedCounts}`);
    }
  }

  private parsingAndFilteringOutput(auditOutput: string): YarnAuditData[] {
    // Split the output into lines and parse each line as JSON
    const auditLines = auditOutput.trim().split("\n");
    return auditLines.map((line) => JSON.parse(line));
  }

  public runYarnAudit(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const yarnAuditProcess = spawn("yarn", ["audit", "--json"]);

      let auditOutput = "";

      yarnAuditProcess.stdout.on("data", (data: Buffer | string) => {
        auditOutput += data.toString();
      });

      yarnAuditProcess.stderr.on("data", (data: Buffer | string) => {
        const stringifyError = data.toString();
        if (stringifyError) {
          const trimAndSplittedArray = stringifyError.trim().split("\n");
          const auditResult: YarnAuditData[] = [];
          trimAndSplittedArray.forEach((line) => {
            try {
              auditResult.push(JSON.parse(line));
            } catch (error) {
              // console.error('Error parsing JSON:', error.message);
              // console.error('Raw output:', line);
            }
          });
          auditResult.forEach((result) => {
            // eslint-disable-next-line no-console
            console.info(
              `${Colors.FG_YELLOW}${result.type}${Colors.RESET_COLOR} ${result.data}`
            );
          });
        }
      });

      yarnAuditProcess.on("close", (code: number) => {
        // Code '0' indicates there are no vulnerabilities found in project's dependencies
        if (code === 0) {
          const auditResult = this.parsingAndFilteringOutput(auditOutput);
          this.printAuditSummary(auditResult, []);
          resolve(true);
        } else if (code === 12) {
          // Code '12' indicates that there are vulnerabilities found in project's dependencies
          try {
            const auditResult = this.parsingAndFilteringOutput(auditOutput);
            const response = this.excludeAndDisplayPackageInfo(auditResult);
            resolve(response);
          } catch (parseError: any) {
            // eslint-disable-next-line no-console
            console.error("Error parsing JSON:", parseError.message);
            reject(new Error(`Failed to parse JSON. See raw output above.`));
          }
        } else {
          // console.error(auditOutput);
          reject(
            new Error(
              `Yarn audit process exited with code ${code}. See output above.`
            )
          );
        }
      });
    });
  }
}

// Check if command line arguments are provided
if (process.argv.length <= 2) {
  console.log("Usage: yarn run automate-improved-yarn-audit <arg1> <arg2> ...");
  process.exit(1); // Exit the script with error code 1
}

// Extract command line arguments (excluding the first two elements which are 'node' and the script file name)
const excludePackages = process.argv.slice(2);

// Instantiate and run the class
const yarnAuditCheck = new YarnAuditCheck(excludePackages);
yarnAuditCheck.runYarnAudit();
