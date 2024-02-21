#! /usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.YarnAuditCheck = void 0;
const node_child_process_1 = require("node:child_process");
const cli_table_1 = __importDefault(require("cli-table"));
class YarnAuditCheck {
    AUDIT_ADVISORY = "auditAdvisory";
    AUDIT_SUMMARY = "auditSummary";
    NO_PATCH_PATCHED_VERSION = "<0.0.0";
    NO_PATCH_AVAILABLE = "No patch available";
    SEVERITY_LEVELS = [
        "critical",
        "high",
        "moderate",
        "low",
        "info"
    ];
    // If you want to add default packages
    excludePackageList = [];
    constructor(excludePackageList) {
        this.excludePackageList =
            excludePackageList.length === 0
                ? this.excludePackageList
                : excludePackageList;
    }
    showTable(tableRows) {
        const table = new cli_table_1.default({
            style: { head: ["reset"] },
            colAligns: ["left", "left", "left"],
            head: []
        });
        tableRows.forEach((row) => table.push(row));
        console.log(table.toString());
    }
    formatStatus = (status) => {
        // Check if status is either true, false, or warn
        switch (status) {
            case true:
                return "\u001B[32m" /* Colors.FG_GREEN */ + "PASS" + "\u001B[0m" /* Colors.RESET_COLOR */;
            case false:
                return "\u001B[31m" /* Colors.FG_RED */ + "FAIL" + "\u001B[0m" /* Colors.RESET_COLOR */;
            case "warn":
                return "\u001B[33m" /* Colors.FG_YELLOW */ + "WARNING" + "\u001B[0m" /* Colors.RESET_COLOR */;
            default:
                return String(status);
        }
    };
    formatSeverity(severity) {
        let formattedSeverity;
        switch (severity) {
            case "critical":
            case "high":
                formattedSeverity = `${"\u001B[31m" /* Colors.FG_RED */}${severity}${"\u001B[0m" /* Colors.RESET_COLOR */}`;
                break;
            case "moderate":
                formattedSeverity = `${"\u001B[33m" /* Colors.FG_YELLOW */}${severity}${"\u001B[0m" /* Colors.RESET_COLOR */}`;
                break;
            default:
                formattedSeverity = severity;
                break;
        }
        return formattedSeverity;
    }
    // Parse the yarn audit output and exclude packages
    excludeAndDisplayPackageInfo(auditOutput) {
        // filter only auditAdvisories and sort based on severity levels
        const auditAdvisories = auditOutput
            .filter((i) => i.type === this.AUDIT_ADVISORY)
            .sort((a, b) => this.SEVERITY_LEVELS.indexOf(a.data.advisory.severity) -
            this.SEVERITY_LEVELS.indexOf(b.data.advisory.severity));
        const finalAuditPackages = auditAdvisories
            .filter((advisory) => !this.excludePackageList.includes(advisory.data.advisory.module_name))
            .map((advisory) => {
            const patchedIn = advisory.data.advisory.patched_versions.replace(" ", "") ===
                this.NO_PATCH_PATCHED_VERSION
                ? this.NO_PATCH_AVAILABLE
                : advisory.data.advisory.patched_versions;
            const auditPackage = {
                Package: advisory.data.advisory.module_name,
                Severity: advisory.data.advisory.severity,
                Title: advisory.data.advisory.title,
                "Patched In": patchedIn,
                "Dependency of": `${advisory.data.resolution.path.split(">")[0]} ${advisory.data.resolution.dev ? "[dev]" : ""}`,
                Path: advisory.data.resolution.path.split(">").join(" > "),
                "More info": `https://www.npmjs.com/advisories/${advisory.data.resolution.id}`
            };
            // Display table for packages with vulnerabilities
            const tableRows = Object.entries(auditPackage).map(([key, value]) => ({
                [key]: key === "Severity" ? this.formatSeverity(value) : value
            }));
            this.showTable(tableRows);
            return auditPackage;
        });
        const vulnerablePackages = finalAuditPackages.filter((i) => this.SEVERITY_LEVELS.slice(0, 2).includes(i.Severity));
        const pass = vulnerablePackages.length === 0;
        if (this.excludePackageList.length) {
            // eslint-disable-next-line no-console
            console.info(`\n ${this.excludePackageList.length} - Package excluded:`);
            const excludePackagesList = this.excludePackageList.map((value) => ({
                [value]: `${"\u001B[32m" /* Colors.FG_GREEN */} EXCLUDED ${"\u001B[0m" /* Colors.RESET_COLOR */}`
            }));
            this.showTable(excludePackagesList);
        }
        this.printAuditSummary(auditOutput, finalAuditPackages);
        return pass;
    }
    printAuditSummary(auditOutput, finalAuditPackages) {
        // audit summary
        const auditSummary = auditOutput.filter((i) => i.type === this.AUDIT_SUMMARY);
        const stringifyAuditSummary = JSON.stringify(auditSummary[0].data);
        const auditSummaryObject = JSON.parse(stringifyAuditSummary);
        const severity = this.SEVERITY_LEVELS.reduce((acc, level) => ({ ...acc, [level]: 0 }), {});
        const severityInfo = this.SEVERITY_LEVELS.map((level) => ({
            severity: level,
            label: `${level.charAt(0)}${level.slice(1)}`
        }));
        // eslint-disable-next-line no-console
        console.info(`\n${finalAuditPackages.length} vulnerabilities found - Packages audited: ${auditSummaryObject.totalDependencies}`);
        if (finalAuditPackages.length) {
            const severityCounts = finalAuditPackages.reduce((acc, item) => {
                const severity = item.Severity;
                acc[severity]++;
                return acc;
            }, severity);
            const displayedCounts = severityInfo
                .map(({ severity, label }) => severityCounts[severity] > 0
                ? `${severityCounts[severity]} ${label}`
                : null)
                .filter((severity) => severity !== null)
                .join(" | ");
            // eslint-disable-next-line no-console
            console.info(`Severity: ${displayedCounts}`);
        }
    }
    parsingAndFilteringOutput(auditOutput) {
        // Split the output into lines and parse each line as JSON
        const auditLines = auditOutput.trim().split("\n");
        return auditLines.map((line) => JSON.parse(line));
    }
    runYarnAudit() {
        return new Promise((resolve, reject) => {
            const yarnAuditProcess = (0, node_child_process_1.spawn)("yarn", ["audit", "--json"]);
            let auditOutput = "";
            yarnAuditProcess.stdout.on("data", (data) => {
                auditOutput += data.toString();
            });
            yarnAuditProcess.stderr.on("data", (data) => {
                const stringifyError = data.toString();
                if (stringifyError) {
                    const trimAndSplittedArray = stringifyError.trim().split("\n");
                    const auditResult = [];
                    trimAndSplittedArray.forEach((line) => {
                        try {
                            auditResult.push(JSON.parse(line));
                        }
                        catch (error) {
                            /* eslint-disable no-console */
                            console.error("Error parsing JSON:", error.message);
                            console.error("Raw output:", line);
                            /* eslint-enable no-console */
                        }
                    });
                    auditResult.forEach((result) => {
                        // eslint-disable-next-line no-console
                        console.info(`${"\u001B[33m" /* Colors.FG_YELLOW */}${result.type}${"\u001B[0m" /* Colors.RESET_COLOR */} ${result.data}`);
                    });
                }
            });
            yarnAuditProcess.on("close", (code) => {
                // Code '0' indicates there are no vulnerabilities found in project's dependencies
                if (code === 0) {
                    const auditResult = this.parsingAndFilteringOutput(auditOutput);
                    this.printAuditSummary(auditResult, []);
                    resolve(true);
                }
                else if (code === 12) {
                    // Code '12' indicates that there are vulnerabilities found in project's dependencies
                    try {
                        const auditResult = this.parsingAndFilteringOutput(auditOutput);
                        const response = this.excludeAndDisplayPackageInfo(auditResult);
                        resolve(response);
                    }
                    catch (parseError) {
                        // eslint-disable-next-line no-console
                        console.error("Error parsing JSON:", parseError.message);
                        reject(new Error(`Failed to parse JSON. See raw output above.`));
                    }
                }
                else {
                    // eslint-disable-next-line no-console
                    console.error(auditOutput);
                    reject(new Error(`Yarn audit process exited with code ${code}. See output above.`));
                }
            });
        });
    }
}
exports.YarnAuditCheck = YarnAuditCheck;
// Check if command line arguments are provided
if (process.argv.length <= 2) {
    console.log("Usage: yarn run automate-improved-yarn-audit <project-path> <arg1> <arg2> ...");
    process.exit(1); // Exit the script with error code 1
}
// Extract command line arguments (excluding the first two elements which are 'node' and the script file name)
const excludePackages = process.argv.slice(3);
const rootPath = process.argv.slice(2, 3)[0];
process.chdir(rootPath);
// Instantiate and run the class
const yarnAuditCheck = new YarnAuditCheck(excludePackages);
yarnAuditCheck
    .runYarnAudit()
    .then((status) => {
    yarnAuditCheck.showTable([
        { "Yarn Audit Check Status": yarnAuditCheck.formatStatus(status) }
    ]);
    if (!status) {
        process.exit(1);
    }
    process.exit(0);
})
    .catch((error) => {
    console.error(`ERROR: ${error.message}`);
    process.exit(1);
});
