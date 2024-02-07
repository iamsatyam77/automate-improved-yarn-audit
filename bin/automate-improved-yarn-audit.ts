#! /usr/bin/env node
import { spawn, ChildProcessWithoutNullStreams } from "child_process";

/**
 * Represents a package advisory.
 */
interface Advisory {
    moduleName: string;
    advisoryId: string;
}

/**
 * A class for running improved yarn audit.
 */
class ImprovedYarnAuditRunner {
    /**
     * Type for audit advisory.
     */
    private readonly AUDIT_ADVISORY: string = "auditAdvisory";

    /**
     * Value for patched versions when no patch is available.
     */
    private readonly NO_PATCH_PATCHED_VERSION: string = "<0.0.0";

    /**
     * Add a unique object to the array if it does not exist already.
     * @param packagesWithNoPatchAvailable - The array to add the object to.
     * @param advisory - The object to add.
     */
    private addUniqueObject(
        packagesWithNoPatchAvailable: Advisory[],
        advisory: Advisory
    ): void {
        const isDuplicate = packagesWithNoPatchAvailable.some(
            (obj) => obj.moduleName === advisory.moduleName
        );

        if (!isDuplicate) {
            packagesWithNoPatchAvailable.push(advisory);
        }
    }

    /**
     * Find packages with no patch available.
     * @param auditOutput - The output of yarn audit.
     * @returns An array of packages with no patch.
     */
    private findPackagesWithNoPatch(auditOutput: any[]): Advisory[] {
        const packagesWithNoPatch: Advisory[] = [];
        const auditAdvisories = auditOutput.filter(
            (i) => i.type === this.AUDIT_ADVISORY
        );

        auditAdvisories.forEach((element) => {
            if (
                element.data.advisory.patched_versions.replace(" ", "") ===
                this.NO_PATCH_PATCHED_VERSION
            ) {
                const advisory = {
                    moduleName: element.data.advisory.module_name,
                    advisoryId: element.data.advisory.github_advisory_id
                };
                this.addUniqueObject(packagesWithNoPatch, advisory);
            }
        });

        return packagesWithNoPatch;
    }

    /**
     * Parse and filter the yarn audit output.
     * @param auditOutput - The output of yarn audit.
     * @returns A comma-separated string of advisory ids.
     */
    private parsingAndFilteringOutput(auditOutput: string): string {
        const auditLines = auditOutput.trim().split("\n");
        const auditResult = auditLines.map((line) => JSON.parse(line));

        const packagesWithNoPatch = this.findPackagesWithNoPatch(auditResult);

        const advisoryIds = packagesWithNoPatch
            .map((obj) => obj.advisoryId)
            .join(",");
        return advisoryIds;
    }

    /**
     * Run the yarn audit process.
     * @returns A promise that resolves with audit data.
     */
    private async runYarnAudit(): Promise<{
        isAuditProcessCompleted: boolean;
        data: string | null;
    }> {
        return new Promise((resolve, reject) => {
            const yarnAuditProcess: ChildProcessWithoutNullStreams = spawn("yarn", [
                "audit",
                "--json"
            ]);
            let auditOutput = "";

            yarnAuditProcess.stdout.on("data", (data: Buffer) => {
                auditOutput += data.toString();
            });

            yarnAuditProcess.stderr.on("data", (data: Buffer) => {
                console.error(data.toString());
            });

            yarnAuditProcess.on("close", (code: number) => {
                console.info(`Yarn audit process closed with exit code ${code}.`);
                if (code === 0) {
                    console.info(
                        `Yarn audit process exit successfully with output:\n${auditOutput}`
                    );
                    resolve({ isAuditProcessCompleted: true, data: null });
                } else if (code === 12) {
                    try {
                        const advisoryIds = this.parsingAndFilteringOutput(auditOutput);
                        resolve({ isAuditProcessCompleted: false, data: advisoryIds });
                    } catch (error: any) {
                        console.error("Error parsing JSON:", error.message);
                        console.error("Raw output:", auditOutput);
                        reject(new Error(`Failed to parse JSON. See raw output above.`));
                    }
                } else {
                    console.error(auditOutput);
                    reject(
                        new Error(
                            `Yarn audit process exited with code ${code}. See output above.`
                        )
                    );
                }
            });
        });
    }

    /**
     * Run the improved yarn audit.
     * @param advisoryIds - Comma-separated string of advisory ids.
     * @returns A promise that resolves when the audit is complete.
     */
    public async runYarnAuditImproved(advisoryIds: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const improvedYarnAuditProcess: ChildProcessWithoutNullStreams = spawn(
                "yarn",
                ["run", "improved-yarn-audit", "--exclude", advisoryIds]
            );
            let auditOutput = "";

            improvedYarnAuditProcess.stdout.on("data", (data: number) => {
                const chunk = data.toString();
                auditOutput += chunk;
            });

            improvedYarnAuditProcess.stderr.on("data", (data: Buffer) => {
                console.error(data.toString());
            });

            improvedYarnAuditProcess.on("close", (code) => {
                console.info(`Improved yarn audit process closed with code ${code}.`);
                if (code === 0) {
                    console.info(
                        `Improved yarn audit process exit successfully with output:\n${auditOutput}`
                    );
                    resolve();
                } else {
                    console.error(auditOutput);
                    reject(
                        new Error(
                            `Improved yarn audit process exited with code ${code}. See output above.`
                        )
                    );
                }
            });
        });
    }

    /**
     * Run the yarn audit process and the improved yarn audit.
     */
    public async run(): Promise<void> {
        try {
            const { isAuditProcessCompleted, data } = await this.runYarnAudit();
            if (isAuditProcessCompleted) {
                console.info(
                    "\x1b[32m%s\x1b[0m",
                    "Yarn Audit Completed Successfully!!"
                );
            } else {
                await this.runYarnAuditImproved(data!);
                console.info(
                    "\x1b[32m%s\x1b[0m",
                    "Improved Yarn Audit Completed Successfully!!"
                );
            }
        } catch (error: any) {
            console.error("\x1b[31m%s\x1b[0m", error.message);
        }
    }
}

// Instantiate and run the class
const improvedYarnAuditRunner = new ImprovedYarnAuditRunner();
improvedYarnAuditRunner.run();
