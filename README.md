# Automate Improved Yarn Audit
Automate Improved Yarn Audit is a script that automates the process of running `yarn audit` and `yarn run improved-yarn-audit` commands for checking dependencies vulnerabilities and ignore the vulnerabilities that don't have any new patch available.

GitHub Repo: https://github.com/iamsatyam77/automate-improved-yarn-audit

[![NPM](https://nodei.co/npm/automate-improved-yarn-audit.png)](https://nodei.co/npm/automate-improved-yarn-audit/)

## Introduction
This README provides guidance on bypassing vulnerability checks in "yarn audit" process when no patches are available for reported vulnerabilities. Yarn's yarn audit command checks your project's dependencies for security vulnerabilities against the Node Security Advisories database. In cases where vulnerabilities are identified for which no patches or fixes are available immediately, you may need to consider bypassing these checks to ensure the continued functionality of your project.
Bypassing Vulnerability Checks
1. Review the Vulnerabilities
Before bypassing any vulnerability, thoroughly review the vulnerabilities reported by yarn audit. Understand the severity and potential impact of each vulnerability on your project's security.
2. Assess the Risk
Evaluate the risk associated with the vulnerabilities for which no patches are available. Consider factors such as the likelihood of exploitation and the potential impact on your project.
3. Consider Mitigation Strategies
In situations where no patches are available and the risk is deemed acceptable, consider alternative mitigation strategies to reduce the risk posed by the vulnerabilities. This may include:
Implementing additional security measures within your application code or infrastructure.
Employing runtime protections or monitoring solutions to detect and mitigate potential exploits.
Limiting the exposure of vulnerable components by reducing their usage or restricting access where possible.
4. Implement Audit Exclusions
Yarn allows you to exclude certain vulnerabilities from the audit report by bypassing the vulnerability checks for vulnerabilities with no available patches, follow the steps below:
 
## Usage:
Add the following package to your repo:

```
    yarn add automate-improved-yarn-audit
    yarn run automate-improved-yarn-audit
```

## Conclusion
Bypassing Yarn audit checks for vulnerabilities with no available patches should be approached with caution and used as a temporary measure. It's essential to prioritize security and regularly address vulnerabilities to safeguard your project and its users.
For more information on Yarn audit and bypassing checks, refer to the official documentation.
