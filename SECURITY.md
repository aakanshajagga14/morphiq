# Security policy

## Supported versions

MorphIQ is currently alpha software. Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Include:

- the affected component and version or commit;
- steps to reproduce the issue;
- the expected and observed security impact; and
- any suggested mitigation, if available.

Please do not open a public issue for an unpatched vulnerability. Allow reasonable time for investigation and remediation before public disclosure.

## Operational guidance

Run MorphIQ with the minimum privileges required for the selected firewall backend. Test new rules with `firewall_backend: mock`, maintain a whitelist for administrative addresses, and keep an independent recovery path in case a firewall rule disrupts access.
