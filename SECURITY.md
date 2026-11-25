# Security Policy

## Supported versions

PrismSCA is pre-1.0. Only the latest release receives fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems in PrismSCA itself.

Report privately through GitHub: **Security → Report a vulnerability** on this repository
(<https://github.com/generalwax2018/PrismSCA/security/advisories/new>).

Please include:

- the PrismSCA version (`prismsca --version`), Python version and OS
- what you ran and what happened
- a minimal input (lockfile/manifest) that reproduces it, with any private package names removed

You can expect an acknowledgement within 7 days. Once a fix is released, the advisory will be published with credit to you unless you'd rather stay anonymous.

## Scope

In scope: bugs in PrismSCA that could cause harm when scanning a project, such as code execution from a crafted lockfile, writing outside the requested output path, or a failure that reports a vulnerable package as clean.

Out of scope: vulnerabilities in the projects you scan (that is what the tool reports), and the accuracy of third-party OSV data (report those to the [OSV project](https://github.com/google/osv.dev)).

PrismSCA never executes code from the projects it scans. It only parses lockfiles and manifests.
