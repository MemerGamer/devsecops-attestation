# Security Policy

## Supported Versions

This is an MSc thesis research prototype. The current development version
on the `main` branch is the only supported version.

## Reporting a Vulnerability

To report a security vulnerability, please open a GitHub issue with the
title prefixed `[SECURITY]`. For sensitive disclosures, contact the author
directly via the email listed on their GitHub profile.

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact

You can expect an acknowledgement within 48 hours and a resolution timeline
within 7 days for confirmed vulnerabilities.

## Key Material

Never commit private key material. The `keys/` directory and all `*.hex`
files are listed in `.gitignore` for this reason. If key material is
accidentally committed, rotate the keys immediately and treat the old
private key as compromised.
