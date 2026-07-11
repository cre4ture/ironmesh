# Security Policy

## Supported Versions

Ironmesh is still experimental. Security fixes land on `main` first, and
backports are limited to the newest published package or release line.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Latest published `1.0.x` release or package line | Yes |
| Older releases, older package lines, and topic branches | No |

## Reporting a Vulnerability

Please do not open public GitHub issues for security reports.

Use one of these private channels:

- Preferred: GitHub Private Vulnerability Reporting for this repository, when
  it is available.
- Fallback: email `creature@creax.de` with the subject `Ironmesh security report`.

Please include:

- the affected component and version, tag, or commit,
- deployment assumptions and relevant configuration,
- reproduction steps or a proof of concept,
- the suspected impact and any suggested mitigations.

## Response Expectations

- Acknowledgement target: within 5 business days.
- Initial triage or status update target: within 14 calendar days.
- Critical actively exploitable issues are prioritized and may receive interim
  mitigation guidance before a full fix is released.
- Fixes are developed on `main` first and backported to the latest supported
  published line when practical.

## Disclosure Process

- Please keep reports private until a fix or mitigation is available and a
  disclosure date has been coordinated.
- After remediation, the project will publish the fix through normal Git
  history and release notes, and will credit the reporter when requested.
- If a report turns out not to be a vulnerability, the maintainer will still
  explain the assessment so the reporter knows why it was closed.
