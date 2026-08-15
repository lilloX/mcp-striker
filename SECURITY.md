# Security Policy

## Supported Versions

Security fixes are provided for the latest release line.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub's **Security**
tab by selecting **Report a vulnerability**. Do not disclose security-sensitive
details in a public issue, discussion, or pull request.

Include as much of the following information as possible:

- the affected version and installation method;
- a clear description of the issue and its security impact;
- reproducible steps or a minimal proof of concept;
- relevant logs, traces, or artifacts with secrets redacted;
- any known mitigations or suggested fixes.

You should receive an acknowledgement within 7 days and an initial assessment
within 14 days. Resolution time depends on severity and complexity. Please allow
reasonable time for investigation and remediation before public disclosure.

## Scope

This policy covers vulnerabilities in MCP Striker itself, including issues that
could compromise the machine running it, expose credentials or assessment data,
bypass its safety controls, or produce unsafe behavior beyond the explicitly
requested probes.

The following are outside the scope of this policy:

- vulnerabilities discovered by MCP Striker in an assessed MCP server;
- expected effects of probes explicitly enabled by the operator, including
  operations allowed with `--allow-mutating`;
- vulnerabilities that exist only in third-party targets or dependencies and
  do not arise from MCP Striker's implementation;
- reports based on unauthorized testing of systems you do not own or have
  explicit permission to assess.

For vulnerabilities in a tested MCP server, contact that server's maintainer
through its own security reporting process.

## Safe Research

Good-faith research that follows this policy, avoids privacy violations and
service disruption, and uses only systems you own or are authorized to test is
welcome. Do not access, modify, retain, or disclose third-party data beyond what
is necessary to demonstrate the issue.

Thank you for helping keep MCP Striker and its users secure.
