# Security policy

VCF Enterprise MCP is an **unofficial community project under testing** by Abhishek Rai. It is not a Broadcom or VMware product. It has **not been tested against a real VCF environment**: everything was developed against simulators and Broadcom's published API specifications. Treat it accordingly and do not point it at production.

## Reporting a vulnerability

Please report security problems privately by email to **abhishekaryan2@gmail.com** with the subject "VCF Enterprise MCP security". Include what you found, how to reproduce it, the version or commit, and what you think the impact is. Please do not open a public issue or post details until we have had a chance to fix it.

This is a one-person, best-effort project: expect an acknowledgement within about a week and a fix or a clear answer as time allows. There is no bounty.

Good reports are things like: a way to read a stored password, to bypass the approval or safety-profile checks, to reach a destination the SSRF allowlist should block, to get a lab token accepted in production mode, or to make a tool act outside the caller's role.

## Supported versions

Only the latest commit on the default branch is supported; there are no maintained release lines yet (the current version is a 1.0.0 beta). Fixes land on the default branch.

## What to expect from the design (and what is not covered)

- Passwords are entered on a loopback page or with `vcf-mcp credentials add`, never through the model; stored secrets are encrypted locally or held in your vault.
- Changes need a dry run, a signed plan and a separate human approver; the operator safety profile can only be loosened from a local terminal.
- Lab tokens (`vcf-mcp token mint`) are for labs only and are refused in production mode.
- Not covered: the security of the appliances, your identity provider, the MCP client or the language model, and any behaviour on a real VCF estate, which has not been verified.
