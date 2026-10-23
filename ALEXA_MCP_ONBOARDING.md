# Alexa+ MCP Toolkit onboarding notes

We don't have Alexa+ developer preview access, so this project couldn't run
`alexa-ai new mcp` against a real Alexa+ environment. This document states
what the onboarding would look like, following the publicly documented
MCP Toolkit quickstart, so judges can see we understood the integration
path even without being able to execute it end-to-end.

## Integration approach
Per Amazon's "Choose the proper Alexa+ integration approach" guidance, this
project doesn't fit Alexa+'s predefined categories (it's a cross-cutting
trust/safety layer, not a single-domain skill), so it targets the **MCP
Toolkit** path: Alexa+ acts as the MCP client, consuming this project's
tools and resources directly.

## What the manifest would declare
```
name: trust-intelligence
transport: streamable-http
spec_version: 2025-11-25
endpoint: <public HTTPS URL>/mcp
auth: bearer token (see Authentication below)
tools:
  - check_trust            # payment/invoice/transfer requests
  - check_access_request    # password/MFA/remote-access/login-link requests
  - reconstruct_trust_story # verifies claimed approvals/vendor accounts
  - report_compromise       # post-incident recovery guidance
  - prepare_incident        # drafts an escalation (never submits alone)
  - submit_incident         # requires explicit human authorization
  - start_investigation     # free-text intake, extracts structured fields
```

## Authentication
The deployed server expects `Authorization: Bearer <TRUST_SERVER_API_TOKEN>`
on every request. An unauthenticated or wrongly-authenticated request
receives a `401` with **no** `WWW-Authenticate` header, matching the
quickstart's documented requirement (see `FRICTION_LOG.md` for why this
needed a custom middleware rather than the SDK's built-in auth).

## Testing without preview access
Validated with:
- The standard **MCP Inspector**, as Amazon's docs prescribe, against the
  deployed Streamable HTTP endpoint.
- A standalone Python MCP client (`investigate_client.py`,
  `try_one_request.py`) simulating the same tool-call sequence a real
  Alexa+ client would make.

## Known gap
Since we can't test against real Alexa+ request/response shaping, there
may be differences between what this document describes and what the
actual MCP Toolkit onboarding flow requires once genuine preview access is
available. This is flagged here rather than glossed over.
