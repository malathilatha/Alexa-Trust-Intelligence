# Friction log — Alexa Trust Intelligence

Real problems hit while building this solo, in the order they mattered.

## MCP SDK (`mcp` 2.2.0)

1. **401 responses always carry `WWW-Authenticate`.** The SDK's built-in
   auth middleware (`RequireAuthMiddleware`) sends that header, but the
   Alexa+ MCP Toolkit quickstart requires it to be absent on an
   unauthenticated request. No setting turns it off. I wrote a small
   Starlette bearer-token middleware in front of `streamable_http_app()`.
   Found only by reading the SDK source; no error message points to it.

2. **`Tool.inputSchema` became `Tool.input_schema`** with no deprecation
   warning. The failure is a bare `AttributeError`, with no hint that the
   attribute was renamed.

3. **Extra packages beyond `mcp`.** The demo bridge needs `starlette`,
   `uvicorn` and `httpx2`; they are listed in `requirements.txt`.

## Amazon Bedrock / AWS

4. **The "Model access" page is retired.** Older tutorials describe
   requesting access and waiting for approval. The console now says the
   page is retired and serverless models auto-enable on first invoke. I
   had to confirm in the console that the step no longer exists. After
   `aws configure` with an IAM access key, `amazon.nova-lite-v1:0` worked
   on the first call.

5. **AWS credentials are easy to forget.** On one run I had not
   configured the AWS secrets. Bedrock has a keyword fallback for wording
   signals, so a missing credential degrades detection instead of failing
   loudly. Check Bedrock explicitly before a demo.

6. **Titan embeddings did not separate paraphrases.** I wired
   `amazon.titan-embed-text-v2:0` (256 dims) into the mass-campaign rule
   with a 0.80 cosine threshold. Real scores: reworded versions of the same
   ask 0.45–0.49, unrelated messages 0.09–0.37. The gap is too thin for a
   safe threshold, so the rule is effectively dormant and word overlap does
   the work. Short messages seem to be the problem; I did not test longer
   ones.

## Alexa+

7. **No Alexa+ developer preview access.** The Alexa+ client is simulated
   by `voice_bridge.py` and `voice_demo.html`. I could not verify the real
   `alexa-ai new mcp` onboarding flow, only follow the public quickstart.

## My own bugs worth recording

8. **Old SQLite file, new column.** I added a `request_text` column to the
   incident log. Anyone with an existing `trust_incidents.db` got
   `sqlite3.OperationalError: no such column: request_text`. Fixed with an
   `ALTER TABLE` migration at startup (`CREATE TABLE IF NOT EXISTS` never
   alters an existing table).

9. **Free text kept returning "More information needed".** The free-text
   path required four fields (sender, device, location, time), so ordinary
   sentences were rejected. Fix: run the check anyway, report missing
   details as "not stated", and add a `missing_context` rule (weight 20)
   so a request with unknown device/location/time can never get a plain
   PROCEED.

10. **Gmail extension is only lightly tested.** One live Gmail account, one
    email (REVIEW 30/100). Gmail's DOM changes often, so the button
    injection may need updating.

11. **Solo, time-boxed build on Windows + OneDrive.** Setup cost time:
    virtual environments, `aws configure`, and keeping the local copy of
    files in sync with edited versions.
