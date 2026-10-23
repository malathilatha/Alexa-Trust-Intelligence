# Product feedback — Alexa Trust Intelligence



## Amazon Bedrock — Nova Lite (`amazon.nova-lite-v1:0`, us-east-1)
**Worked well:** Fast and cheap enough to call several times per request
(signal extraction, free-text extraction, narration). With a tightly
specified system prompt, its JSON output was reliable. First call worked
right after `aws configure`, with no approval wait.

**Friction:**
- No schema-enforced JSON mode. I hand-wrote parsing with a fallback
  (strip markdown fences, catch `JSONDecodeError`). A "respond only in this
  schema" option would remove that code.
- It sometimes reads soft phrases ("just a routine check") as pressure.
  Useful in one test, but it means wording signals vary slightly.
- The console's old tutorials still describe the retired Model access step.

## Amazon Bedrock — Titan Text Embeddings v2 (`amazon.titan-embed-text-v2:0`)
**Worked well:** Simple to call; 256-dim output keeps storage small.

**Friction:** On short scam messages, paraphrases scored 0.45–0.49 cosine
and unrelated messages 0.09–0.37, so I could not pick a safe threshold. A
documented guide on similarity ranges for short text, or for choosing
dimensions, would have saved me the experiment.

## MCP Python SDK (`mcp` 2.2.0)
**Worked well:** Decorator-based tool registration turns a typed Python
function into a schema'd MCP tool with little boilerplate. Streamable HTTP
client and server both worked locally.

**Friction:** The `WWW-Authenticate` header on 401 cannot be turned off
without bypassing the built-in auth (see `FRICTION_LOG.md`). The
`inputSchema` → `input_schema` rename gave no deprecation warning.

## Alexa+ MCP Toolkit documentation
**Worked well:** The quickstart's requirements (Streamable HTTP, 401
without `WWW-Authenticate`) are specific and testable.

**Friction:** No sandbox or preview access, so the Alexa+ side is
simulated. A self-serve reference client or test harness, like MCP
Inspector but Alexa+-shaped, would let entrants verify onboarding without
full preview enrollment.

## AWS IAM / `aws configure`
**Friction:** A missing credential is easy to miss when the app has a fallback. A one-line "who am I
and can I invoke this model" check in the Bedrock quickstart would help.
