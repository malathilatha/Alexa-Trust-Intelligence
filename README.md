# Alexa Trust Intelligence

A trust-verification layer that sits behind Alexa+ and checks requests for
money, access, or credentials for signs of fraud or social engineering
**before** they're acted on — whether Alexa+ is acting on its own behalf
(it can already buy things using a stored payment method) or relaying a
request from someone else.

Built for the Amazon Developer Hackathon — "Build, Ship, Shape" — Alexa+
track.

## The persona

**Amira, a small-business owner/bookkeeper working from home**, uses
Alexa+ to handle day-to-day admin: paying vendors, approving invoices,
managing access. That means anyone trying to scam her business now has a
new channel in — through Alexa+ itself, not just email or phone. This
project is the layer that catches that.

## What it checks

Two different shapes of attack, because they look nothing alike:

- **`check_trust`** — payment, invoice, and transfer requests. Is the
  device/location/timing normal for this person? Is the amount typical? Was
  the approval chain followed? Does the wording use pressure, secrecy, or
  authority tactics? Has this same identity, or this same target, shown up
  before under suspicious circumstances?
- **`check_access_request`** — password, MFA code, remote-access, and
  lookalike-login-link requests. Does the message ask for something a real
  IT team never asks for? Is there an actual open ticket? Does the contact
  channel match the official one on file? Is a linked domain a lookalike?
  Is this a burst of MFA prompts (fatigue attack)?

A third tool, **`reconstruct_trust_story`**, checks what a request *claims*
(an approval that supposedly happened, a vendor's bank account) against
separate trusted records — this is what catches business email compromise
cases that look completely clean on every surface signal and are only
wrong on the bank account itself.

A fourth, **`authorize_autonomous_purchase`**, checks something different
in kind: not a request someone else sent in, but **Alexa+'s own capability
to spend money**. Alexa+ already has a stored payment method and can place
an order on its own — which is exactly why this matters specifically for
Alexa+, not any text-based assistant that can only talk, not act. This
tool is what Alexa+ would call immediately *before* executing an autonomous
purchase; the money doesn't move until it returns `PROCEED`. It checks
whether the instruction itself carries pressure/secrecy language, whether
the merchant has ever been paid before, whether the amount is unusual for
this account, and whether this is a coached retry of an already-held
purchase under a new session.

## Architecture — why the scoring is deterministic, not an LLM's opinion

Every HOLD/REVIEW/PROCEED decision is **fixed, auditable Python arithmetic**
over a table of weighted rule hits — never an LLM guessing. Amazon Bedrock
(Nova Lite) is used only for three things, none of which decide the outcome:

1. **Semantic signal extraction** — reading a request's wording for
   pressure tactics, secrecy requests, claimed authority, and isolation
   language, without matching a fixed keyword list (a paraphrase, a
   different language, or indirect phrasing still counts). Falls back to a
   keyword list if Bedrock is unreachable — degraded detection, not no
   detection.
2. **Free-text entity extraction** — turning a plain-English description
   into structured fields when someone describes a request in their own
   words rather than as separate parameters.
3. **Plain-language narration** — explaining a decision that's already been
   made, in words a person can act on.

This matches current consensus for agent action safety: the AP2 payments
spec requires validation "in deterministic code," and AWS's own AgentCore
Policy is deterministic authorization "outside the agent's code" for
exactly this reason — a probabilistic model should never be the thing that
decides whether money moves.

## The memory rules — what a single request can't see

Four rules specifically require looking across *multiple* requests, not
just one:

- **`repeat_pattern`** — same session, same claimed identity, retried with
  a different device/location after an earlier hold.
- **`repeat_pattern_cross_session` / `repeat_target_access`** — the harder
  version: an attacker who gets held once can simply start a **brand-new
  session** to dodge the earlier flag. These rules look past the current
  session, keyed on the claimed identity (money) or the **targeted person**
  (access — since an attacker's claimed role and contact channel can change
  every attempt, but who they're targeting usually doesn't).
- **`mass_campaign_detected`** — looks across *employees* instead of one
  target: the same pretext sent to several people at once. It compares
  messages by word overlap first and, if that misses, by meaning using
  Amazon Titan text embeddings (cosine similarity) when a match clears a
  configurable threshold. If the embedding call fails, it falls back to word
  overlap only.

The three repeat-pattern rules are specifically covered — and pass live,
against a real deployed server using real Bedrock calls — in
`test_repeat_patterns.py`. The embedding path of `mass_campaign_detected`
is wired up and the Titan call works, but with the default 0.80 threshold it
is effectively dormant: on real Titan output, reworded versions of the same
ask scored about 0.45–0.49 while unrelated messages scored 0.09–0.37, a gap
too thin to set a safe threshold without more data. Word-overlap matching is
what currently drives this rule.

## Hardening against the attack being on the human, not the system

- **Out-of-band verification as the stated action.** On HOLD/REVIEW, the
  system doesn't just say "be careful" — it names the specific action: call
  the person back using a contact method already on file, never one given
  in the request itself. This matches FBI guidance on BEC verification.
- **Approval-fatigue resistance.** `prepare_incident` tracks how many cases
  have been prepared for the same claimed identity in the last hour; from
  the 3rd one on, the prompt itself names the pattern ("this is the Nth
  approval request...") instead of looking like a routine ask. This is the
  agent-era version of MFA-prompt bombing — **OWASP's Top 10 for Agentic
  Applications lists this as ASI09 (Human-Agent Trust Exploitation)**, and
  a recent MCP threat taxonomy names it specifically as **"Fatigue
  Exploitation" (MCP-38)**. The hard gate itself — nothing is ever
  escalated to Finance or IT Security without an explicit, real human
  "yes" — is the mitigation both call for.
- **Credential/MFA-fatigue detection is specifically scoped.** The
  MFA-fatigue rule only fires when the *current* request is itself about an
  MFA/sign-in approval — not as a blanket flag on every unrelated request
  from someone who merely has MFA history on file. (An earlier version had
  this bug; it's fixed and covered in the test suite.)

## Measured accuracy — not just hand-waved

Both scenario suites are labeled and graded, not just eyeballed. I wrote
the scenarios myself, so these are test results, not independent or
production numbers:

- **Money pipeline (`fraud_scenarios.csv`, 32 cases): 32/32 correct, 0
  false positives, 0 false negatives.** Run: `python evaluate_scenarios.py`
- **Access pipeline (`access_scenarios_labeled.csv`, 16 cases): 15/16
  correct, 0 false positives, 0 false negatives.** Run:
  `python evaluate_access_scenarios.py access_scenarios_labeled.csv`
  — the one case scored stricter than labeled (HOLD instead of REVIEW)
  because Bedrock read a minimizing phrase ("it's just a routine check")
  as mild pressure language, which is itself a real manipulation pattern,
  not a false alarm.

`access_scenarios.csv` (no label column) is kept separately as an ad-hoc
test file — point `try_one_request.py` at any scenario you want to try on
the spot, no CSV editing required.

### What that looks like as a business outcome

Pass/fail accuracy is one way to read those numbers; here's the same 48
test cases read as what actually happened to each request — this is
test-suite performance, not real-world production volume:

| | Should PROCEED | Should REVIEW | Should HOLD | Total |
|---|---|---|---|---|
| Money pipeline | 14 | 6 | 12 | 32 |
| Access pipeline | 6 | 3 | 7 | 16 |
| **Combined** | **20** | **9** | **19** | **48** |

Of 48 cases, **20 legitimate requests passed through without friction, 9
were correctly flagged for a second look, and 19 fraudulent or
credential-harvesting attempts were stopped before acting** — the
system's actual decisions matched this expected breakdown on 47 of 48
cases (see the one scored-stricter case above).

## Known limitations — stated honestly, not hidden

- **No real Alexa+ developer preview access.** The "Alexa+ as MCP client"
  relationship is simulated with a standalone Python MCP client
  (`investigate_client.py`, `try_one_request.py`). See
  `ALEXA_MCP_ONBOARDING.md` for what real onboarding would look like.
- **Session/incident memory is SQLite**, which is fine for a single-instance
  demo but won't survive a redeploy or scale to multiple instances — the
  real fix is DynamoDB, which is a named follow-up, not yet built.
- **Detection is hand-weighted rules, not a learned model.** For a
  regulated, explainable decision this is defensible — production BEC
  tools add learned behavioral baselines on top, which is future work here,
  not a replacement for the deterministic layer.

## Future work (not built)

- A learned risk signal (e.g. TabPFN) shown alongside the rule score, never
  replacing it.
- PII redaction before request text is sent to Bedrock; encryption at rest
  for the incident store; a cap on request-text length.
- An explicit relationship graph, treating first-ever contact between a
  claimed sender and a target as a weak, weighted signal.
- Signature checks on vendor payment instructions (C2PA-style provenance or
  digitally signed invoices) as one more rule.
- An optional voice-authenticity signal as one more weighted rule. The
  out-of-band callback already defends against a perfect voice clone because
  it doesn't depend on detecting the fake.
- Embedding similarity needs real data to tune: a first live check showed
  short reworded messages score far below 0.80 with Titan v2, and the gap to
  unrelated messages is small. A larger labeled set of reworded campaigns is
  needed before lowering the threshold.

## Running it

Needs Python 3.11+ and AWS credentials with Bedrock access in `us-east-1`
(`aws configure`). Without them the server still runs and the prepared scenarios
still return correct decisions (the rules are plain Python), but wording
signals fall back to a keyword list, explanations become generic, and
free-text requests can't be parsed. When Bedrock can't be reached, each
result says so in its explanation and tells you to run `aws configure`.

```
pip install -r requirements.txt
python trust_server.py        # MCP server  -> http://127.0.0.1:8000/mcp
python voice_bridge.py        # demo app    -> http://127.0.0.1:8010  (second terminal)
```

Open `http://127.0.0.1:8010` in Chrome. The demo app is the simulated
Alexa+ (no preview access): it calls the real MCP server over Streamable HTTP.

Set `TRUST_SERVER_API_TOKEN` (in both terminals) to require bearer-token
auth; leave it unset for local testing.

Reproduce the test results: `python evaluate_scenarios.py` and
`python evaluate_access_scenarios.py access_scenarios_labeled.csv`.

**Not deployed.** Everything runs locally. There is no public URL, and a
public HTTPS endpoint would be required for real Alexa+ integration.

## Project files

- `trust_server.py` — the MCP server (all 8 tools)
- `voice_bridge.py` + `voice_demo.html` — the simulated Alexa+ web app
  (source for the simulation, as the Alexa+ track requires)
- `chrome_extension/` — experimental Gmail button ("Check with Trust
  Intelligence") that sends an open email to the checkpoint through
  `voice_bridge.py`. Tested once on a live Gmail account; Gmail's page
  layout changes often, so it may break. Load it unpacked in Chrome.
- `*.csv` — fixture data (employees, vendors, approvals, IT tickets, MFA
  events, purchase history) and the labeled test scenarios
- `try_one_request.py` — test any scenario ad hoc, no CSV needed
- `investigate_client.py` — simulates the full Alexa+ decision sequence
  end to end, including the human-approval gate
- `evaluate_scenarios.py` / `evaluate_access_scenarios.py` — graded
  accuracy runs against the labeled suites
- `test_repeat_patterns.py` — checks the cross-session memory rules
- `check_embeddings.py` — measures real Titan similarity scores
- `ALEXA_MCP_ONBOARDING.md` — intended Alexa+ MCP Toolkit onboarding
- `PRODUCT_FEEDBACK.md` / `FRICTION_LOG.md` — hackathon submission docs
- `LICENSE` — MIT

## Human-in-the-loop, always

Nothing is ever escalated to Finance Risk or IT Security without an
explicit, real person saying yes. `prepare_incident` only ever drafts a
case; `submit_incident` requires `authorized=true`, which must come from an
actual human decision — never assumed, never inferred.
