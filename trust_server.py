"""Trust Intelligence MCP server.

Run:  python trust_server.py
URL:  http://127.0.0.1:8000/mcp

Needs employees.csv in the same folder, and AWS credentials configured
(aws configure) with Bedrock access to amazon.nova-lite-v1:0 in us-east-1.

Step 1 (done): Python calculates risk_score/decision deterministically.
Step 5 (done): every HOLD/REVIEW result includes a safe_resolution.
Step 2 (done): start_investigation(freeform_text) extracts what it can
from a plain-English description and asks for what's missing.
Fixes in this version: claimed_sender resolves by role ("CFO") as well
as exact name; device extraction can't be satisfied by just the
communication channel ("text"/"call"/"email").

Latest additions:
- The urgency/manipulation rule no longer matches a fixed keyword list.
  classify_manipulation_signals() asks Bedrock to read the request for
  pressure tactics, secrecy requests, claimed authority, and isolation
  language - any phrasing, any language - and returns structured signals
  that feed into the same deterministic scoring table as every other rule.
  Falls back to the old keyword list if Bedrock is unreachable.
- An 8th rule, repeat_pattern, gives the system memory across requests
  within one caller's session (see session_id on check_trust): the same
  claimed sender retrying with a different device/location after an
  earlier HOLD/REVIEW in that session is a real signal a single-message
  snapshot can never see on its own.
"""
import csv
import json
import os
import sqlite3
from datetime import datetime, timedelta

import boto3
from mcp.server.mcpserver import MCPServer  # mcp<2: from mcp.server.fastmcp import FastMCP

mcp = MCPServer("trust-intelligence")

AMOUNT_MULTIPLIER = 3.0
URGENCY_WORDS = [
    "immediately", "urgent", "asap", "right away", "before end of day",
    "do not discuss", "confidential", "emergency", "today only", "act now",
]
BENEFICIARY_WORDS = ["new iban", "new account", "update the account", "update the payout",
                     "change the beneficiary", "beneficiary details", "new bank account",
                     "payout account"]
TRAVEL_HINTS = ["travels", "approved trip", "approved travel"]

RULE_WEIGHTS = {
    "device": 20, "location": 20, "time": 15, "amount": 20,
    "approval": 25, "urgency": 10, "beneficiary_change": 20,
    "sender_ambiguous": 20, "repeat_pattern": 20,
    # A free-text description that leaves out the device, location or time can't be
    # checked against the person's normal pattern. It never gets an automatic
    # PROCEED: weight equals the REVIEW threshold, so it lands on REVIEW at least.
    "missing_context": 20,
    # Weighted slightly higher than repeat_pattern: this is the harder
    # variant to catch, since it requires looking PAST the session the
    # attacker is currently using, not just within it.
    "repeat_pattern_cross_session": 25,
}
HIGH_THRESHOLD = 40  # lowered from 50 after the 15-scenario evaluation: scenario #9
                      # (credential phishing, no amount involved) scored 45 and was
                      # the only case in the 40-49 range — every other real score was
                      # either well below 40 or well above 50, so this fixes #9 with
                      # no effect on any other tested case
MED_THRESHOLD = 20

BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"
BEDROCK_REGION = "us-east-1"
bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)


def _load_employees():
    with open("employees.csv", newline="") as f:
        return {row["name"]: row for row in csv.DictReader(f)}


def _load_vendor_accounts():
    with open("vendor_accounts.csv", newline="") as f:
        return {row["vendor_name"]: row for row in csv.DictReader(f)}


def _load_approval_records():
    with open("approval_records.csv", newline="") as f:
        records = {}
        for row in csv.DictReader(f):
            records.setdefault(row["reference_id"], []).append(row)
        return records


EMPLOYEES = _load_employees()
VENDOR_ACCOUNTS = _load_vendor_accounts()
APPROVAL_RECORDS = _load_approval_records()

# Maps role (lowercase) -> list of names with that role, so "the CFO" or
# "CFO" resolves to the actual person even when a name isn't given.
ROLE_INDEX = {}
for _name, _row in EMPLOYEES.items():
    _role = _row.get("role", "").strip().lower()
    if _role:
        ROLE_INDEX.setdefault(_role, []).append(_name)


def resolve_employee(claimed_sender):
    """Return (employee_row_or_None, resolved_name, ambiguous: bool).
    Tries an exact name match first, then falls back to a role match
    (e.g. "CFO" or "the CFO") if the name alone isn't in employees.csv.
    """
    if claimed_sender in EMPLOYEES:
        return EMPLOYEES[claimed_sender], claimed_sender, False

    role_key = claimed_sender.strip().lower()
    for prefix in ("the ", "our "):
        if role_key.startswith(prefix):
            role_key = role_key[len(prefix):]
    matches = ROLE_INDEX.get(role_key, [])

    if len(matches) == 1:
        return EMPLOYEES[matches[0]], matches[0], False
    if len(matches) > 1:
        return None, claimed_sender, True  # ambiguous — more than one person has this role
    return None, claimed_sender, False  # no match at all


# ---------- the 7 rules ----------

NOT_STATED = "not stated"


def _not_stated(value):
    return str(value).strip().lower() == NOT_STATED


def rule_device(device, emp):
    if _not_stated(device):
        return False, ""  # covered by the missing_context rule instead
    normal = emp["normal_device"] if emp else ""
    if "Unknown" in device or "Unregistered" in device:
        return True, f"Device '{device}' is not a registered device"
    if emp and device not in normal:
        return True, f"Device '{device}' does not match usual device '{normal}'"
    return False, ""


def rule_location(location, emp):
    if _not_stated(location):
        return False, ""  # covered by the missing_context rule instead
    normal = emp["normal_location"] if emp else ""
    if "not on file" in location.lower() or "unknown" in location.lower():
        return True, f"Location '{location}' is not on file for this person"
    if emp and location.split()[0] not in normal:
        if any(hint in normal.lower() for hint in TRAVEL_HINTS):
            return False, ""
        return True, f"Location '{location}' does not match usual location '{normal}'"
    return False, ""


def rule_time(time_str, emp):
    try:
        t = datetime.strptime(time_str, "%H:%M").time()
    except ValueError:
        return False, ""
    if not emp or not emp.get("normal_hours") or emp["normal_hours"] == "N/A":
        return (t.hour < 6 or t.hour >= 22), "Off-hours request, no profile to compare"
    start_s, end_s = emp["normal_hours"].split("-")
    start, end = datetime.strptime(start_s, "%H:%M").time(), datetime.strptime(end_s, "%H:%M").time()
    if not (start <= t <= end):
        return True, f"Request at {time_str} is outside normal hours {emp['normal_hours']}"
    return False, ""


def rule_amount(amount, emp):
    if amount == 0 or not emp or not emp.get("avg_transaction_aed"):
        return False, ""
    avg = float(emp["avg_transaction_aed"])
    if avg > 0 and amount > AMOUNT_MULTIPLIER * avg:
        return True, f"Amount {amount:.0f} AED is {amount/avg:.1f}x this person's average ({avg:.0f})"
    return False, ""


def rule_approval(approval_chain):
    chain = approval_chain.lower()
    if "skip" in chain or "bypass" in chain:
        return True, f"Approval step was skipped or bypassed: '{approval_chain}'"
    return False, ""


MANIPULATION_PROMPT = """You analyze a short business request message for social-
engineering / manipulation tactics commonly used in business email compromise and
CEO-fraud scams. You do NOT decide whether the request is fraudulent overall -
that is decided separately, by rules, from several inputs including your output.
You only report which tactics are present in how the message is WORDED, however
it is phrased - do not rely on a fixed list of trigger words; a paraphrase, a
different language, or indirect phrasing that conveys the same tactic still
counts.

Reply with ONLY JSON in this exact shape:
{"pressure_tactics_score": <integer 0-10, how strongly the wording pressures for
   immediate action - 0 if there is no such pressure>,
 "secrecy_requested": <true/false - does it ask the recipient to keep this
   confidential, not discuss it with others, or otherwise hide it>,
 "authority_claimed": <true/false - does it lean on a senior title or claimed
   authority to compel compliance rather than on the merits of the request>,
 "isolation_language": <true/false - does it discourage or try to prevent the
   recipient from checking with anyone else before acting>,
 "reasoning": "<one short phrase, for a human reading a log>"}
"""


def classify_manipulation_signals(request_text):
    """Reads the request text for manipulation tactics the way a person would -
    by understanding what it's doing, not by matching a fixed word list. This
    replaces the old keyword-list urgency check: a scam written as "kindly
    process this before you leave today, let's keep it between us" trips this
    the same way "URGENT, confidential" would, because both texts enact the
    same tactics once Nova actually reads them for meaning.

    If Bedrock can't be reached or returns something unparseable, falls back
    to the original keyword list rather than silently skipping the check -
    degraded detection, not no detection."""
    try:
        response = bedrock.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": MANIPULATION_PROMPT}],
            messages=[{"role": "user", "content": [{"text": request_text}]}],
            inferenceConfig={"maxTokens": 200, "temperature": 0.0},
        )
        raw = response["output"]["message"]["content"][0]["text"].strip()
        if raw.startswith("```"):
            raw = raw.strip("`").removeprefix("json").strip()
        result = json.loads(raw)
        return {
            "pressure_tactics_score": int(result.get("pressure_tactics_score", 0)),
            "secrecy_requested": bool(result.get("secrecy_requested", False)),
            "authority_claimed": bool(result.get("authority_claimed", False)),
            "isolation_language": bool(result.get("isolation_language", False)),
            "reasoning": result.get("reasoning", ""),
            "source": "bedrock_semantic",
        }
    except Exception:
        hits = [w for w in URGENCY_WORDS if w in request_text.lower()]
        secrecy_hit = any(w in request_text.lower() for w in
                           ("confidential", "do not discuss", "keep this between us", "don't discuss"))
        return {
            "pressure_tactics_score": 10 if hits else 0,
            "secrecy_requested": secrecy_hit,
            "authority_claimed": False,
            "isolation_language": False,
            "reasoning": (f"fallback keyword match: {', '.join(hits)}" if hits
                          else "fallback: no keywords matched, Bedrock unreachable"),
            "source": "keyword_fallback",
        }


def rule_urgency(signals):
    reasons = []
    if signals["pressure_tactics_score"] >= 5:
        reasons.append(f"pressure/urgency tactics detected (score {signals['pressure_tactics_score']}/10)")
    if signals["secrecy_requested"]:
        reasons.append("asks the recipient to keep this confidential or not discuss it")
    if signals["authority_claimed"]:
        reasons.append("leans on a claimed senior title/authority rather than the merits of the request")
    if signals["isolation_language"]:
        reasons.append("discourages checking with anyone else before acting")
    return (bool(reasons), "; ".join(reasons))


def rule_beneficiary_change(text, approval_chain):
    text_l, chain_l = text.lower(), approval_chain.lower()
    hit = any(w in text_l for w in BENEFICIARY_WORDS)
    if hit and ("no approval" in chain_l or "no formal approval" in chain_l):
        return True, "Bank/beneficiary detail change requested with no verification step on file"
    if hit:
        return True, "Bank/beneficiary detail change requested — verify through a second channel"
    return False, ""


def rule_repeat_pattern(session_id, claimed_sender, device, location, lookback_hours=24):
    """Looks at whether THIS claimed sender has made other requests earlier in
    the SAME session within the lookback window - and if so, whether any of
    them were held/reviewed and this one shows up with a changed device or
    location. That pattern (same name, refused once, back with a different
    story) is a real social-engineering signal that a single-message snapshot
    can never see.

    Scoped to session_id on purpose: with no session_id given (the default),
    this check is skipped entirely, so unrelated one-off requests - like two
    different test scenarios that happen to name the same person - never
    contaminate each other. A real client (Alexa+, or investigate_client.py)
    passes a stable session_id for one ongoing conversation/caller so the
    real pattern can be seen."""
    if not session_id:
        return False, ""
    con = sqlite3.connect(INCIDENT_DB)
    cutoff = (datetime.now() - timedelta(hours=lookback_hours)).isoformat()
    rows = con.execute(
        "SELECT device, location, decision FROM request_log "
        "WHERE session_id = ? AND claimed_sender = ? AND created_at >= ?",
        (session_id, claimed_sender, cutoff),
    ).fetchall()
    con.close()
    if not rows:
        return False, ""

    prior_held_or_reviewed = any(dec in ("HOLD", "REVIEW") for _, _, dec in rows)
    seen_combos = {(d, l) for d, l, _ in rows}
    changed_detail = (device, location) not in seen_combos

    if prior_held_or_reviewed and changed_detail:
        return True, (f"'{claimed_sender}' made {len(rows)} earlier request(s) in this session "
                       f"(at least one HOLD/REVIEW), now retrying with a different device/location")
    if len(rows) >= 2:
        return True, (f"'{claimed_sender}' has made {len(rows) + 1} requests in this session "
                       f"within {lookback_hours}h — unusually frequent")
    return False, ""


def rule_repeat_target(session_id, claimed_sender, device, location, lookback_hours=24):
    """Closes the obvious hole in rule_repeat_pattern: an attacker who gets
    held once can simply start a brand-new session_id and retry, and the
    same-session rule above has no way to see them since it only looks
    inside one session. This rule deliberately does NOT filter by session_id
    when querying history — it looks at every request logged for this same
    claimed identity across ALL sessions in the lookback window, which is
    exactly what catches a deliberate new-session retry.

    Still gated on THIS call's session_id being non-blank, for the same
    reason as rule_repeat_pattern: a one-off, standalone check (session_id
    left blank, e.g. batch-evaluating unrelated test scenarios) must never
    be cross-contaminated just because two unrelated scenarios happen to
    name the same person. A real caller (Alexa+, or any real client) always
    passes a session_id for an actual ongoing interaction, even a brand-new
    one — so this still activates exactly when it should."""
    if not session_id:
        return False, ""
    con = sqlite3.connect(INCIDENT_DB)
    cutoff = (datetime.now() - timedelta(hours=lookback_hours)).isoformat()
    rows = con.execute(
        "SELECT session_id, device, location, decision FROM request_log "
        "WHERE claimed_sender = ? AND created_at >= ? AND session_id != ?",
        (claimed_sender, cutoff, session_id),
    ).fetchall()
    con.close()
    if not rows:
        return False, ""

    prior_held_or_reviewed = any(dec in ("HOLD", "REVIEW") for _, _, _, dec in rows)
    seen_combos = {(d, l) for _, d, l, _ in rows}
    changed_detail = (device, location) not in seen_combos
    other_sessions = {s for s, _, _, _ in rows}

    if prior_held_or_reviewed and changed_detail:
        return True, (f"'{claimed_sender}' was held/reviewed under a different session "
                       f"({len(other_sessions)} other session(s) in the last {lookback_hours}h) and is "
                       f"now retrying here with a different device/location — looks like a deliberate "
                       f"new-session retry to dodge the earlier hold, not a coincidence")
    return False, ""


def run_rules(request_text, claimed_sender, device, location, time, amount_aed, approval_chain,
              session_id=""):
    emp, resolved_name, ambiguous = resolve_employee(claimed_sender)
    signals = classify_manipulation_signals(request_text)
    fired = []
    if ambiguous:
        fired.append({
            "rule": "sender_ambiguous",
            "reason": f"'{claimed_sender}' matches more than one person — a specific name is needed to verify this request",
            "weight": RULE_WEIGHTS["sender_ambiguous"],
        })
    for name, ok_reason in [
        ("device", rule_device(device, emp)),
        ("location", rule_location(location, emp)),
        ("time", rule_time(time, emp)),
        ("amount", rule_amount(amount_aed, emp)),
        ("approval", rule_approval(approval_chain)),
        ("urgency", rule_urgency(signals)),
        ("beneficiary_change", rule_beneficiary_change(request_text, approval_chain)),
        ("repeat_pattern", rule_repeat_pattern(session_id, claimed_sender, device, location)),
        ("repeat_pattern_cross_session", rule_repeat_target(session_id, claimed_sender, device, location)),
    ]:
        ok, reason = ok_reason
        if ok:
            fired.append({"rule": name, "reason": reason, "weight": RULE_WEIGHTS[name]})
    # Details the person didn't give can't be verified, so say so plainly
    # instead of silently passing or failing the request.
    missing = [label for label, value in (("device", device), ("location", location),
                                           ("time", time)) if _not_stated(value)]
    if missing:
        fired.append({
            "rule": "missing_context",
            "reason": f"Not provided: {', '.join(missing)}. Without them this request can't be checked against the person's normal pattern",
            "weight": RULE_WEIGHTS["missing_context"],
        })
    return emp, fired, signals


def _build_card(decision, risk_score, risk_level, fired_rules, safe_resolution, subtitle=""):
    """A small structured block alongside the prose explanation, meant for a
    screen device (Echo Show-style) via the MCP Apps extension — the voice
    response stays the spoken_summary, this is what a screen would show at
    the same time: the decision, the score, the top reasons (never all of
    them — a screen glance needs 2-3, not a full audit log), and the one
    concrete action to take. Nova never sees or builds this — it's assembled
    directly from the same deterministic fields everything else uses."""
    top_reasons = [r["reason"] for r in sorted(fired_rules, key=lambda r: -r["weight"])[:3]]
    return {
        "type": "trust_decision_card",
        "title": f"{decision} — risk {risk_score}/100",
        "risk_level": risk_level,
        "subtitle": subtitle,
        "top_reasons": top_reasons,
        "action": safe_resolution,
    }


def score_deterministically(fired_rules):
    risk_score = min(100, sum(r["weight"] for r in fired_rules))
    trust_score = 100 - risk_score
    if risk_score >= HIGH_THRESHOLD:
        risk_level, decision = "HIGH", "HOLD"
    elif risk_score >= MED_THRESHOLD:
        risk_level, decision = "MEDIUM", "REVIEW"
    else:
        risk_level, decision = "LOW", "PROCEED"
    return {"risk_score": risk_score, "trust_score": trust_score,
            "risk_level": risk_level, "decision": decision}


# ---------- explanation (Nova explains, never scores) ----------

SYSTEM_PROMPT = """You write the human-facing explanation for a trust-verification
decision that has ALREADY been made by deterministic rules. You do NOT decide
the score, risk_level, or decision — they are given to you as fixed facts.
Use the exact decision word (PROCEED, REVIEW, or HOLD) in your spoken_summary,
do not substitute a different word like "on hold" for REVIEW.

Reply with ONLY a JSON object, no other text, in this exact shape:
{"explanation": "<one or two sentences, plain language, for a person to read>",
 "spoken_summary": "<the decision word plus the single most important reason, max 2 short sentences, written to be read aloud>",
 "missing_requirements": ["<short requirement>", ...],
 "safe_resolution": "<one sentence on what to do next; empty string if decision is PROCEED>"}
"""


def explain_with_bedrock(request_text, claimed_sender, emp, fired_rules, scoring):
    user_payload = {
        "request_text": request_text, "claimed_sender": claimed_sender,
        "known_profile": emp is not None,
        "rules_fired": [{"rule": r["rule"], "reason": r["reason"]} for r in fired_rules],
        "risk_score": scoring["risk_score"], "risk_level": scoring["risk_level"],
        "decision": scoring["decision"],
    }
    try:
        response = bedrock.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": [{"text": json.dumps(user_payload)}]}],
            inferenceConfig={"maxTokens": 400, "temperature": 0.2},
        )
        raw = response["output"]["message"]["content"][0]["text"].strip()
        if raw.startswith("```"):
            raw = raw.strip("`").removeprefix("json").strip()
        return json.loads(raw)
    except Exception:
        # Bedrock unreachable, no AWS credentials, or unusable reply. The decision
        # itself is already made by the rules, so only the wording degrades.
        return {
            "explanation": f"{scoring['decision']} ({scoring['risk_level']} risk, score {scoring['risk_score']}). NOTE: "
                           "AWS Bedrock is unavailable (no AWS credentials or no access), so this is the built-in wording. "
                           "Run `aws configure` with Bedrock access in us-east-1 for full explanations.",
            "spoken_summary": f"{scoring['decision']}. Risk score {scoring['risk_score']} out of 100.",
            "missing_requirements": [],
            "safe_resolution": "Review manually. Note: AWS Bedrock is unavailable, so explanations are generic.",
            "bedrock_status": "unavailable",
        }


# ---------- Step 2: extract details from free text ----------

EXTRACT_PROMPT = """You extract structured facts from a free-text description an
employee gives about an unusual or suspicious business request they received.
Extract ONLY what is explicitly stated or very strongly implied. Never guess
or invent a value — if it isn't there, leave it null.

Fields:
- claimed_sender: the name of the person the request claims to be from
- device: the SPECIFIC device or number used — e.g. "her registered laptop",
  "an unrecognized number", "a new phone not on file". Do NOT use the
  communication channel (text, call, email, WhatsApp) as the device value —
  those describe how the message arrived, not what device sent it. If only
  the channel is mentioned and no specific device detail is given, leave
  device null.
- location: any location mentioned
- time: time of the request in 24-hour HH:MM format, only if explicitly stated
- amount_aed: numeric amount in AED if a number is given (convert only if the
  currency is explicit or obviously implied; otherwise null)
- approval_chain: any mention of approval being followed, skipped, or bypassed

For every field you could NOT extract, add an entry to missing_evidence with:
- field: the field name
- priority: 1 (critical — needed before any assessment is meaningful),
            2 (important), or 3 (nice to have)
- question: a short, natural follow-up question to ask the employee

device, location, and time are priority 1 if missing (the rules can't run
without them). claimed_sender is priority 1 if missing. amount_aed is
priority 2. approval_chain is priority 3 (default to "unknown" if absent,
not worth a follow-up question on its own).

Reply with ONLY JSON, no other text:
{"extracted": {"claimed_sender": null|"...", "device": null|"...", "location": null|"...",
                "time": null|"HH:MM", "amount_aed": null|<number>, "approval_chain": null|"..."},
 "missing_evidence": [{"field": "...", "priority": 1, "question": "..."}]}
"""


@mcp.tool()
def start_investigation(freeform_text: str) -> dict:
    """Start here when someone describes a request in their own words, not as
    separate fields — e.g. 'The CFO just texted asking me to wire 5 million,
    seemed urgent.' Extracts whatever details are present and returns
    missing_evidence (with a follow-up question per gap) for what's still
    needed. Once claimed_sender, device, location, and time are all known,
    call check_trust with the full details."""
    try:
        response = bedrock.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": EXTRACT_PROMPT}],
            messages=[{"role": "user", "content": [{"text": freeform_text}]}],
            inferenceConfig={"maxTokens": 400, "temperature": 0.0},
        )
        raw = response["output"]["message"]["content"][0]["text"].strip()
        if raw.startswith("```"):
            raw = raw.strip("`").removeprefix("json").strip()
        result = json.loads(raw)
    except Exception:
        return {
            "extracted": {},
            "missing_evidence": [{"field": "all", "priority": 1,
                                   "question": "I couldn't process that free-text request. This needs AWS Bedrock: run `aws configure` with Bedrock access in us-east-1, or use the prepared scenarios."}],
            "ready_for_check_trust": False,
        }

    extracted = result.get("extracted", {})
    missing = result.get("missing_evidence", [])

    # Safety net: never leave a field in missing_evidence if it already has
    # a real extracted value — regardless of what the model's own JSON said.
    # This also catches near-useless values like a bare "text"/"call"/"email"
    # being mistaken for a device.
    NON_ANSWERS = {"text", "call", "email", "whatsapp", "message", "phone call"}

    def _has_real_value(field, value):
        if value is None or value == "":
            return False
        if field == "device" and str(value).strip().lower() in NON_ANSWERS:
            return False
        return True

    missing = [m for m in missing if not _has_real_value(m.get("field"), extracted.get(m.get("field")))]

    # Readiness is decided here, in code, against a fixed list of fields the
    # rules genuinely cannot run without — NOT by trusting whatever priority
    # number the model assigned this time. The model's priority labels are
    # still used for how the questions are presented, but never for this gate.
    ALWAYS_CRITICAL = {"claimed_sender", "device", "location", "time"}
    still_missing_critical = [
        f for f in ALWAYS_CRITICAL if not _has_real_value(f, extracted.get(f))
    ]

    return {
        "extracted": extracted,
        "missing_evidence": missing,
        "ready_for_check_trust": len(still_missing_critical) == 0,
    }


@mcp.tool()
def check_trust(
    request_text: str,
    claimed_sender: str,
    device: str,
    location: str,
    time: str,
    amount_aed: float = 0,
    approval_chain: str = "",
    session_id: str = "",
) -> dict:
    """Check whether a business request (payment, invoice change, credential ask)
    should be trusted. Runs 9 rules and scores the result deterministically in
    Python (same input always gives the same score for a given history), then
    uses Bedrock to explain the decision in plain language and describe a safe
    path forward if the request is held or needs review. One of the 9 rules
    (urgency/manipulation) itself uses Bedrock to understand the wording's
    intent rather than matching fixed trigger words, but the score it
    contributes and the final decision are still fixed, deterministic
    arithmetic over that rule's output - the AI never decides the outcome.

    session_id is optional: pass a stable id for one ongoing caller/conversation
    to let two different repeat-pattern rules catch someone retrying the same
    claim with a different device/location — one checks within this same
    session, the other checks across every OTHER session for the same claimed
    identity, so starting a brand-new session to dodge an earlier hold doesn't
    work either. Leave session_id blank for a one-off, standalone check (e.g.
    batch-evaluating unrelated test scenarios) so they can't cross-contaminate.

    If you only have a free-text description and not these separate fields,
    call start_investigation first."""
    emp, resolved_name, ambiguous = resolve_employee(claimed_sender)
    _, fired, signals = run_rules(request_text, claimed_sender, device, location, time,
                                   amount_aed, approval_chain, session_id)
    scoring = score_deterministically(fired)
    _log_request(session_id, claimed_sender, resolved_name, device, location,
                  scoring["decision"], scoring["risk_score"])
    explanation = explain_with_bedrock(request_text, claimed_sender, emp, fired, scoring)

    # On HOLD/REVIEW, give a concrete, FBI-BEC-guidance-aligned action rather
    # than leaning only on Nova's more general safe_resolution text: verify
    # out-of-band, using a contact method already on file for this person —
    # never a number or channel supplied inside the request being checked.
    # This is the same principle real BEC defenses use: a compromised vendor
    # or executive account passes every authentication check there is, so
    # the only reliable check left is calling the person back on a channel
    # the request itself didn't give you.
    safe_resolution = explanation.get("safe_resolution", "")
    if scoring["decision"] in ("HOLD", "REVIEW"):
        who = resolved_name if emp else claimed_sender
        safe_resolution = (
            f"Don't act on this yet. Call or message {who} back using a contact method "
            f"already on file for them — not any number, email, or channel given in this "
            f"request — and confirm the request before doing anything else."
        )

    return {
        "claimed_sender": claimed_sender,
        "resolved_to": resolved_name,
        "known_profile": emp is not None,
        "manipulation_signals": signals,
        "rules_fired": [{"rule": r["rule"], "reason": r["reason"]} for r in fired],
        "rules_fired_count": len(fired),
        "risk_score": scoring["risk_score"],
        "trust_score": scoring["trust_score"],
        "risk_level": scoring["risk_level"],
        "decision": scoring["decision"],
        "explanation": explanation.get("explanation"),
        "spoken_summary": explanation.get("spoken_summary"),
        "missing_requirements": explanation.get("missing_requirements", []),
        "safe_resolution": safe_resolution,
        "card": _build_card(scoring["decision"], scoring["risk_score"], scoring["risk_level"],
                             fired, safe_resolution, subtitle=f"Request from {claimed_sender}"),
    }


# ---------- Phase 2b: authorize_autonomous_purchase ----------
# Every tool above checks a request someone ELSE is sending in. This one is
# different on purpose: Alexa+ already has a stored payment method and can
# place an order or pay a bill on its own, without a human typing a card
# number each time. That's a real capability most consumer AI assistants
# don't have at the smart-speaker level - and it's exactly why it needs a
# gate. This tool is what Alexa+ would call immediately BEFORE it executes
# an autonomous purchase with the card already on file, not after - the
# whole point is that the money never moves until this returns PROCEED.

AUTONOMOUS_ACTION_WEIGHTS = {
    # Pressure/urgency in the instruction itself is the strongest signal
    # here - a legitimate "reorder the usual printer paper" has none of it.
    "pressured_instruction": 35,
    # A merchant never seen before, for an account that already has a
    # purchase history, is a bigger flag here than it would be for a brand
    # new account - the owner has an established pattern to compare against.
    "unfamiliar_merchant": 30,
    "unusual_purchase_amount": 35,
    # Same shape as repeat_pattern_cross_session: someone coaching the
    # account owner to retry ("just say yes this time") after an earlier
    # block, under a fresh session so it doesn't look like a retry.
    "repeat_after_hold": 25,
}


def _load_purchase_history():
    with open("purchase_history.csv", newline="") as f:
        records = {}
        for row in csv.DictReader(f):
            records.setdefault(row["account_owner"], []).append(row)
        return records


PURCHASE_HISTORY = _load_purchase_history()


def rule_pressured_instruction(instruction_text):
    """Reuses the same manipulation-signal classifier as check_trust's
    urgency rule, applied to what Alexa+ was just told to do rather than to
    an inbound message - a scammer coaching someone live on a call ("tell it
    to buy this now, don't mention it to anyone") leaves the same linguistic
    fingerprint as a phishing email does."""
    signals = classify_manipulation_signals(instruction_text)
    if signals["pressure_tactics_score"] >= 5 or signals["secrecy_requested"] or signals["isolation_language"]:
        return True, ("The instruction itself carries pressure or secrecy language "
                       "('right now', 'don't tell anyone') - exactly the pattern used to "
                       "rush a purchase through before anyone can question it")
    return False, ""


def rule_unfamiliar_merchant(account_owner, merchant):
    history = PURCHASE_HISTORY.get(account_owner, [])
    if not history:
        return False, ""  # no history to compare against - nothing to flag on this signal
    known_merchants = {h["merchant"].strip().lower() for h in history}
    if merchant.strip().lower() not in known_merchants:
        return True, (f"'{merchant}' has never been purchased from before on this account - "
                       f"every prior autonomous purchase went to a different, already-known merchant")
    return False, ""


def rule_unusual_purchase_amount(account_owner, amount_aed, multiplier=3):
    history = PURCHASE_HISTORY.get(account_owner, [])
    if not history:
        threshold = 5000  # flat fallback for an account with no purchase history yet
    else:
        amounts = [float(h["amount_aed"]) for h in history]
        threshold = (sum(amounts) / len(amounts)) * multiplier
    if amount_aed > threshold:
        return True, (f"AED {amount_aed:,.0f} is more than {multiplier}x this account's typical "
                       f"autonomous purchase size (threshold ~AED {threshold:,.0f}) - unusually large "
                       f"for Alexa+ to execute without extra confirmation")
    return False, ""


def rule_repeat_autonomous_attempt(session_id, account_owner, merchant, lookback_hours=24):
    if not session_id:
        return False, ""
    con = sqlite3.connect(INCIDENT_DB)
    cutoff = (datetime.now() - timedelta(hours=lookback_hours)).isoformat()
    rows = con.execute(
        "SELECT session_id, decision FROM autonomous_action_log "
        "WHERE account_owner = ? AND merchant = ? AND created_at >= ? AND session_id != ?",
        (account_owner, merchant, cutoff, session_id),
    ).fetchall()
    con.close()
    if not rows:
        return False, ""
    if any(dec in ("HOLD", "REVIEW") for _, dec in rows):
        other_sessions = {s for s, _ in rows}
        return True, (f"This same purchase to '{merchant}' was already held or flagged for review "
                       f"under a different session ({len(other_sessions)} other session(s) in the "
                       f"last {lookback_hours}h) and is now being asked for again - looks like someone "
                       f"is coaching a retry rather than this being a fresh, independent request")
    return False, ""


def run_autonomous_action_rules(instruction_text, account_owner, merchant, amount_aed, session_id=""):
    fired = []
    for name, ok_reason in [
        ("pressured_instruction", rule_pressured_instruction(instruction_text)),
        ("unfamiliar_merchant", rule_unfamiliar_merchant(account_owner, merchant)),
        ("unusual_purchase_amount", rule_unusual_purchase_amount(account_owner, amount_aed)),
        ("repeat_after_hold", rule_repeat_autonomous_attempt(session_id, account_owner, merchant)),
    ]:
        ok, reason = ok_reason
        if ok:
            fired.append({"rule": name, "reason": reason, "weight": AUTONOMOUS_ACTION_WEIGHTS[name]})
    return fired


def _log_autonomous_action(session_id, account_owner, merchant, amount_aed, decision, risk_score):
    if not session_id:
        return
    con = sqlite3.connect(INCIDENT_DB)
    con.execute(
        """INSERT INTO autonomous_action_log
           (session_id, account_owner, merchant, amount_aed, decision, risk_score, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (session_id, account_owner, merchant, amount_aed, decision, risk_score,
         datetime.now().isoformat()),
    )
    con.commit()
    con.close()


@mcp.tool()
def authorize_autonomous_purchase(
    instruction_text: str,
    merchant: str,
    amount_aed: float,
    account_owner: str = "Amira",
    session_id: str = "",
) -> dict:
    """Call this BEFORE Alexa+ executes a purchase or payment using a stored
    payment method on the account owner's behalf - this is the gate for
    Alexa+'s OWN autonomous spending capability, not for a request someone
    else is sending in (use check_trust for that instead). The money must
    not move until this returns decision == "PROCEED".

    instruction_text: what Alexa+ was just told to do, in the account
    owner's or a caller's own words - used to detect pressure/secrecy
    language, the same signal a scammer coaching someone live on a call
    would leave. merchant: who the purchase goes to. amount_aed: the
    purchase amount. account_owner: whose stored payment method this is.

    session_id is optional, same reasoning as check_trust: pass a stable id
    to catch someone being coached to retry the same purchase in a fresh
    session after an earlier hold."""
    fired = run_autonomous_action_rules(instruction_text, account_owner, merchant, amount_aed, session_id)
    scoring = score_deterministically(fired)
    _log_autonomous_action(session_id, account_owner, merchant, amount_aed,
                            scoring["decision"], scoring["risk_score"])
    explanation = explain_with_bedrock(instruction_text, merchant, None, fired, scoring)

    execution_blocked = scoring["decision"] != "PROCEED"
    if execution_blocked:
        safe_resolution = (
            f"Don't let Alexa+ complete this purchase yet. Step away from whoever is asking for "
            f"this right now, and independently verify the merchant and amount — not while still "
            f"on the call or chat that triggered it — before authorizing it again."
        )
    else:
        safe_resolution = "Clear to proceed - Alexa+ can complete this purchase with the payment method on file."

    return {
        "account_owner": account_owner,
        "merchant": merchant,
        "amount_aed": amount_aed,
        "rules_fired": [{"rule": r["rule"], "reason": r["reason"]} for r in fired],
        "rules_fired_count": len(fired),
        "risk_score": scoring["risk_score"],
        "trust_score": scoring["trust_score"],
        "risk_level": scoring["risk_level"],
        "decision": scoring["decision"],
        "execution_blocked": execution_blocked,
        "would_have_executed": f"Alexa+ would have charged the card on file AED {amount_aed:,.0f} to {merchant}",
        "explanation": explanation.get("explanation"),
        "spoken_summary": explanation.get("spoken_summary"),
        "safe_resolution": safe_resolution,
        "card": _build_card(scoring["decision"], scoring["risk_score"], scoring["risk_level"],
                             fired, safe_resolution, subtitle=f"Autonomous purchase: {merchant}"),
    }


# ---------- Phase 3: reconstruct_trust_story ----------
# Checks what a request CLAIMS (an approval that supposedly happened, a
# vendor's bank account) against separate ground-truth records. This is
# deliberately deterministic, same reasoning as Step 1 — Python decides
# whether a contradiction exists; Nova only writes the plain-language
# summary of what was found.

NARRATE_PROMPT = """You explain, in plain language, the result of checking a
payment request's claims against trusted company records. You are given a
list of contradictions already found by code — you do not decide whether
something is a contradiction, you only explain the ones you're given
clearly, in one or two sentences, for a person to read.

Reply with ONLY JSON: {"summary": "<plain-language summary of the findings>"}
"""


def _narrate_contradictions(reference_id, contradictions):
    if not contradictions:
        return "No contradictions found — the claims in this request match company records."
    payload = {"reference_id": reference_id, "contradictions": contradictions}
    try:
        response = bedrock.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": NARRATE_PROMPT}],
            messages=[{"role": "user", "content": [{"text": json.dumps(payload)}]}],
            inferenceConfig={"maxTokens": 250, "temperature": 0.2},
        )
        raw = response["output"]["message"]["content"][0]["text"].strip()
        if raw.startswith("```"):
            raw = raw.strip("`").removeprefix("json").strip()
        return json.loads(raw).get("summary", "")
    except Exception:
        return f"{len(contradictions)} contradiction(s) found — see details below."


@mcp.tool()
def reconstruct_trust_story(
    reference_id: str,
    claimed_approvers: list[str] | None = None,
    claimed_vendor: str = "",
    claimed_beneficiary_account: str = "",
) -> dict:
    """Checks what a request CLAIMS happened against trusted company records —
    not whether the request itself looks risky (that's check_trust), but
    whether its story holds up. Use this when a request claims a specific
    approval already happened (e.g. 'the CEO and Finance Director approved
    this'), or claims a specific vendor bank account, and you want to verify
    those claims against real records. reference_id is the invoice/PO/PR
    number mentioned in the request. claimed_approvers is a list of names or
    roles the request says approved it. Returns story_status (CONSISTENT or
    INCONSISTENT) and a list of contradictions, if any."""
    contradictions = []

    # Check 1: does a purchase/approval record exist for this reference at all?
    real_records = APPROVAL_RECORDS.get(reference_id, [])
    if claimed_approvers and not real_records:
        contradictions.append({
            "claim": f"Approval exists under reference '{reference_id}'",
            "trusted_record": "No approval record found for this reference at all",
        })
    elif claimed_approvers:
        real_names_or_roles = set()
        for r in real_records:
            real_names_or_roles.add(r["approver_name"].lower())
            real_names_or_roles.add(r["approver_role"].lower())
        for claimed in claimed_approvers:
            emp, resolved_name, ambiguous = resolve_employee(claimed)
            check_against = {claimed.lower()}
            if resolved_name:
                check_against.add(resolved_name.lower())
            if emp and emp.get("role"):
                check_against.add(emp["role"].lower())
            if not check_against & real_names_or_roles:
                contradictions.append({
                    "claim": f"{claimed} approved this request",
                    "trusted_record": f"No matching approval from '{claimed}' found under reference '{reference_id}'",
                })

    # Check 2: does the claimed vendor account match the verified one on file?
    if claimed_vendor and claimed_beneficiary_account:
        vendor = VENDOR_ACCOUNTS.get(claimed_vendor)
        if not vendor:
            contradictions.append({
                "claim": f"Vendor '{claimed_vendor}' has a verified account on file",
                "trusted_record": f"'{claimed_vendor}' is not a recognized vendor in company records",
            })
        elif vendor["verified_account"] != claimed_beneficiary_account:
            contradictions.append({
                "claim": f"The payment account belongs to {claimed_vendor}",
                "trusted_record": f"{claimed_vendor}'s verified account is {vendor['verified_account']}, "
                                   f"which differs from the submitted account {claimed_beneficiary_account}",
            })

    story_status = "INCONSISTENT" if contradictions else "CONSISTENT"
    summary = _narrate_contradictions(reference_id, contradictions)

    return {
        "reference_id": reference_id,
        "story_status": story_status,
        "contradictions": contradictions,
        "contradiction_count": len(contradictions),
        "summary": summary,
    }


# ---------- Phase 6: access requests (credentials, MFA codes, login links) ----------
# A DIFFERENT shape of attack from check_trust: nobody is being asked to move
# money, someone is trying to get ACCESS instead - a password, an MFA code, a
# remote-access tool install, or a click on a lookalike login page. Scored the
# same way as everything else: deterministic Python rules, Nova explains only.

import difflib
import re

CODE_ASK_RE = re.compile(
    r"(read|give|tell|share|provide|send)\s+(me|out)?\s*(the|your)?\s*"
    r"(\d+[\s-]?digit\s+)?(mfa|otp|verification|one[\s-]?time|security)?\s*code",
    re.IGNORECASE,
)
PASSWORD_ASK_RE = re.compile(
    r"(what'?s|what is|tell me|give me|share|provide|confirm|send me)\s+(your\s+)?password",
    re.IGNORECASE,
)
REMOTE_ACCESS_RE = re.compile(
    r"install\s+(anydesk|teamviewer)|give\s+(me\s+)?remote\s+access",
    re.IGNORECASE,
)
FORWARDING_RULE_RE = re.compile(
    r"(set up|add|enable|create)\s+a\s+forwarding\s+rule",
    re.IGNORECASE,
)

ACCESS_RULE_WEIGHTS = {
    # credential_or_code_request, domain, and mfa_fatigue are each set at the
    # HOLD threshold on their own on purpose: a lookalike login domain or an
    # MFA-fatigue burst is the whole attack by itself (this is exactly the
    # Uber 2022 and credential-phishing mechanism) - it shouldn't need a
    # second rule to pile on before the system takes it seriously.
    "credential_or_code_request": 40,
    "no_open_ticket": 30,
    "unknown_contact_channel": 15,
    "domain": 40,
    "mfa_fatigue": 40,
    "urgency": 10,
    # Same idea as repeat_pattern_cross_session on the money side: the person
    # being TARGETED (employee_name) is the stable thing across an attacker's
    # retries, even when they change their claimed role or contact channel
    # or start a fresh session each time.
    "repeat_target_access": 25,
    # A mass phishing wave often looks completely unremarkable on any ONE
    # person's request - no urgency language, no odd contact channel, just a
    # plain "please verify this code" sent to 200 people at once. The signal
    # isn't in any individual message, it's in the fan-out across people, so
    # this is weighted high enough to escalate on its own.
    "mass_campaign_detected": 35,
}

# mfa_fatigue only applies when THIS request is itself about an MFA/sign-in
# approval - not as a blanket flag on every unrelated request from someone
# who merely has MFA history on file (that was a real bug: a genuine
# password-reset call would otherwise get flagged only because the same
# person had push prompts logged for something else entirely).
MFA_CONTEXT_RE = re.compile(
    r"approve|push notification|sign-in request|login attempt|verify it'?s you|login request",
    re.IGNORECASE,
)

IT_ROLE_NAMES = ("it", "it support", "it helpdesk", "it department")


def _load_known_domains():
    with open("known_domains.csv", newline="") as f:
        return [row["domain"].lower() for row in csv.DictReader(f)]


def _load_it_tickets():
    with open("it_tickets.csv", newline="") as f:
        records = {}
        for row in csv.DictReader(f):
            records.setdefault(row["employee_name"], []).append(row)
        return records


def _load_it_contacts():
    with open("it_contacts.csv", newline="") as f:
        return {row["channel"]: row["official_contact"] for row in csv.DictReader(f)}


def _load_mfa_events():
    with open("mfa_events.csv", newline="") as f:
        records = {}
        for row in csv.DictReader(f):
            records.setdefault(row["employee_name"], []).append(row)
        return records


KNOWN_DOMAINS = _load_known_domains()
IT_TICKETS = _load_it_tickets()
IT_CONTACTS = _load_it_contacts()
MFA_EVENTS = _load_mfa_events()


def rule_credential_or_code_request(text):
    # Deliberately specific to being ASKED TO DISCLOSE or INSTALL something,
    # not just a message that happens to mention "password" or "code" in
    # passing - a genuine password-reset notification also contains the
    # word "password" and must not trip this (it's one of the test cases).
    hits = []
    if PASSWORD_ASK_RE.search(text):
        hits.append("asks you to disclose your password")
    if CODE_ASK_RE.search(text):
        hits.append("asks you to read out a verification/MFA code")
    if REMOTE_ACCESS_RE.search(text):
        hits.append("asks you to install remote-access software")
    if FORWARDING_RULE_RE.search(text):
        hits.append("asks you to set up a mailbox forwarding rule")
    if hits:
        return True, f"A legitimate IT team never does this — {'; '.join(hits)}"
    return False, ""


def rule_no_open_ticket(claimed_sender_role, employee_name):
    if claimed_sender_role.strip().lower() not in IT_ROLE_NAMES:
        return False, ""
    open_tickets = [t for t in IT_TICKETS.get(employee_name, []) if t.get("status", "").lower() == "open"]
    if not open_tickets:
        return True, f"'{claimed_sender_role}' contacted {employee_name}, but no open IT ticket exists for them"
    return False, ""


def rule_unknown_contact_channel(claimed_sender_role, contact_used):
    if claimed_sender_role.strip().lower() not in IT_ROLE_NAMES or not contact_used:
        return False, ""
    if contact_used not in IT_CONTACTS.values():
        return True, f"Contacted via '{contact_used}', which does not match the official IT contact on file"
    return False, ""


def rule_domain(link_domain):
    if not link_domain:
        return False, ""
    link_l = link_domain.strip().lower()
    if link_l in KNOWN_DOMAINS:
        return False, ""
    for known in KNOWN_DOMAINS:
        ratio = difflib.SequenceMatcher(None, link_l, known).ratio()
        if ratio >= 0.75:
            return True, f"Link domain '{link_domain}' closely resembles known domain '{known}' but isn't it — likely a lookalike"
    return True, f"Link domain '{link_domain}' is not a recognized company or vendor domain"


def rule_mfa_fatigue(request_text, employee_name, min_prompts=3):
    if not MFA_CONTEXT_RE.search(request_text):
        return False, ""  # this request isn't itself an MFA/sign-in approval ask
    push_events = [e for e in MFA_EVENTS.get(employee_name, []) if e.get("event_type") == "push_prompt"]
    if len(push_events) >= min_prompts:
        return True, (f"{len(push_events)} MFA push prompts recorded for {employee_name} in a short "
                       f"window — looks like an MFA-fatigue attack, not normal use")
    return False, ""


def rule_repeat_target_access(session_id, employee_name, claimed_sender_role, contact_used,
                               lookback_hours=24):
    """The access-request equivalent of rule_repeat_target on the money side.
    An attacker working an access-request pretext doesn't need to keep the
    same claimed_sender_role or contact_used across attempts - 'IT Support'
    one time, a 'manager' the next, a different number each time - so
    matching on THEIR claimed identity (like the money-side rules do) would
    miss them completely. What stays constant is who they're TARGETING:
    employee_name. This rule looks across every session for repeated access
    attempts against the same employee, regardless of what the attacker
    claimed that time, and flags it if an earlier attempt was held/reviewed
    and this one presents differently (different claimed role or contact
    channel).

    Gated on THIS call's session_id being non-blank, same reasoning as the
    money-side rules: keeps one-off/batch-eval calls (session_id="") from
    cross-contaminating each other."""
    if not session_id:
        return False, ""
    con = sqlite3.connect(INCIDENT_DB)
    cutoff = (datetime.now() - timedelta(hours=lookback_hours)).isoformat()
    rows = con.execute(
        "SELECT session_id, claimed_sender_role, contact_used, decision FROM access_request_log "
        "WHERE employee_name = ? AND created_at >= ? AND session_id != ?",
        (employee_name, cutoff, session_id),
    ).fetchall()
    con.close()
    if not rows:
        return False, ""

    prior_held_or_reviewed = any(dec in ("HOLD", "REVIEW") for _, _, _, dec in rows)
    seen_combos = {(role, contact) for _, role, contact, _ in rows}
    changed_detail = (claimed_sender_role, contact_used) not in seen_combos
    other_sessions = {s for s, _, _, _ in rows}

    if prior_held_or_reviewed and changed_detail:
        return True, (f"{employee_name} was targeted by an access request under a different "
                       f"session ({len(other_sessions)} other session(s) in the last {lookback_hours}h, "
                       f"at least one HOLD/REVIEW), and this attempt presents a different claimed "
                       f"role or contact channel — looks like the same attacker retrying a new angle")
    return False, ""


def _normalize_for_similarity(text):
    """Lowercase, strip punctuation, collapse whitespace. Makes 'Hi Rajesh,
    this is IT!' and 'Hi Fatima, this is IT.' compare as near-identical
    rather than merely similar, so campaign detection isn't thrown off by
    nothing more than which employee's name got swapped into the template."""
    text = re.sub(r"[^\w\s]", " ", text.lower())
    return re.sub(r"\s+", " ", text).strip()


EMBED_MODEL_ID = os.environ.get("EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0")
# Cosine similarity at or above this counts as "same message, reworded". Set from
# a handful of paraphrase/unrelated pairs, NOT a tuned value - re-check it with
# your own examples before relying on it (override with EMBED_SIMILARITY_THRESHOLD).
EMBED_SIMILARITY_THRESHOLD = float(os.environ.get("EMBED_SIMILARITY_THRESHOLD", "0.80"))
_EMBED_CACHE = {}


def _embed(text):
    """Vector for a message via Bedrock Titan embeddings, or None if the call
    fails. Cached per normalized text so each logged message is embedded once.
    Failure is never fatal: the caller falls back to the plain text-overlap
    check, so this can only ADD detections, never remove one."""
    key = _normalize_for_similarity(text)
    if key in _EMBED_CACHE:
        return _EMBED_CACHE[key]
    vec = None
    try:
        resp = bedrock.invoke_model(
            modelId=EMBED_MODEL_ID,
            body=json.dumps({"inputText": key[:2000], "dimensions": 256, "normalize": True}),
            contentType="application/json",
            accept="application/json",
        )
        vec = json.loads(resp["body"].read())["embedding"]
    except Exception:
        vec = None
    _EMBED_CACHE[key] = vec
    return vec


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def _messages_similar(norm_a, text_a, norm_b, text_b, ratio_threshold):
    """True if two messages are the same pretext. First the original word-overlap
    check; only if that misses, compare meaning via embeddings, which is what
    catches a scammer rewording the same ask. Returns (similar, method)."""
    if difflib.SequenceMatcher(None, norm_a, norm_b).ratio() >= ratio_threshold:
        return True, "text overlap"
    va, vb = _embed(text_a), _embed(text_b)
    if va and vb and _cosine(va, vb) >= EMBED_SIMILARITY_THRESHOLD:
        return True, "meaning (embedding)"
    return False, ""


def rule_mass_campaign(employee_name, claimed_sender_role, request_text,
                        lookback_minutes=60, min_distinct_targets=3, similarity_threshold=0.70):
    """Catches the attack a single per-request check structurally cannot see:
    the SAME pretext sent to MANY employees at once. No individual message
    here needs to look unusual on its own — what makes it a campaign rather
    than a one-off is that several different people got something close to
    the same message in the same short window. That's the actual signature a
    SOC watches for in a real phishing wave, and it's exactly what
    repeat_target_access (keyed on one employee) and repeat_pattern_cross_session
    (keyed on one attacker identity) both miss, because each is scoped to a
    single target or a single claimed sender - neither looks ACROSS employees.

    Deliberately NOT gated on session_id the way the other memory rules are:
    a campaign doesn't need one attacker's session to repeat, it needs many
    different employees' first contact with it to cluster in time, and each
    of those employees has their own separate session. Counts how many
    DISTINCT employees (besides this one) have had a request this similar,
    under the same claimed role, in the last lookback_minutes - if this
    employee is simply the Nth person to get essentially the same message,
    that's the finding, regardless of whether their own request looks risky
    in isolation."""
    if not request_text or not employee_name:
        return False, ""
    con = sqlite3.connect(INCIDENT_DB)
    cutoff = (datetime.now() - timedelta(minutes=lookback_minutes)).isoformat()
    rows = con.execute(
        "SELECT DISTINCT employee_name, request_text FROM access_request_log "
        "WHERE claimed_sender_role = ? AND created_at >= ? AND request_text IS NOT NULL "
        "AND employee_name != ?",
        (claimed_sender_role, cutoff, employee_name),
    ).fetchall()
    con.close()
    if not rows:
        return False, ""

    norm_current = _normalize_for_similarity(request_text)
    matched_targets = {employee_name}
    for emp, txt in rows:
        if not txt:
            continue
        similar, _method = _messages_similar(
            norm_current, request_text, _normalize_for_similarity(txt), txt, similarity_threshold)
        if similar:
            matched_targets.add(emp)

    if len(matched_targets) >= min_distinct_targets:
        others = sorted(matched_targets - {employee_name})
        shown = ", ".join(others[:5]) + ("..." if len(others) > 5 else "")
        return True, (f"The same '{claimed_sender_role}' message (or a close variant) has also gone "
                       f"to {len(others)} other employee(s) in the last {lookback_minutes} minutes "
                       f"({shown}) — this is a mass campaign hitting the organization at once, not "
                       f"an isolated request")
    return False, ""


def run_access_rules(request_text, claimed_sender_role, employee_name, contact_used, link_domain,
                      session_id=""):
    signals = classify_manipulation_signals(request_text)
    fired = []
    for name, ok_reason in [
        ("credential_or_code_request", rule_credential_or_code_request(request_text)),
        ("no_open_ticket", rule_no_open_ticket(claimed_sender_role, employee_name)),
        ("unknown_contact_channel", rule_unknown_contact_channel(claimed_sender_role, contact_used)),
        ("domain", rule_domain(link_domain)),
        ("mfa_fatigue", rule_mfa_fatigue(request_text, employee_name)),
        ("urgency", rule_urgency(signals)),
        ("repeat_target_access", rule_repeat_target_access(session_id, employee_name,
                                                             claimed_sender_role, contact_used)),
        ("mass_campaign_detected", rule_mass_campaign(employee_name, claimed_sender_role, request_text)),
    ]:
        ok, reason = ok_reason
        if ok:
            fired.append({"rule": name, "reason": reason, "weight": ACCESS_RULE_WEIGHTS[name]})
    return fired, signals


@mcp.tool()
def check_access_request(
    request_text: str,
    claimed_sender_role: str,
    employee_name: str,
    contact_used: str = "",
    link_domain: str = "",
    session_id: str = "",
) -> dict:
    """Check whether a request for a password, an MFA code, remote-access
    software, or a click on a login link should be trusted. This is a
    DIFFERENT shape of attack from check_trust (which is for payment/money
    requests): nobody is being asked to move money here — someone is trying
    to get ACCESS instead. Checks: does the message ask for something a real
    IT team would never ask for (password, MFA code, remote-access install,
    mailbox forwarding rule)? If it claims to be IT, is there an actual open
    ticket for this person, and does the contact channel match the official
    one on file? If a link's domain was given, is it a recognized company/
    vendor domain or a lookalike? Has this person had a burst of MFA push
    prompts recently (fatigue-attack pattern)? Scored the same deterministic
    way as check_trust; Nova only explains the result afterward, never
    decides it.

    claimed_sender_role: who they say they are, e.g. "IT Support" or a name.
    employee_name: the person being targeted — must match a name in
    employees.csv to check ticket/MFA history. contact_used: the phone
    number or email the message came through, if known. link_domain: the
    domain of any link in the message, if one was given.

    session_id is optional: pass a stable id for one ongoing caller/
    conversation to let a repeat-target rule catch the same employee being
    targeted again under a different claimed role or contact channel, even
    across separate sessions — the attacker's story can change each time,
    but who they're targeting usually doesn't. Leave it blank for a one-off,
    standalone check so unrelated test scenarios can't cross-contaminate."""
    fired, signals = run_access_rules(request_text, claimed_sender_role, employee_name,
                                       contact_used, link_domain, session_id)
    scoring = score_deterministically(fired)
    _log_access_request(session_id, employee_name, claimed_sender_role, contact_used,
                         scoring["decision"], scoring["risk_score"], request_text)
    explanation = explain_with_bedrock(request_text, claimed_sender_role, None, fired, scoring)

    # A request-type-specific safe step is worth being exact about, rather
    # than leaning only on Nova's more general one for this category.
    safe_resolution = explanation.get("safe_resolution", "")
    fired_names = {r["rule"] for r in fired}
    if "mass_campaign_detected" in fired_names:
        # Org-wide signal, so the action is org-wide too - telling just this
        # one person isn't enough once several others already got it.
        safe_resolution = ("Don't act on this, and report it to IT Security right away so they can "
                            "warn everyone — this message has gone to multiple other employees too, "
                            "not just you.")
    elif "credential_or_code_request" in fired_names:
        safe_resolution = ("Don't give a password or MFA code to anyone, even someone claiming "
                            "to be IT. Hang up and call the helpdesk number on file.")
    elif "domain" in fired_names:
        safe_resolution = ("Don't click the link or enter credentials there. Type the company "
                            "portal address in directly instead.")
    elif "mfa_fatigue" in fired_names:
        safe_resolution = "Don't approve any further prompts. Change your password and contact IT Security now."

    return {
        "claimed_sender_role": claimed_sender_role,
        "employee_name": employee_name,
        "manipulation_signals": signals,
        "rules_fired": [{"rule": r["rule"], "reason": r["reason"]} for r in fired],
        "rules_fired_count": len(fired),
        "risk_score": scoring["risk_score"],
        "trust_score": scoring["trust_score"],
        "risk_level": scoring["risk_level"],
        "decision": scoring["decision"],
        "explanation": explanation.get("explanation"),
        "spoken_summary": explanation.get("spoken_summary"),
        "safe_resolution": safe_resolution,
        "card": _build_card(scoring["decision"], scoring["risk_score"], scoring["risk_level"],
                             fired, safe_resolution, subtitle=f"Contact claiming to be {claimed_sender_role}"),
    }


# ---------- Phase 7: report_compromise ----------
# Everything above warns BEFORE a mistake. This is the tool for AFTER one:
# someone already typed a password on a fake page, or approved a push they
# didn't start. It never judges whether that was a mistake - it returns the
# right recovery steps immediately, because early reporting is what limits
# the damage, and prepare_incident/submit_incident (below) handle logging it
# with the same human-approval gate as everything else.

RECOVERY_STEPS = {
    "entered_password": [
        "Change your password immediately, from a device you trust — not the one you entered it on.",
        "Sign out of all active sessions for your account.",
        "Check whether a mailbox forwarding rule was added, and remove it if so.",
        "Check for any new or unknown MFA device registered on your account, and remove it.",
    ],
    "approved_mfa_push": [
        "Change your password immediately, from a device you trust.",
        "Review and revoke any new MFA device or app registered around the same time.",
        "Sign out of all active sessions for your account.",
    ],
    "clicked_link": [
        "Don't enter any credentials on that page if you haven't already.",
        "Run a malware/antivirus scan on the device used.",
        "Change your password from a different, trusted device as a precaution.",
    ],
    "other": [
        "Change your password from a trusted device as a precaution.",
        "Report this to IT Security immediately so they can check your account activity.",
    ],
}


@mcp.tool()
def report_compromise(
    employee_name: str,
    what_happened: str,
    incident_type: str = "other",
) -> dict:
    """Use this when someone reports they ALREADY took the risky action —
    typed a password on a page, approved an MFA push they didn't start,
    clicked a suspicious link — rather than asking whether a request looks
    safe BEFORE acting. This never judges whether it was a mistake; it
    immediately returns the right recovery steps for what happened, because
    early reporting limits damage. After showing the steps, prepare an
    incident with prepare_incident (risk_score=100, decision="HOLD" since a
    self-reported compromise is always treated as real until IT Security
    says otherwise) and only submit_incident after the person explicitly
    agrees, same as any other case.

    incident_type: one of "entered_password", "approved_mfa_push",
    "clicked_link", or "other" if unsure — a reasonable guess from
    what_happened is fine, this never blocks on getting it exactly right."""
    steps = RECOVERY_STEPS.get(incident_type, RECOVERY_STEPS["other"])
    return {
        "employee_name": employee_name,
        "incident_type": incident_type,
        "reported_at": datetime.now().isoformat(),
        "immediate_steps": steps,
        "message": ("Do these steps now, in order. I can also log this as an IT Security "
                     "incident with a timestamp — would you like me to prepare that?"),
        "next_tool": "prepare_incident",
    }


# ---------- Phase 5: prepare_incident / submit_incident ----------
# The system may prepare a case on its own, but it never submits one
# without an explicit yes from a person. No Bedrock involved here —
# this is bookkeeping, not judgment.

INCIDENT_DB = "trust_incidents.db"


def _init_incident_db():
    con = sqlite3.connect(INCIDENT_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE,
        reference_id TEXT,
        claimed_sender TEXT,
        risk_score INTEGER,
        decision TEXT,
        story_status TEXT,
        contradictions_json TEXT,
        summary TEXT,
        status TEXT,
        created_at TEXT,
        submitted_at TEXT
    )""")
    # Logs EVERY check_trust call (not just escalated ones), scoped by
    # session_id, so rule_repeat_pattern can look back at what the same
    # claimed sender asked for earlier in the same session. This is what
    # makes pattern detection possible - a single-call rule engine has no
    # memory of anything that happened before it.
    con.execute("""CREATE TABLE IF NOT EXISTS request_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        claimed_sender TEXT,
        resolved_to TEXT,
        device TEXT,
        location TEXT,
        decision TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")
    # Same idea as request_log, but for check_access_request instead of
    # check_trust - lets rule_repeat_target_access look back at every prior
    # access attempt made against a given employee_name, across sessions.
    # request_text is stored here (unlike request_log on the money side)
    # specifically so rule_mass_campaign can compare wording across
    # DIFFERENT employees - every other column in this table is already
    # enough for repeat_target_access, which only looks at one employee's
    # own history.
    con.execute("""CREATE TABLE IF NOT EXISTS access_request_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        employee_name TEXT,
        claimed_sender_role TEXT,
        contact_used TEXT,
        request_text TEXT,
        decision TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")
    # An older database file may already have access_request_log without the
    # request_text column (CREATE TABLE IF NOT EXISTS never alters an existing
    # table). Add it in place so an old trust_incidents.db keeps working.
    _cols = [r[1] for r in con.execute("PRAGMA table_info(access_request_log)").fetchall()]
    if "request_text" not in _cols:
        con.execute("ALTER TABLE access_request_log ADD COLUMN request_text TEXT")
    con.execute("""CREATE TABLE IF NOT EXISTS incident_prep_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        claimed_sender TEXT,
        created_at TEXT
    )""")
    # Logs every authorize_autonomous_purchase call so rule_repeat_autonomous_attempt
    # can catch someone coaching the account owner to retry a held purchase
    # under a fresh session.
    con.execute("""CREATE TABLE IF NOT EXISTS autonomous_action_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        account_owner TEXT,
        merchant TEXT,
        amount_aed REAL,
        decision TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")
    con.commit()
    con.close()


def _log_request(session_id, claimed_sender, resolved_name, device, location, decision, risk_score):
    if not session_id:
        return  # no session context given -> nothing to log, nothing to look back on
    con = sqlite3.connect(INCIDENT_DB)
    con.execute(
        """INSERT INTO request_log
           (session_id, claimed_sender, resolved_to, device, location, decision, risk_score, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (session_id, claimed_sender, resolved_name, device, location, decision, risk_score,
         datetime.now().isoformat()),
    )
    con.commit()
    con.close()


def _log_access_request(session_id, employee_name, claimed_sender_role, contact_used,
                         decision, risk_score, request_text=""):
    if not session_id:
        return
    con = sqlite3.connect(INCIDENT_DB)
    con.execute(
        """INSERT INTO access_request_log
           (session_id, employee_name, claimed_sender_role, contact_used, request_text,
            decision, risk_score, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (session_id, employee_name, claimed_sender_role, contact_used, request_text, decision,
         risk_score, datetime.now().isoformat()),
    )
    con.commit()
    con.close()


_init_incident_db()


@mcp.tool()
def prepare_incident(
    reference_id: str,
    claimed_sender: str,
    risk_score: int,
    decision: str,
    story_status: str = "",
    contradictions: list | None = None,
    summary: str = "",
) -> dict:
    """Prepares a case from a completed investigation (the results of
    check_trust and, if run, reconstruct_trust_story) so it can be escalated
    to Finance Risk. This does NOT submit anything — it only drafts the case
    and returns a case_id. Call submit_incident afterward, and only after
    the person has explicitly agreed, to actually log it."""
    case_id = f"TRUST-{1000 + int(datetime.now().timestamp()) % 9000}"
    now_iso = datetime.now().isoformat()
    con = sqlite3.connect(INCIDENT_DB)
    con.execute(
        """INSERT INTO incidents
           (case_id, reference_id, claimed_sender, risk_score, decision,
            story_status, contradictions_json, summary, status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (case_id, reference_id, claimed_sender, risk_score, decision,
         story_status, json.dumps(contradictions or []), summary,
         "DRAFT", now_iso),
    )

    # Approval-fatigue guard: an attacker (or an agent being socially
    # engineered) can try to wear a human down by triggering the SAME
    # approval prompt repeatedly, hoping they eventually click yes without
    # reading it carefully (this is the agent-era version of MFA-prompt
    # bombing - OWASP ASI09 names this directly). Count how many cases have
    # been PREPARED for this claimed_sender in the last hour; past a small
    # threshold, the prompt itself names the pattern instead of looking like
    # just another routine approval ask, so a tired human (or an automated
    # client) can't rubber-stamp it without noticing.
    cooldown_cutoff = (datetime.now() - timedelta(hours=1)).isoformat()
    con.execute(
        "INSERT INTO incident_prep_log (claimed_sender, created_at) VALUES (?, ?)",
        (claimed_sender, now_iso),
    )
    recent_count = con.execute(
        "SELECT COUNT(*) FROM incident_prep_log WHERE claimed_sender = ? AND created_at >= ?",
        (claimed_sender, cooldown_cutoff),
    ).fetchone()[0]
    con.commit()
    con.close()

    base_prompt = (
        f"I've prepared case {case_id} for Finance Risk — {decision} decision, "
        f"risk score {risk_score}" + (f", story status {story_status}" if story_status else "") +
        ". Would you like me to submit it?"
    )

    approval_fatigue_warning = recent_count >= 3
    if approval_fatigue_warning:
        prompt_for_user = (
            f"⚠ This is the {recent_count}th approval request involving '{claimed_sender}' in "
            f"the last hour. Before deciding, re-read the full context rather than approving "
            f"from memory of the earlier ones — repeated prompts are a known way to wear down "
            f"a human approver. {base_prompt}"
        )
    else:
        prompt_for_user = base_prompt

    return {
        "case_id": case_id,
        "status": "DRAFT",
        "requires_authorization": True,
        "approval_fatigue_warning": approval_fatigue_warning,
        "recent_requests_for_this_sender": recent_count,
        "prompt_for_user": prompt_for_user,
    }


@mcp.tool()
def submit_incident(case_id: str, authorized: bool) -> dict:
    """Submits a previously prepared incident — but ONLY if authorized=true,
    which must come from the person explicitly agreeing, never assumed or
    inferred. If authorized=false, the case is cancelled, not submitted."""
    con = sqlite3.connect(INCIDENT_DB)
    row = con.execute("SELECT status FROM incidents WHERE case_id = ?", (case_id,)).fetchone()
    if row is None:
        con.close()
        return {"case_id": case_id, "status": "NOT_FOUND",
                 "message": f"No case {case_id} was found — it may need to be prepared first."}

    if not authorized:
        con.execute("UPDATE incidents SET status = 'CANCELLED' WHERE case_id = ?", (case_id,))
        con.commit()
        con.close()
        return {"case_id": case_id, "status": "CANCELLED",
                 "message": f"Case {case_id} was not submitted — no action was taken."}

    con.execute(
        "UPDATE incidents SET status = 'SUBMITTED', submitted_at = ? WHERE case_id = ?",
        (datetime.now().isoformat(), case_id),
    )
    con.commit()
    con.close()
    return {"case_id": case_id, "status": "SUBMITTED",
             "message": f"Case {case_id} has been submitted to Finance Risk."}


# ---------- deployment: public HTTPS entrypoint with a minimal auth gate ----------
# Amazon's Alexa+ MCP Toolkit quickstart requires that an UNAUTHENTICATED
# request get back a 401 with NO WWW-Authenticate header. This SDK's own
# built-in OAuth middleware (RequireAuthMiddleware) always adds one - it's
# built for a real OAuth authorization server, which this project doesn't
# have (and doesn't need for a hackathon deployment with no real Alexa+
# preview access). So instead of wiring that in, this is a minimal shared-
# secret gate sitting in front of the same Starlette app the SDK builds:
# if TRUST_SERVER_API_TOKEN is set in the environment, a request must send
# `Authorization: Bearer <that token>` or it gets exactly the 401 shape
# Alexa+ expects. Leave the env var unset to run open, e.g. for local dev.
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

REQUIRED_API_TOKEN = os.environ.get("TRUST_SERVER_API_TOKEN", "")


class BearerGate(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not REQUIRED_API_TOKEN:
            return await call_next(request)
        auth_header = request.headers.get("authorization", "")
        if auth_header != f"Bearer {REQUIRED_API_TOKEN}":
            return JSONResponse(
                {"error": "invalid_token", "error_description": "Authentication required"},
                status_code=401,
                # Deliberately no WWW-Authenticate header here - see note above.
            )
        return await call_next(request)


def build_app():
    """Returns the deployable ASGI app: the SDK's own Streamable HTTP app
    (MCP spec 2025-11-25) with the bearer gate in front of it. A deployment
    platform (App Runner, Lambda via Mangum, or plain uvicorn) imports this
    as `trust_server:asgi_app`."""
    app = mcp.streamable_http_app()
    app.add_middleware(BearerGate)
    return app


asgi_app = build_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(asgi_app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
