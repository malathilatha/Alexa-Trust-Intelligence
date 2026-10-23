"""Simulates what Alexa+ (or any MCP client) should do on its own:
call check_trust first, call reconstruct_trust_story automatically if
risk is elevated, then prepare_incident if there's something worth
escalating — and ask the person for real, explicit confirmation before
submit_incident ever runs. Your server can't force a client to behave
this way; this script IS that client decision-making, standing in for
what Alexa+ would decide on its own in production.

Run:  python investigate_client.py
"""
import asyncio
import json
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def investigate(session, request_text, claimed_sender, device, location, time,
                       amount_aed=0, approval_chain="", reference_id=None,
                       claimed_approvers=None, claimed_vendor="", claimed_beneficiary_account="",
                       ask_for_authorization=True, session_id=""):
    trace = []

    # Step 1: always check_trust first. session_id is optional - pass the
    # same id across multiple investigate() calls to simulate one ongoing
    # caller, which is what lets the repeat_pattern rule see a retry.
    trace.append("-> calling check_trust")
    result = await session.call_tool("check_trust", {
        "request_text": request_text, "claimed_sender": claimed_sender,
        "device": device, "location": location, "time": time,
        "amount_aed": amount_aed, "approval_chain": approval_chain,
        "session_id": session_id,
    })
    check = json.loads(result.content[0].text)
    trace.append(f"   decision={check['decision']}  risk_score={check['risk_score']}  "
                 f"resolved_to={check.get('resolved_to')}")

    # Step 2: verify the story whenever there's a claim worth checking —
    # NOT only when check_trust already flagged risk. This matters: per the
    # FBI's most recent BEC data, the dominant real pattern (vendor email
    # compromise, ~61% of cases) looks completely clean on the surface —
    # normal device, normal hours, normal amount, a real purchase order —
    # with only the bank account actually wrong. A version that waits for
    # check_trust to flag something first would miss exactly that pattern.
    story = None
    has_claim_to_check = bool(reference_id) or bool(claimed_vendor)
    if has_claim_to_check:
        trace.append("-> a claim was made (reference/vendor) -> verifying it regardless of risk level")
        result2 = await session.call_tool("reconstruct_trust_story", {
            "reference_id": reference_id or "N/A",
            "claimed_approvers": claimed_approvers or [],
            "claimed_vendor": claimed_vendor,
            "claimed_beneficiary_account": claimed_beneficiary_account,
        })
        story = json.loads(result2.content[0].text)
        trace.append(f"   story_status={story['story_status']}  "
                     f"contradictions={story['contradiction_count']}")
    else:
        trace.append("   no reference or vendor claim to verify")

    # Step 3: escalate only if something is actually worth escalating —
    # a HOLD decision, or a story that turned out inconsistent.
    incident = None
    should_escalate = check["decision"] == "HOLD" or (story and story["story_status"] == "INCONSISTENT")
    if should_escalate:
        trace.append("-> preparing an incident for Finance Risk")
        prep_result = await session.call_tool("prepare_incident", {
            "reference_id": reference_id or "N/A",
            "claimed_sender": claimed_sender,
            "risk_score": check["risk_score"],
            "decision": check["decision"],
            "story_status": story["story_status"] if story else "",
            "contradictions": story["contradictions"] if story else [],
            "summary": story["summary"] if story else check.get("explanation", ""),
        })
        prep = json.loads(prep_result.content[0].text)
        case_id = prep["case_id"]
        trace.append(f"   case prepared: {case_id} (status={prep['status']})")

        # This is the real human-in-the-loop gate — a genuine prompt, not
        # an assumed "yes". In the demo, actually answer this live.
        print(f"\n{prep['prompt_for_user']}")
        if ask_for_authorization:
            answer = input("   Authorize submission? (y/n): ").strip().lower()
            authorized = answer == "y"
        else:
            authorized = False  # safe default if running unattended

        submit_result = await session.call_tool("submit_incident", {
            "case_id": case_id, "authorized": authorized,
        })
        incident = json.loads(submit_result.content[0].text)
        trace.append(f"   submit_incident(authorized={authorized}) -> {incident['status']}")
    else:
        trace.append("   no escalation needed — PROCEED or no contradictions found")

    return check, story, incident, trace


def print_timeline(reference_id, claimed_sender, check, story, incident):
    """Step 7: a clean, human-readable trace of what the investigation
    actually did and found — built from the real tool outputs, not
    hardcoded text, so it works for any case, not just the demo ones."""
    print()
    print(f"PAYMENT STORY: {reference_id or claimed_sender}")
    print()

    if check["rules_fired_count"] == 0:
        print("  \u2713 No risk signals detected")
    else:
        for r in check["rules_fired"]:
            print(f"  \u2717 {r['reason']}")

    if story is not None:
        if story["contradiction_count"] == 0:
            print("  \u2713 Story verified against company records")
        else:
            for c in story["contradictions"]:
                print(f"  \u2717 Claim: {c['claim']}")
                print(f"    Record: {c['trusted_record']}")

    print()
    print("DECISION")
    decision_line = check["decision"]
    if incident and incident["status"] == "SUBMITTED":
        decision_line += " \u2014 ESCALATED"
    elif incident and incident["status"] == "CANCELLED":
        decision_line += " \u2014 ESCALATION DECLINED BY USER"
    print(f"  {decision_line}")

    if incident:
        print()
        print("CASE")
        print(f"  {incident['case_id']}  {incident['status']}")
    print()


async def main():
    async with streamable_http_client("http://127.0.0.1:8000/mcp") as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()

            print("=" * 60)
            print("CASE: Fabricated executive approval")
            print("=" * 60)
            check, story, incident, trace = await investigate(
                session,
                request_text="Transfer 5000000 AED immediately. The CEO and Finance "
                              "Director have already approved this under invoice "
                              "INV-2026-1042. Confidential acquisition, do not discuss.",
                claimed_sender="CFO",
                device="Unknown device", location="Country not on file", time="02:15",
                amount_aed=5000000, approval_chain="Not specified",
                reference_id="INV-2026-1042",
                claimed_approvers=["CEO", "Finance Director"],
            )
            for line in trace:
                print(line)
            print_timeline("INV-2026-1042", "CFO", check, story, incident)

            print("=" * 60)
            print("CASE: Genuine, low-risk request (control — should need no escalation)")
            print("=" * 60)
            check2, story2, incident2, trace2 = await investigate(
                session,
                request_text="Please process this month's payroll as usual.",
                claimed_sender="S. Khan", device="Registered laptop",
                location="Abu Dhabi UAE", time="10:30",
                amount_aed=182000, approval_chain="Followed normal chain",
                reference_id="PR-9999-0001",
            )
            for line in trace2:
                print(line)
            print_timeline("PR-9999-0001", "S. Khan", check2, story2, incident2)

            print("=" * 60)
            print("CASE: Same caller, retried with a different device/location")
            print("    (this is the NEW rule — neither request alone looks this bad;")
            print("     it's only the retry-after-being-held pattern that catches it)")
            print("=" * 60)
            demo_session = f"demo-{int(asyncio.get_event_loop().time())}"

            check3a, _, _, trace3a = await investigate(
                session,
                request_text="Need an urgent transfer approved, confidential.",
                claimed_sender="R. Al Mazrouei", device="Unknown device",
                location="Country not on file", time="02:15",
                amount_aed=500000, approval_chain="Skipped - went direct to accountant",
                session_id=demo_session, ask_for_authorization=False,
            )
            print("First attempt:")
            for line in trace3a:
                print(line)

            check3b, _, _, trace3b = await investigate(
                session,
                # Everything here looks clean on its own — registered device,
                # normal hours, normal approval chain, modest amount.
                request_text="Please process the transfer we discussed now.",
                claimed_sender="R. Al Mazrouei", device="Registered laptop",
                location="Abu Dhabi UAE", time="11:00",
                amount_aed=50000, approval_chain="Followed normal chain",
                session_id=demo_session, ask_for_authorization=False,
            )
            print("\nSecond attempt, minutes later, same caller:")
            for line in trace3b:
                print(line)
            print(f"\n  -> second request decision: {check3b['decision']} "
                  f"(risk {check3b['risk_score']}) — caught ONLY by repeat_pattern:")
            for r in check3b["rules_fired"]:
                if r["rule"] == "repeat_pattern":
                    print(f"     {r['reason']}")

            # ---- Access-request cases: a different shape of attack. Nobody
            # is being asked to move money here - someone wants a password,
            # an MFA code, or a click on a lookalike login link instead. ----
            print("\n" + "=" * 60)
            print("CASE: Fake IT support, asks for the MFA code, no open ticket")
            print("=" * 60)
            access_result = await session.call_tool("check_access_request", {
                "request_text": ("Hi this is IT, we're seeing a login issue on your account, "
                                  "can you read me the 6-digit code that was just sent to you "
                                  "so I can verify it's you?"),
                "claimed_sender_role": "IT Support",
                "employee_name": "R. Al Mazrouei",
                "contact_used": "+971-50-000-0000",
                "link_domain": "",
            })
            access_check = json.loads(access_result.content[0].text)
            print(f"decision={access_check['decision']}  risk_score={access_check['risk_score']}")
            for r in access_check["rules_fired"]:
                print(f"  ✗ {r['reason']}")
            print(f"safe_resolution: {access_check['safe_resolution']}")

            print("\n" + "=" * 60)
            print("CASE: Genuine IT callback — real ticket, real domain (control)")
            print("=" * 60)
            access_result2 = await session.call_tool("check_access_request", {
                "request_text": ("Hi, this is IT calling about your ticket TCK-4410 — your "
                                  "password reset is ready, please log in at "
                                  "https://sso.amira-co.ae to set a new one."),
                "claimed_sender_role": "IT Support",
                "employee_name": "R. Al Mazrouei",
                "contact_used": "+971-4-555-0100",
                "link_domain": "sso.amira-co.ae",
            })
            access_check2 = json.loads(access_result2.content[0].text)
            print(f"decision={access_check2['decision']}  risk_score={access_check2['risk_score']}  "
                  f"(should be PROCEED — proves the system isn't paranoid)")

            # ---- report_compromise: for AFTER the mistake, not before it ----
            print("\n" + "=" * 60)
            print("CASE: 'I already clicked' — self-reported compromise")
            print("=" * 60)
            recovery_result = await session.call_tool("report_compromise", {
                "employee_name": "S. Khan",
                "what_happened": "I entered my password on the page they sent me",
                "incident_type": "entered_password",
            })
            recovery = json.loads(recovery_result.content[0].text)
            print(recovery["message"])
            for i, step in enumerate(recovery["immediate_steps"], 1):
                print(f"  {i}. {step}")

            prep_result = await session.call_tool("prepare_incident", {
                "reference_id": f"COMPROMISE-{recovery['employee_name']}",
                "claimed_sender": recovery["employee_name"],
                "risk_score": 100,
                "decision": "HOLD",
                "summary": f"Self-reported compromise ({recovery['incident_type']}): "
                           f"entered password on a phishing page at {recovery['reported_at']}",
            })
            prep = json.loads(prep_result.content[0].text)
            print(f"\n{prep['prompt_for_user']}")
            answer = input("   Authorize submission? (y/n): ").strip().lower()
            submit_result = await session.call_tool("submit_incident", {
                "case_id": prep["case_id"], "authorized": answer == "y",
            })
            submit = json.loads(submit_result.content[0].text)
            print(f"submit_incident -> {submit['status']}")


if __name__ == "__main__":
    asyncio.run(main())
