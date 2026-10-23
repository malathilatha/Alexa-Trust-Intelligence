"""Step 8: run the labeled test scenarios through the real, live pipeline
and report honest numbers — not estimated, not hand-waved.

This runs the FULL pipeline, the same way investigate_client.py simulates
Alexa+ deciding on its own: check_trust first, then reconstruct_trust_story
whenever a request makes a reference/vendor claim worth verifying (not only
when check_trust already flagged risk). That second step is what catches
scenarios 16-17 — vendor email compromise cases that look completely clean
on every surface signal (normal device, hours, amount, a real PO) and are
only wrong on the bank account itself. check_trust alone can't see that;
reconstruct_trust_story checks the claim against vendor_accounts.csv.

Needs the server running (python trust_server.py) and fraud_scenarios.csv
in this folder. This makes real Bedrock calls, so it costs a small,
genuine amount per scenario.

Run:  python evaluate_scenarios.py
"""
import asyncio
import csv
import json
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

# genuine -> should PROCEED, suspicious -> should REVIEW, fraudulent -> should HOLD
EXPECTED_DECISION = {"genuine": "PROCEED", "suspicious": "REVIEW", "fraudulent": "HOLD"}


def load_scenarios(path="fraud_scenarios.csv"):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _split_approvers(raw):
    if not raw:
        return []
    return [a.strip() for a in raw.split(";") if a.strip()]


async def run_one(session, s):
    reference_id = (s.get("reference_id") or "").strip()
    claimed_vendor = (s.get("claimed_vendor") or "").strip()
    claimed_beneficiary_account = (s.get("claimed_beneficiary_account") or "").strip()
    claimed_approvers = _split_approvers(s.get("claimed_approvers"))

    # Step 1: always check_trust
    result = await session.call_tool("check_trust", {
        "request_text": s["request_text"], "claimed_sender": s["claimed_sender"],
        "device": s["device"], "location": s["location"], "time": s["time"],
        "amount_aed": float(s["amount_aed"]), "approval_chain": s["approval_chain"],
    })
    check = json.loads(result.content[0].text)

    # Step 2: verify the story whenever a reference/vendor claim was made,
    # regardless of what check_trust already decided (see module docstring).
    story = None
    has_claim_to_check = bool(reference_id) or bool(claimed_vendor)
    if has_claim_to_check:
        result2 = await session.call_tool("reconstruct_trust_story", {
            "reference_id": reference_id or "N/A",
            "claimed_approvers": claimed_approvers,
            "claimed_vendor": claimed_vendor,
            "claimed_beneficiary_account": claimed_beneficiary_account,
        })
        story = json.loads(result2.content[0].text)

    # Final decision: an inconsistent story escalates to HOLD even if
    # check_trust alone looked clean (exactly the scenario 16/17 case).
    final_decision = check["decision"]
    if story and story["story_status"] == "INCONSISTENT":
        final_decision = "HOLD"

    return check, story, final_decision


async def run_evaluation():
    scenarios = load_scenarios()
    results = []

    async with streamable_http_client("http://127.0.0.1:8000/mcp") as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()

            for s in scenarios:
                check, story, final_decision = await run_one(session, s)
                expected = EXPECTED_DECISION[s["label"]]
                correct = final_decision == expected
                results.append({
                    "id": s["id"], "label": s["label"], "expected": expected,
                    "check_only": check["decision"], "actual": final_decision,
                    "risk_score": check["risk_score"],
                    "story_status": story["story_status"] if story else "n/a",
                    "correct": correct,
                })

    # ---- report, in the exact style the plan asked for ----
    print(f"\n{len(results)} scenarios evaluated")
    correct_count = sum(r["correct"] for r in results)
    print(f"{correct_count} correct final decisions")

    false_high_risk = [r for r in results if r["label"] == "genuine" and r["actual"] != "PROCEED"]
    print(f"{len(false_high_risk)} false positive(s) — genuine requests not left at PROCEED")
    false_negatives = [r for r in results if r["label"] == "fraudulent" and r["actual"] != "HOLD"]
    print(f"{len(false_negatives)} false negative(s) — fraudulent requests not caught at HOLD")

    caught_only_by_story = [
        r for r in results
        if r["correct"] and r["check_only"] != r["expected"] and r["story_status"] == "INCONSISTENT"
    ]
    print(f"{len(caught_only_by_story)} case(s) caught only by reconstruct_trust_story "
          f"(check_trust alone would have missed them)")

    print("\nDetail:")
    for r in results:
        mark = "OK " if r["correct"] else "!! "
        flag = "  <- caught by story check, not check_trust" if r in caught_only_by_story else ""
        print(f"{mark}#{r['id']:>2}  label={r['label']:<11}  expected={r['expected']:<8}  "
              f"check_trust={r['check_only']:<8}  story={r['story_status']:<12}  "
              f"final={r['actual']:<8}  risk={r['risk_score']}{flag}")

    if not all(r["correct"] for r in results):
        print("\nMisses — review these before writing up final numbers:")
        for r in results:
            if not r["correct"]:
                print(f"  #{r['id']}: expected {r['expected']}, got {r['actual']} "
                      f"(check_trust={r['check_only']}, story={r['story_status']}, risk {r['risk_score']})")

    print("\nNot tested by this script — real gaps, not implemented yet:")
    print("  - Employee correction handling (no such feature exists yet)")
    print("  - Tool/Bedrock failure recovery (would require deliberately breaking")
    print("    a working connection; not simulated here)")


if __name__ == "__main__":
    asyncio.run(run_evaluation())
