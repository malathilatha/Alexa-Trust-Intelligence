"""Same idea as evaluate_scenarios.py, but for the access-request pipeline
(check_access_request) instead of the money pipeline (check_trust): someone
trying to get a password, an MFA code, a remote-access install, or a click
on a lookalike login link, instead of trying to move money.

Needs the server running (python trust_server.py) and a scenarios CSV in
this folder. By default this reads access_scenarios.csv (your unlabeled,
ad-hoc file). Pass a different path to measure against the labeled suite
instead, which is what the submission's detection/false-positive numbers
should come from:

    python evaluate_access_scenarios.py access_scenarios_labeled.csv

Works with or without a "label" column. check_access_request itself never
sees or needs the label either way - it's never sent in the tool call below.
If the CSV has a label, this script also grades the result against it
(so you get a "16/16 correct" count and a false-positive/false-negative
breakdown). If there's no label column, it just shows what the system
decided for each row, same decisions, no grading - this is what it looks
like on a real, unlabeled feed.

Run:  python evaluate_access_scenarios.py [path_to_csv]
"""
import asyncio
import csv
import json
import sys
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

EXPECTED_DECISION = {"genuine": "PROCEED", "suspicious": "REVIEW", "fraudulent": "HOLD"}


def load_scenarios(path="access_scenarios.csv"):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


async def run_evaluation():
    path = sys.argv[1] if len(sys.argv) > 1 else "access_scenarios.csv"
    scenarios = load_scenarios(path)
    results = []

    async with streamable_http_client("http://127.0.0.1:8000/mcp") as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()

            for s in scenarios:
                result = await session.call_tool("check_access_request", {
                    "request_text": s["request_text"],
                    "claimed_sender_role": s["claimed_sender_role"],
                    "employee_name": s["employee_name"],
                    "contact_used": s["contact_used"],
                    "link_domain": s["link_domain"],
                })
                check = json.loads(result.content[0].text)
                has_label = "label" in s and s["label"]
                expected = EXPECTED_DECISION[s["label"]] if has_label else None
                correct = (check["decision"] == expected) if has_label else None
                results.append({
                    "id": s["id"], "label": s.get("label", ""), "expected": expected,
                    "actual": check["decision"], "risk_score": check["risk_score"],
                    "rules_fired": check["rules_fired"], "correct": correct,
                })

    graded = results and results[0]["correct"] is not None

    if graded:
        print(f"\n{len(results)} access-request scenarios evaluated")
        correct_count = sum(r["correct"] for r in results)
        print(f"{correct_count} correct final decisions")
        false_high_risk = [r for r in results if r["label"] == "genuine" and r["actual"] != "PROCEED"]
        print(f"{len(false_high_risk)} false positive(s) — genuine requests not left at PROCEED "
              f"(this is the 'proves it isn't paranoid' check)")
        false_negatives = [r for r in results if r["label"] == "fraudulent" and r["actual"] != "HOLD"]
        print(f"{len(false_negatives)} false negative(s) — fraudulent requests not caught at HOLD")
    else:
        print(f"\n{len(results)} access-request scenarios run — no label column found, "
              f"so this is showing raw decisions only, not grading them.")

    print("\nDetail:")
    for r in results:
        if graded:
            mark = "OK " if r["correct"] else "!! "
            print(f"{mark}#{r['id']}  label={r['label']:<11}  expected={r['expected']:<8}  "
                  f"actual={r['actual']:<8}  risk={r['risk_score']}")
        else:
            print(f"#{r['id']}  decision={r['actual']:<8}  risk={r['risk_score']}")
        for rule in r["rules_fired"]:
            print(f"      - {rule['rule']}: {rule['reason']}")

    if graded and not all(r["correct"] for r in results):
        print("\nMisses:")
        for r in results:
            if not r["correct"]:
                print(f"  #{r['id']}: expected {r['expected']}, got {r['actual']} (risk {r['risk_score']})")


if __name__ == "__main__":
    asyncio.run(run_evaluation())
