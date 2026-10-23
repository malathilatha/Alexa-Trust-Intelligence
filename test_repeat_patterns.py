"""Proves the three 'memory' rules work — the ones a flat CSV of single
requests can never test, because each one only exists across MULTIPLE
calls: a real attacker trying again after being held, using the session
scoping that keeps them apart from unrelated test cases.

1. repeat_pattern          — same session, second attempt looks different.
2. repeat_pattern_cross_session — a FRESH session_id each time (the
   evasion the report flagged: attacker just starts a new session to
   dodge the earlier hold) but same claimed identity.
3. repeat_target_access    — same idea on the access-request side, keyed
   on who's being TARGETED (employee_name) rather than who's calling,
   since the attacker's claimed role/contact can change every time.

Needs the server running (python trust_server.py) in another window, with
a FRESH trust_incidents.db (delete the old one first, or these calls will
mix with whatever history is already in it from earlier testing).

Run:  python test_repeat_patterns.py
"""
import asyncio
import json
import time
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def check(label, condition, detail=""):
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {label}" + (f" — {detail}" if detail else ""))
    return condition


async def main():
    all_passed = True
    async with streamable_http_client("http://127.0.0.1:8000/mcp") as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()

            # ---------------------------------------------------------
            # Test 1: repeat_pattern — same session, held once, retried
            # moments later with a different device/location. Neither
            # single request looks bad enough alone.
            # ---------------------------------------------------------
            print("\n=== Test 1: repeat_pattern (same session) ===")
            s1 = f"test1-{int(time.time())}"

            r1 = await session.call_tool("check_trust", {
                "request_text": "Need an urgent transfer approved, confidential.",
                "claimed_sender": "R. Al Mazrouei", "device": "Unknown device",
                "location": "Country not on file", "time": "02:15",
                "amount_aed": 500000, "approval_chain": "Skipped - went direct to accountant",
                "session_id": s1,
            })
            c1 = json.loads(r1.content[0].text)
            print(f"  attempt 1: decision={c1['decision']} risk={c1['risk_score']}")

            r2 = await session.call_tool("check_trust", {
                "request_text": "Please process the transfer we discussed now.",
                "claimed_sender": "R. Al Mazrouei", "device": "Registered laptop",
                "location": "Abu Dhabi UAE", "time": "11:00",
                "amount_aed": 50000, "approval_chain": "Followed normal chain",
                "session_id": s1,
            })
            c2 = json.loads(r2.content[0].text)
            print(f"  attempt 2 (clean-looking, same session): decision={c2['decision']} risk={c2['risk_score']}")
            fired_names_2 = {rl["rule"] for rl in c2["rules_fired"]}
            all_passed &= check(
                "attempt 2 caught by repeat_pattern despite looking clean on every other signal",
                "repeat_pattern" in fired_names_2,
                f"rules_fired={sorted(fired_names_2)}",
            )

            # ---------------------------------------------------------
            # Test 2: repeat_pattern_cross_session — a BRAND NEW session
            # id each time (the evasion attempt), same claimed identity.
            # ---------------------------------------------------------
            print("\n=== Test 2: repeat_pattern_cross_session (new session each time) ===")
            s2a = f"test2a-{int(time.time())}"
            r3 = await session.call_tool("check_trust", {
                "request_text": "Need an urgent transfer approved, confidential.",
                "claimed_sender": "P. Nazir", "device": "Unknown device",
                "location": "Country not on file", "time": "02:20",
                "amount_aed": 500000, "approval_chain": "Skipped - went direct to accountant",
                "session_id": s2a,
            })
            c3 = json.loads(r3.content[0].text)
            print(f"  attempt 1 (session {s2a}): decision={c3['decision']} risk={c3['risk_score']}")

            s2b = f"test2b-{int(time.time()) + 1}"  # deliberately a DIFFERENT session
            r4 = await session.call_tool("check_trust", {
                "request_text": "Please process the transfer we discussed now.",
                "claimed_sender": "P. Nazir", "device": "Registered laptop",
                "location": "Abu Dhabi UAE", "time": "11:05",
                "amount_aed": 50000, "approval_chain": "Followed normal chain",
                "session_id": s2b,
            })
            c4 = json.loads(r4.content[0].text)
            print(f"  attempt 2 (NEW session {s2b}, clean-looking): decision={c4['decision']} risk={c4['risk_score']}")
            fired_names_4 = {rl["rule"] for rl in c4["rules_fired"]}
            all_passed &= check(
                "attempt 2 caught by repeat_pattern_cross_session even with a brand-new session_id",
                "repeat_pattern_cross_session" in fired_names_4,
                f"rules_fired={sorted(fired_names_4)}",
            )

            # ---------------------------------------------------------
            # Test 3: repeat_target_access — same employee targeted twice,
            # different claimed role/contact each time, different sessions.
            # ---------------------------------------------------------
            print("\n=== Test 3: repeat_target_access (same target, different story, new session) ===")
            s3a = f"test3a-{int(time.time())}"
            r5 = await session.call_tool("check_access_request", {
                "request_text": "Hi this is IT, can you read me the code that was just sent to you?",
                "claimed_sender_role": "IT Support", "employee_name": "T. Fernandes",
                "contact_used": "+971-50-000-0000", "link_domain": "",
                "session_id": s3a,
            })
            a1 = json.loads(r5.content[0].text)
            print(f"  attempt 1 (session {s3a}): decision={a1['decision']} risk={a1['risk_score']}")

            s3b = f"test3b-{int(time.time()) + 1}"
            r6 = await session.call_tool("check_access_request", {
                "request_text": "Hi, it's your manager — can you quickly confirm you're online right now?",
                "claimed_sender_role": "Manager", "employee_name": "T. Fernandes",
                "contact_used": "+971-55-999-0000", "link_domain": "",
                "session_id": s3b,
            })
            a2 = json.loads(r6.content[0].text)
            print(f"  attempt 2 (NEW session {s3b}, different claimed role entirely): "
                  f"decision={a2['decision']} risk={a2['risk_score']}")
            fired_names_a2 = {rl["rule"] for rl in a2["rules_fired"]}
            all_passed &= check(
                "attempt 2 caught by repeat_target_access even with a different claimed role/contact",
                "repeat_target_access" in fired_names_a2,
                f"rules_fired={sorted(fired_names_a2)}",
            )

    print("\n" + ("ALL PASSED" if all_passed else "SOME FAILED — see above"))


if __name__ == "__main__":
    asyncio.run(main())
