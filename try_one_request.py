"""Test ANY scenario you can think of, on the spot, with no CSV involved at
all. Just edit the variables below and run this file.

Needs the server running (python trust_server.py) in another window.

Run:  python try_one_request.py
"""
import asyncio
import json
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

# ============================================================
# EDIT THIS SECTION — type whatever scenario you're curious about
# ============================================================

# Which tool to try: "money" for a payment/invoice/transfer request
# (check_trust), or "access" for a password/MFA/login-link request
# (check_access_request).
SCENARIO_TYPE = "access"

# ---- for SCENARIO_TYPE = "access" ----
ACCESS_REQUEST = {
    "request_text": "Hi, this is IT, can you confirm your password so I can reset your VPN access?",
    "claimed_sender_role": "IT Support",
    "employee_name": "R. Al Mazrouei",   # must be a name from employees.csv
    "contact_used": "+971-99-999-9999",  # phone/email the message came through, or "" if unknown
    "link_domain": "",                    # domain of any link in the message, or "" if none
}

# ---- for SCENARIO_TYPE = "money" ----
MONEY_REQUEST = {
    "request_text": "Please wire 50000 AED to the usual account, approved as normal.",
    "claimed_sender": "S. Khan",         # must be a name/role from employees.csv
    "device": "Registered laptop",
    "location": "Abu Dhabi UAE",
    "time": "11:00",
    "amount_aed": 50000,
    "approval_chain": "Followed normal chain",
}

# ============================================================
# Nothing below this line needs editing
# ============================================================


async def main():
    async with streamable_http_client("http://127.0.0.1:8000/mcp") as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()

            # --- TEMP DEBUG: show exactly what the live server thinks this
            # tool's parameters are, to track down the "rejected arguments"
            # error. Safe to delete once that's solved. ---
            tools = await session.list_tools()
            for t in tools.tools:
                if t.name == "check_access_request":
                    print("SERVER-SIDE SCHEMA FOR check_access_request:")
                    print(json.dumps(t.input_schema, indent=2))
            # --- END TEMP DEBUG ---

            if SCENARIO_TYPE == "access":
                result = await session.call_tool("check_access_request", ACCESS_REQUEST)
            elif SCENARIO_TYPE == "money":
                result = await session.call_tool("check_trust", MONEY_REQUEST)
            else:
                print(f"SCENARIO_TYPE must be 'access' or 'money', got {SCENARIO_TYPE!r}")
                return

            check = json.loads(result.content[0].text)

            print(f"\nDECISION: {check['decision']}  (risk score {check['risk_score']})\n")
            print("Why:")
            for rule in check.get("rules_fired", []):
                print(f"  - {rule['rule']}: {rule['reason']}")
            if not check.get("rules_fired"):
                print("  (nothing fired - looks clean)")

            if check.get("manipulation_signals"):
                print(f"\nHow Nova read the wording: {check['manipulation_signals']}")

            if check.get("explanation"):
                print(f"\nPlain-language explanation: {check['explanation']}")
            if check.get("safe_resolution"):
                print(f"Safe next step: {check['safe_resolution']}")


if __name__ == "__main__":
    asyncio.run(main())
