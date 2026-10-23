"""One-off check that Bedrock Titan embeddings work with your AWS credentials
and that the 0.80 similarity threshold in trust_server.py makes sense.

Run:  python check_embeddings.py

Prints the cosine similarity for reworded-same-ask pairs (should be HIGH,
ideally above 0.80) and unrelated pairs (should be clearly LOWER). If the
numbers overlap, change EMBED_SIMILARITY_THRESHOLD (env var) to sit between them.
"""
import json
import boto3

MODEL_ID = "amazon.titan-embed-text-v2:0"
client = boto3.client("bedrock-runtime", region_name="us-east-1")


def embed(text):
    resp = client.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps({"inputText": text, "dimensions": 256, "normalize": True}),
        contentType="application/json", accept="application/json",
    )
    return json.loads(resp["body"].read())["embedding"]


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    return dot / ((sum(x * x for x in a) ** 0.5) * (sum(y * y for y in b) ** 0.5))


SAME_ASK = [
    ("Hi, this is IT. Please read me the 6-digit code we just texted you.",
     "Helpdesk here - kindly share the verification number sent to your phone."),
    ("IT support: we need your one-time password to fix a login problem.",
     "This is the IT team, send me the OTP that just arrived on your mobile."),
]
DIFFERENT = [
    ("Hi, this is IT. Please read me the 6-digit code we just texted you.",
     "Your October payslip is ready to view in the portal."),
    ("IT support: we need your one-time password to fix a login problem.",
     "Reminder: submit your timesheets by Friday."),
    ("Hi, this is IT. Please read me the 6-digit code we just texted you.",
     "Your IT ticket 4521 has been resolved, no action needed."),
]

for title, pairs in (("REWORDED SAME ASK (want high)", SAME_ASK),
                     ("DIFFERENT MESSAGES (want clearly lower)", DIFFERENT)):
    print(title)
    for a, b in pairs:
        print(f"  {cosine(embed(a), embed(b)):.3f}   {a[:42]!r} vs {b[:42]!r}")
