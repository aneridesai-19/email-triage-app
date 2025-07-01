import os
import re
import streamlit as st
from dotenv import load_dotenv
import mailparser
from openai import OpenAI
from email.utils import parsedate_to_datetime
from html import unescape
from pyairtable import Table

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Airtable credentials
airtable_api_key = os.getenv("AIRTABLE_API_KEY")
airtable_base_id = os.getenv("AIRTABLE_BASE_ID")
airtable_table_name = os.getenv("AIRTABLE_TABLE_NAME")

# === Builder shortcuts and domains
BUILDER_SHORTS = {
    "Mungo Homes": "MUN", "Great Southern Homes": "GSH", "Ryan Homes": "RYAN",
    "Mag Custom Homes": "MAG", "David Weekly home": "DW", "Ashtonwood Homes": "ASHTON",
    "HAVEN HOMES": "HAVEN", "IVEY SOUTH CONSTRUCTION": "IVEY", "Pulte Homes": "PUL"
}

KNOWN_BUILDER_DOMAINS = {
    "@mungo.com": "MUN", "@pulte.com": "PUL", "@nvrinc.com": "RYAN",
    "@greatsouthernhomes.com": "GSH", "@magnoliacustomhomesofsc.com": "MAG",
    "@dwhomes.com": "DW", "@ashtonwoods.com": "ASHTON",
    "@havenhomessc.com": "HAVEN", "@iveygroup.com": "IVEY"
}

# === Helpers
def extract_initial_message(body):
    separators = [
        r"\n[-]+\s?Original Message\s?[-]+\n",
        r"\nOn .*? wrote:\n",
        r"\nFrom: .*?\n.*?\n",
        r"\n__+ Forwarded message __+",
    ]
    for sep in separators:
        parts = re.split(sep, body, flags=re.IGNORECASE)
        if parts and len(parts[0].strip()) > 20:
            return parts[0].strip()
    return body.strip()

def extract_earliest_email_date(body):
    sent_matches = re.findall(r"Sent:\s*(.*)", body, flags=re.IGNORECASE)
    dates = []
    for match in sent_matches:
        try:
            dt = parsedate_to_datetime(match.strip())
            if dt:
                dates.append(dt)
        except:
            continue
    if dates:
        return min(dates).strftime("%Y-%m-%d")
    return "Unknown"

def extract_address_from_signature(body):
    lines = body.strip().splitlines()[-20:]
    block = "\n".join(lines)
    match = re.search(r"(\d{3,6} .+?)\n([A-Za-z .]+),?\s+([A-Z]{2})\s+(\d{5})", block)
    if match:
        return {
            "address": match.group(1).strip(),
            "city": match.group(2).strip(),
            "state": match.group(3).strip(),
            "zip": match.group(4).strip()
        }
    return {}

def detect_builder_from_emails(body):
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", body)
    for email in emails:
        for domain, short in KNOWN_BUILDER_DOMAINS.items():
            if email.lower().endswith(domain):
                return short
    return ""

def map_urgency(text):
    text = text.lower()
    if any(w in text for w in ["48 hour", "asap", "urgent", "immediate", "back charge", "as soon as possible"]):
        return "High"
    if any(w in text for w in ["on the schedule", "few days", "soon"]):
        return "Medium"
    if any(w in text for w in ["no rush", "when available", "next week"]):
        return "Low"
    return "Medium"

def clean_text(val):
    return unescape(re.sub(r"<[^>]+>", "", val or "")).strip()

def is_valid_color(val):
    val = val.strip().lower()
    invalids = ["", "unknown", "n/a", "na", "-", "--", "[blank]", "[unknown]", "none", "not specified"]
    return val not in invalids

def send_to_airtable(records):
    table = Table(airtable_api_key, airtable_base_id, airtable_table_name)
    success = 0
    for record in records:
        try:
            table.create({
                "Email Date": record["email_date"],
                "Lot/Job Name": record["lot"],
                "Builder Name": record["builder"],
                "Home Street Address": record["address"],
                "City/State/Zip": record["cityzip"],
                "Notes": record["notes"],
                "Repair Crew": None,               # Leave blank
                "Scheduled Date": None,            # Fix: use None not ""
                "Urgency": record["urgency"],
                "Shingle Color": record["shingle_color"] if is_valid_color(record["shingle_color"]) else None,
                "Handler": record["handler"],
                "Needs Follow-Up?": record["needs_follow_up"]
            })
            success += 1
        except Exception as e:
            st.error(f"❌ Failed to send record: {e}")
    return success


# === Streamlit UI
st.set_page_config("📧 Email Triage to Airtable", layout="wide")
st.title("📧 Upload Repair Emails for Extraction")
uploaded_files = st.file_uploader("Upload `.eml` files", type="eml", accept_multiple_files=True)
progress = st.empty()

if uploaded_files and "results" not in st.session_state:
    st.session_state.results = []
    for i, file in enumerate(uploaded_files):
        raw = file.read()
        parsed = mailparser.parse_from_bytes(raw)
        subject = parsed.subject or ""
        from_email = parsed.from_[0][1] if parsed.from_ else "unknown"
        body = parsed.body.strip()
        clean_body = extract_initial_message(body)
        email_date = extract_earliest_email_date(clean_body)

        prompt = f"""
Extract the following fields from the email content. Leave blank if unknown.
Lot/Job Name:
Builder Name:
Home Street Address:
City:
State:
Zip Code:
Notes:
Shingle Color:
Handler: Karol or Yarimar
Subject: {subject}
From: {from_email}
---
{clean_body}
---
        """

        try:
            res = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Extract and return fields cleanly."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0
            )
            reply = res.choices[0].message.content.strip()
        except Exception as e:
            reply = f"❌ OpenAI Error: {str(e)}"

        fields = {}
        for line in reply.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip()] = clean_text(v.strip())

        def get(k): return fields.get(k, "")

        builder_full = get("Builder Name")
        builder_short = detect_builder_from_emails(body)
        if not builder_short:
            builder_short = "UNKNOWN"


        lot = get("Lot/Job Name").upper()
        if lot and not lot.startswith("LOT"):
            lot = "LOT " + lot

        address = get("Home Street Address")
        city = get("City")
        state = get("State")
        zipc = get("Zip Code")
        cityzip = f"{city}, {state} {zipc}".strip(", ")

        if not address or not city or not state or not zipc:
            sig = extract_address_from_signature(body)
            address = address or sig.get("address", "")
            city = city or sig.get("city", "")
            state = state or sig.get("state", "")
            zipc = zipc or sig.get("zip", "")
            cityzip = f"{city}, {state} {zipc}".strip(", ")

        notes = get("Notes")
        urgency = map_urgency(body)
        shingle_color = get("Shingle Color")
        if not is_valid_color(shingle_color):
            shingle_color = ""

        raw_handler = get("Handler").lower()
        if "karol" in raw_handler:
            handler = "Karol"
        elif "yarimar" in raw_handler:
            handler = "Yarimar"
        else:
            handler = None  # fallback to blank if not recognized

        needs_follow_up = "Yes" if not address or not city or not state or not zipc or not notes else "No"

        st.session_state.results.append({
            "email_date": email_date,
            "subject": subject,
            "from": from_email,
            "lot": lot,
            "builder": builder_short,
            "address": address,
            "cityzip": cityzip,
            "notes": notes,
            "repair_crew": "",
            "urgency": urgency,
            "shingle_color": shingle_color,
            "handler": handler,
            "needs_follow_up": needs_follow_up
        })

        progress.info(f"Processed {i + 1}/{len(uploaded_files)}")
    progress.success("✅ All files parsed.")

if "results" in st.session_state:
    

    if st.button("📤 Send to Airtable"):
        count = send_to_airtable(st.session_state.results)
        st.success(f"✅ Successfully sent {count} record(s) to Airtable.")
