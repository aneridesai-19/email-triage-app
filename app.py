
import os
import re
import streamlit as st
from dotenv import load_dotenv
import mailparser
from openai import OpenAI
from email.utils import parsedate_to_datetime
from html import unescape
from pyairtable import Table
from urllib.parse import urlparse

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Airtable credentials
airtable_api_key = os.getenv("AIRTABLE_API_KEY")
airtable_base_id = os.getenv("AIRTABLE_BASE_ID")
airtable_table_name = os.getenv("AIRTABLE_TABLE_NAME")

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

def extract_initial_message(body):
    separators = [
        r"\n[-]+\s?Original Message\s?[-]+\n",
        r"\nOn .*?wrote:\n",
        r"\nFrom: .*?\nTo: .*?\nSubject: .*?\n",
        r"\n__+ Forwarded message __+"
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
    return min(dates).strftime("%Y-%m-%d") if dates else "Unknown"

# def extract_builder_message_only(body):
#     messages = re.split(r"\n+From: ", body, flags=re.IGNORECASE)
#     for msg in reversed(messages):
#         if "jason.morgan@pulte.com" in msg.lower() or "build quality confirmation" in msg.lower():
#             return "From: " + msg.strip()
#     return messages[-1].strip()
def extract_builder_message_only(body):
    messages = re.split(r"\n+From: ", body, flags=re.IGNORECASE)
    
    # Look for highly specific known builder indicators first
    for msg in reversed(messages):
        if any(keyword in msg.lower() for keyword in [
            "jason.morgan@pulte.com", "build quality confirmation"
        ]):
            return "From: " + msg.strip()
    
    # General builder domain check as fallback
    builder_domains = [d.lower() for d in KNOWN_BUILDER_DOMAINS.keys()]
    for msg in reversed(messages):
        full_msg = "From: " + msg.strip()
        if any(domain in full_msg.lower() for domain in builder_domains):
            return full_msg
    
    # Absolute fallback to oldest message
    return "From: " + messages[-1].strip() if messages else body.strip()


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


def extract_links(text):
    raw_links = re.findall(r'https?://[^\s<>"\'\]]+', text)
    cleaned = set()

    # Allow if ends in file OR matches whitelisted portal/report URLs
    VALID_EXTENSIONS = (".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff")

    # Whitelist key functional links even if not file-based
    WHITELIST_KEYWORDS = [
        "clipboard-portal-prd-nvr-app.azurewebsites.net/reports",  # Clipboard Reports
    ]

    # Known bad domains
    EXCLUDE_DOMAINS = {
        "letsignit.com", "ci3.googleusercontent.com", "mail-sig",
        "facebook.com", "instagram.com", "youtube.com",
        "linkedin.com", "twitter.com", "claytonhomes.com",
        "google.com", "aka.ms", "urldefense.proofpoint.com", "urldefense.com"
    }

    # Builder domains from known email suffixes
    builder_domains = {domain.replace("@", "").lower() for domain in KNOWN_BUILDER_DOMAINS.keys()}

    for link in raw_links:
        link = link.rstrip('.,;:!?)]\'">')
        parsed = urlparse(link)
        domain = parsed.netloc.lower().replace("www.", "")

        # Skip builder and excluded domains
        if any(bad in domain for bad in EXCLUDE_DOMAINS.union(builder_domains)):
            continue

        # Allow if it's a valid file link
        if any(link.lower().endswith(ext) for ext in VALID_EXTENSIONS):
            cleaned.add(link)
            continue

        # Allow if it's a functional app/report link (whitelisted)
        if any(keyword in link for keyword in WHITELIST_KEYWORDS):
            cleaned.add(link)

    return "\n".join(sorted(cleaned))


def clean_notes(notes_raw):
    if not notes_raw.strip():
        return ""
    lines = notes_raw.splitlines()
    cleaned = []
    for line in lines:
        line = line.strip("•- \t")
        if line:
            if len(lines) == 1 and '.' in line:
                sentences = [s.strip() for s in line.split('.') if s.strip()]
                cleaned.extend(sentences)
                break
            cleaned.append(line)
    cleaned = [n + ('' if n.endswith('.') else '.') for n in cleaned]
    return "\n".join(f"- {n}" for n in cleaned)

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
                "Repair Crew": None,
                "Scheduled Date": None,
                "Urgency": record["urgency"],
                "Shingle Color": record["shingle_color"] if is_valid_color(record["shingle_color"]) else None,
                "Handler": record["handler"],
                "Needs Follow-Up?": record["needs_follow_up"],
                "Additional Links": record["additional_links"]
            })
            success += 1
        except Exception as e:
            st.error(f"❌ Failed to send record: {e}")
    return success

# Streamlit UI
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
        additional_links = extract_links(clean_body)
        original_request = extract_builder_message_only(body)
        # Remove confidentiality notice and signature
        original_request = re.split(r"(?i)(confidentiality notice|thank you,|regards,)", original_request)[0].strip()

        prompt = f"""
You are an assistant that extracts structured repair information from builder punch list emails.
Only use the **original builder message** below (ignore all replies, confirmations, or messages from Karol/Yarimar or ICS).

Instructions:
- Extract the following fields using this format:
  Lot/Job Name: ...
  Builder Name: ...
  Home Street Address: 
  City: 
  State: 
  Zip Code: 
  Notes:
  - Bullet 1 (summarised).
  - Bullet 2 (summarised).
  Shingle Color: ...
  Handler: ...

Notes Field Instructions:
- Provide a summarised version of repair items (3–6 key bullets max).
- Group and condense similar items together.
- Avoid names, greetings, or signatures.
- Extract only punch list or repair requests made by the builder.
- Do not include status updates, confirmations, apologies, or repair completions.
- Exclude any messages from ICS, Karol, Yarimar, or similar repair staff.
- Keep bullets clear, complete, and professional (max 6).

If a field is unknown, leave it blank.

Subject: {subject}
From: {from_email}

Original Message:
\"\"\"
{original_request}
\"\"\"
"""


        try:
            res = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Extract fields like Notes, Handler, Shingle Color, and a short Summary of Notes. Use bullet points and keep formatting clean."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0
            )
            reply = res.choices[0].message.content.strip()
        except Exception as e:
            reply = f"❌ OpenAI Error: {str(e)}"


        # Parse fields robustly
        fields = {}
        current_key = None
        buffer = []

        for line in reply.splitlines():
            if ":" in line and not line.strip().startswith("-"):
                if current_key:
                    fields[current_key] = "\n".join(buffer).strip()
                k, v = line.split(":", 1)
                current_key = k.strip()
                buffer = [v.strip()]
            elif current_key:
                buffer.append(line.strip())
        if current_key:
            fields[current_key] = "\n".join(buffer).strip()

        notes = fields.get("Notes", "").strip()

        def get(k): return fields.get(k, "")

        builder_full = get("Builder Name")
        builder_short = detect_builder_from_emails(body)
        if not builder_short:
            builder_short = BUILDER_SHORTS.get(builder_full.strip(), "UNKNOWN")

        lot = get("Lot/Job Name").upper()
        if lot and not lot.startswith("LOT"):
            lot = "LOT " + lot
        if not lot:
            match = re.search(r"\bGA\d{5}\b", subject + clean_body)
            if match:
                lot = "LOT " + match.group()

        address = get("Home Street Address")
        city = get("City")
        state = get("State")
        zipc = get("Zip Code")
        cityzip = f"{city}, {state} {zipc}".strip(", ")

        urgency = map_urgency(body)
        shingle_color = get("Shingle Color")
        if not is_valid_color(shingle_color):
            shingle_color = ""

        raw_handler = get("Handler").lower()
        handler = "Karol" if "karol" in raw_handler else "Yarimar" if "yarimar" in raw_handler else None
        if not handler:
            if "karol" in from_email.lower(): handler = "Karol"
            elif "yarimar" in from_email.lower(): handler = "Yarimar"

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
            "needs_follow_up": needs_follow_up,
            "additional_links": additional_links
        })

        progress.info(f"Processed {i + 1}/{len(uploaded_files)}")
    progress.success("✅ All files parsed.")

if "results" in st.session_state:

    if st.button("📤 Send to Airtable"):
        count = send_to_airtable(st.session_state.results)
        st.success(f"✅ Successfully sent {count} record(s) to Airtable.")
