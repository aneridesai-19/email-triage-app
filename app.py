import os
import re
import streamlit as st
from openai import OpenAI
from dotenv import load_dotenv
import mailparser
from email.utils import parsedate_to_datetime
import gspread
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from gspread_formatting import CellFormat, Color, format_cell_range, TextFormat
from time import sleep
import json

# Save secrets to file (so Google libraries can use them)
with open("oauth-credentials.json", "w") as f:
    f.write(st.secrets["OAUTH_CREDENTIALS_JSON"])

with open("token.json", "w") as f:
    f.write(st.secrets["TOKEN_JSON"])

# Load environment variables
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
GOOGLE_SHEET_ID = os.getenv("GOOGLE_SHEET_ID")
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

HEADERS = [
    "Email Date", "Lot/Job Name", "Builder Name",
    "Home Street Address", "City/State/Zip", "Notes", "Repair Crew",
    "Start Time", "Urgency", "Shingle Color", "Handler", "Needs Follow-Up?"
]

BUILDER_SHORTS = {
    "Mungo Homes": "MUN", "Great Southern Homes": "GSH", "Ryan Homes": "RYAN",
    "Mag Custom Homes": "MAG", "David Weekly home": "DW", "Ashtonwood Homes": "ASHTON",
    "HAVEN HOMES": "HAVEN", "IVEY SOUTH CONSTRUCTION": "IVEY", "Pulte Homes": "PUL"
}

KNOWN_BUILDER_DOMAINS = {
    "@mungo.com": "MUN", "@pulte.com": "PUL", "@nvrinc.com": "RYAN",
    "@greatsouthernhomes.com": "GSH", "@magcustomhomes.com": "MAG",
    "@davidweekleyhomes.com": "DW", "@ashtonwood.com": "ASHTON",
    "@havenhomes.com": "HAVEN", "@iveygroup.com": "IVEY"
}

BUILDER_COLORS = {
    "MUN": Color(0.8, 0.7, 0.9), "GSH": Color(1, 1, 0.6), "RYAN": Color(0.8, 1, 0.8),
    "MAG": Color(1, 0.8, 0.8), "DW": Color(1, 0.4, 0.4), "ASHTON": Color(0.96, 0.87, 0.7),
    "HAVEN": Color(0.8, 0.7, 0.9), "IVEY": Color(1, 0.8, 0.5), "PUL": Color(1, 0.75, 0.8)
}

URGENCY_COLORS = {
    "High": Color(0.9, 0.2, 0.2), "Medium": Color(1, 0.5, 0.5), "Low": Color(1, 0.7, 0.7)
}

FOLLOWUP_COLORS = {
    "Yes": Color(1, 0.8, 0.8), "No": Color(0.8, 1, 0.8)
}

def get_gsheet_client():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("oauth-credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return gspread.authorize(creds)

def extract_earliest_email_date(body):
    matches = re.findall(r"Sent:\s+(.+)", body, re.IGNORECASE)
    for m in matches:
        try:
            return parsedate_to_datetime(m.strip()).strftime("%Y-%m-%d")
        except:
            continue
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
    if any(w in text for w in ["48 hour", "asap", "urgent", "immediate", "back charge"]):
        return "High"
    if any(w in text for w in ["on the schedule", "few days", "soon"]):
        return "Medium"
    if any(w in text for w in ["no rush", "when available", "next week"]):
        return "Low"
    return "Medium"

def extract_start_time(body):
    matches = re.findall(r"(?:repair|schedule|scheduled|rescheduled).*?(\d{1,2}/\d{1,2}(?:/\d{2,4})?)", body, flags=re.IGNORECASE)
    return matches[0] if matches else ""

# Streamlit UI
st.set_page_config("📧 Email Triage", layout="wide")
st.title("📧 Upload Builder Repair Emails")
uploaded_files = st.file_uploader("Upload .eml files", type="eml", accept_multiple_files=True)
progress = st.empty()

if uploaded_files and "results" not in st.session_state:
    st.session_state.results = []
    for i, file in enumerate(uploaded_files):
        raw = file.read()
        parsed = mailparser.parse_from_bytes(raw)
        subject = parsed.subject or ""
        from_email = parsed.from_[0][1] if parsed.from_ else "unknown"
        body = parsed.body.strip()
        email_date = extract_earliest_email_date(body)

        prompt = f"""
Extract this info from the email. Leave fields blank if unknown (not "Not provided").

Lot/Job Name:
Builder Name:
Home Street Address:
City:
State:
Zip Code:
Notes:
Repair Crew:
Urgency:
Shingle Color:
Handler: Karol or Yarimar

Subject: {subject}
From: {from_email}

---
{body}
---
        """

        try:
            res = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "Extract and format the repair request fields cleanly."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            reply = res.choices[0].message.content.strip()
        except Exception as e:
            reply = f"❌ OpenAI Error: {str(e)}"

        st.session_state.results.append({
            "email_date": email_date,
            "extracted": reply,
            "raw_body": body
        })
        progress.info(f"Processed {i+1}/{len(uploaded_files)}")
    progress.success("✅ All files processed!")

if "results" in st.session_state and st.button("📤 Send to Google Sheet"):
    try:
        gc = get_gsheet_client()
        ss = gc.open_by_key(GOOGLE_SHEET_ID)
        try:
            sheet = ss.worksheet("Sheet1")
        except:
            sheet = ss.add_worksheet(title="Sheet1", rows="200", cols="50")

        if not sheet.get_all_values():
            sheet.insert_row(HEADERS, 1)

        write_progress = st.progress(0)
        total = len(st.session_state.results)

        for idx, result in enumerate(st.session_state.results):
            fields = {}
            for line in result["extracted"].splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fields[k.strip()] = v.strip()

            def get(k): return fields.get(k, "").strip()

            builder_short = BUILDER_SHORTS.get(get("Builder Name"), detect_builder_from_emails(result["raw_body"]))
            lot = get("Lot/Job Name")
            if lot and not lot.upper().startswith("LOT"):
                lot = "LOT " + lot

            address = get("Home Street Address")
            city, state, zipc = get("City"), get("State"), get("Zip Code")
            if not all([address, city, state, zipc]):
                sig = extract_address_from_signature(result["raw_body"])
                address = address or sig.get("address", "")
                city = city or sig.get("city", "")
                state = state or sig.get("state", "")
                zipc = zipc or sig.get("zip", "")
            cityzip = f"{city}, {state} {zipc}".strip(", ")

            notes = get("Notes")
            notes_lines = [line.strip() + ('' if line.strip().endswith('.') else '.') for line in notes.split('.') if line.strip()]
            notes = "\n".join(notes_lines)

            start_time = extract_start_time(result["raw_body"])
            urgency = map_urgency(get("Urgency") + " " + result["raw_body"])
            color = get("Shingle Color")
            handler = get("Handler")
            repair_crew = get("Repair Crew")
            follow_up = "Yes" if any(x.strip() == "" for x in [lot, builder_short, address, cityzip, notes]) else "No"

            row = [result["email_date"], lot, builder_short, address, cityzip, notes, repair_crew,
                   start_time, urgency, color, handler, follow_up]

            sheet.append_row(row, value_input_option="USER_ENTERED")
            sleep(2.5)
            last_row = len(sheet.get_all_values())

            colmap = {
                "Builder Name": builder_short,
                "Urgency": urgency,
                "Needs Follow-Up?": follow_up
            }

            for col, val in colmap.items():
                if val:
                    cidx = HEADERS.index(col) + 1
                    clr_map = BUILDER_COLORS if col == "Builder Name" else URGENCY_COLORS if col == "Urgency" else FOLLOWUP_COLORS
                    if val in clr_map:
                        format_cell_range(sheet, f"{chr(64+cidx)}{last_row}", CellFormat(
                            backgroundColor=clr_map[val],
                            textFormat=TextFormat(bold=True if col == "Builder Name" else False)
                        ))

            if handler.lower() == "yarimar":
                handler_col = HEADERS.index("Handler") + 1
                format_cell_range(sheet, f"{chr(64+handler_col)}{last_row}", CellFormat(
                    backgroundColor=Color(1, 1, 0.6)
                ))

            write_progress.progress((idx + 1) / total)

        st.success("✅ All data is saved in the google sheet.")
    except Exception as e:
        st.error(f"❌ Google Sheet Write Error: {e}")
