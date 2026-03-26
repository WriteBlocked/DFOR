""" DFOR 772
    Hiller Hoover """

version = '0.1'

""" Change Log:
    03/20/2026: copied template and began defining modules."""

"""TODO:
    add timeline functionality
    create GUI"""

from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import argparse
from datetime import datetime
import csv


def parse_arguments():
    parser = argparse.ArgumentParser(description="EVTX Parser Tool")

    parser.add_argument("file", help="Path to EVTX file")
    parser.add_argument("--eventid", help="Filter by Event ID")
    parser.add_argument("--provider", help="Filter by Provider")
    parser.add_argument("--keyword", help="Search keyword")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    parser.add_argument("--timeline", action="store_true", help="Generate timeline")
    parser.add_argument("--export", help="Export timeline to CSV")

    return parser.parse_args()


def parse_evtx(file_path):
    events = []

    with Evtx(file_path) as log:
        for record in log.records():
            xml = record.xml()
            root = ET.fromstring(xml)

            event = {
                "EventID": root.find(".//EventID").text if root.find(".//EventID") is not None else None,
                "TimeCreated": root.find(".//TimeCreated").attrib.get("SystemTime") if root.find(".//TimeCreated") is not None else None,
                "Provider": root.find(".//Provider").attrib.get("Name") if root.find(".//Provider") is not None else None,
                "Message": xml
            }

            events.append(event)

    return events


def filter_events(events, event_id=None, provider=None, keyword=None):
    results = []

    for e in events:
        if event_id and e["EventID"] != str(event_id):
            continue
        if provider and provider.lower() not in (e["Provider"] or "").lower():
            continue
        if keyword and keyword.lower() not in e["Message"].lower():
            continue

        results.append(e)

    return results


# ---------------- TIMELINE ---------------- #

def normalize_events(events):
    timeline = []

    for e in events:
        try:
            ts = e["TimeCreated"]
            if not ts:
                continue

            timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            continue

        timeline.append({
            "timestamp": timestamp,
            "event_id": e["EventID"],
            "provider": e["Provider"]
        })

    return timeline


def build_timeline(events):
    timeline = normalize_events(events)
    timeline.sort(key=lambda x: x["timestamp"])
    return timeline


def summarize_event(event_id):
    mapping = {
        "4624": "Successful Logon",
        "4625": "Failed Logon",
        "4688": "Process Created",
        "7045": "Service Installed"
    }
    return mapping.get(event_id, "Other")


def print_timeline(timeline):
    for e in timeline:
        summary = summarize_event(e["event_id"])
        print(f"{e['timestamp']} | {summary} | {e['provider']} | EventID {e['event_id']}")


def export_timeline(timeline, filename):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "EventID", "Provider", "Summary"])

        for e in timeline:
            writer.writerow([
                e["timestamp"],
                e["event_id"],
                e["provider"],
                summarize_event(e["event_id"])
            ])


# ---------------- CLI ---------------- #

def run_cli(args):
    events = parse_evtx(args.file)

    # Apply filters first
    filtered = filter_events(events, args.eventid, args.provider, args.keyword)

    # Timeline mode
    if args.timeline:
        timeline = build_timeline(filtered)

        if args.export:
            export_timeline(timeline, args.export)
            print(f"[+] Timeline exported to {args.export}")
        else:
            print_timeline(timeline)

    # Normal output
    else:
        for e in filtered:
            print(f"[{e['TimeCreated']}] {e['Provider']} (ID {e['EventID']})")


def main():
    args = parse_arguments()
    run_cli(args)


if __name__ == '__main__':
    main()