__artifacts_v2__ = {
    "Messages": {
        "name": "Messages",
        "description": "Extracts messages from Telegram",
        "author": "@WriteBlocked - Hiller Hoover",
        "version": "0.1",
        "date": "2026-04-06",
        "requirements": "none",
        "category": "Really cool artifacts",
        "notes": "",
        "paths": ('*/com.android.cooldata/databases/database*.db',),
        "function": "get_cool_data1"
    },
    "User Config Data": {
        "name": "User Config Data",
        "description": "Extracts User config data from userconfing.xml",
        "author": "@WriteBlocked - Hiller Hoover",
        "version": "0.1",
        "date": "2026-04-10",
        "requirements": "none",
        "category": "Really cool artifacts",
        "notes": "",
        "paths": ('*/com.android.cooldata/files/cool.xml',),
        "function": "get_cool_data2"
    },
    "Telegram Media": {
        "name": "Telegram Media",
        "description": "Extracts Telegram Media",
        "author": "@WriteBlocked - Hiller Hoover",
        "version": "0.1",
        "date": "2026-04-10",
        "requirements": "none",
        "category": "Really cool artifacts",
        "notes": "",
        "paths": ('*/com.android.cooldata/files/cool.xml',),
        "function": "get_cool_data2"
    }
}

"""
This is a 
Version history:

4/6/2026: Cloned aLEAPP, set up pycharm for editing. started creating functions.
4/7/2026: added userconfing.xml parsing.  
4/9/2026: added primitives for TLObject parsing.

TODO:
improve blob parsing
figure out what version of telegram this works with.
    case switch at beginning to output warning to ALEAPP report for unsupported versions.


NOTE:
this parser only supports one user, the active one. 
Also, I did not have a full set of test data to parse artifacts like drafts. 
in the event i didnt understand the relevance of an artifact I didn't include it. 
I can add more upon request if necessary. 
"""
#this import is used to add to the HTML report.
from scripts.artifact_report import ArtifactHtmlReport

# what functions do i need to import from aLEAPP? possible functions from the WhatsApp parser below.
from scripts.ilapfuncs import logfunc, tsv, timeline, open_sqlite_db_readonly, does_column_exist_in_db, media_to_html

from datetime import datetime, timezone
import sqlite3
import hashlib
import base64
import xml.etree.ElementTree as ET
from scripts.artifact_report import ArtifactHtmlReport
from scripts.filetype import types
import scripts.ilapfuncs
import io
import struct

#not sure I'm going to use Telethon. It doesn't seem to have the most modern constructors.
from telethon.extensions import BinaryReader as BR, BinaryReader
from telethon.tl.alltlobjects import tlobjects
from telethon.tl import TLObject

def get_cool_data1(files_found, report_folder, seeker, wrap_text):
    rows = [
     (datetime.datetime.now(), "Cool data col 1, value 1", "Cool data col 1, value 2", "Cool data col 1, value 3"),
     (datetime.datetime.now(), "Cool data col 2, value 1", "Cool data col 2, value 2", "Cool data col 2, value 3"),
    ]

    headers = ["Timestamp", "Data 1", "Data 2", "Data 3"]

    # HTML output:
    report = ArtifactHtmlReport("Cool stuff")
    report_name = "Cool DFIR Data"
    report.start_artifact_report(report_folder, report_name)
    report.add_script()
    report.write_artifact_data_table(headers, rows, files_found[0])  # assuming only the first file was processed
    report.end_artifact_report()

    # TSV output:
    scripts.ilapfuncs.tsv(report_folder, headers, rows, report_name, files_found[0])  # assuming first file only

    # Timeline:
    scripts.ilapfuncs.timeline(report_folder, report_name, rows, headers)

def parse_cache4db(cache4db_path):

    results = []

    def table_exists(conn, name):
        cur = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,)
        )
        return cur.fetchone() is not None

    def read_u32(buf, off):
        if off + 4 > len(buf):
            raise ValueError("read_u32 past end")
        return struct.unpack_from("<I", buf, off)[0], off + 4

    def read_i32(buf, off):
        if off + 4 > len(buf):
            raise ValueError("read_i32 past end")
        return struct.unpack_from("<i", buf, off)[0], off + 4

    def read_i64(buf, off):
        if off + 8 > len(buf):
            raise ValueError("read_i64 past end")
        return struct.unpack_from("<q", buf, off)[0], off + 8

    def read_tl_bytes(buf, off):
        if off >= len(buf):
            raise ValueError("read_tl_bytes past end")

        first = buf[off]
        off += 1

        if first < 254:
            length = first
            if off + length > len(buf):
                raise ValueError("short tl bytes")
            value = buf[off:off + length]
            off += length
            consumed = 1 + length
        else:
            if off + 3 > len(buf):
                raise ValueError("short tl long bytes header")
            length = buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16)
            off += 3
            if off + length > len(buf):
                raise ValueError("short tl long bytes body")
            value = buf[off:off + length]
            off += length
            consumed = 4 + length

        pad = (4 - (consumed % 4)) % 4
        off += pad
        return value, off

    def read_tl_string(buf, off):
        raw, off = read_tl_bytes(buf, off)
        return raw.decode("utf-8", errors="replace"), off

    def unix_to_iso(ts):
        try:
            return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(ts)

    def printable_runs(buf, min_len=4):
        out = []
        cur = bytearray()
        for b in buf:
            if 32 <= b <= 126:
                cur.append(b)
            else:
                if len(cur) >= min_len:
                    out.append(cur.decode("utf-8", errors="ignore"))
                cur = bytearray()
        if len(cur) >= min_len:
            out.append(cur.decode("utf-8", errors="ignore"))
        return out

    def parse_message_blob(blob):
        """
        Best-effort parser.
        Returns constructor always if possible.
        Tries to recover text and a few obvious fields without pretending
        every Telegram version uses the same layout.
        """
        parsed = {
            "constructor": None,
            "text": None,
            "strings": [],
            "parse_note": "",
        }

        if not blob or len(blob) < 4:
            parsed["parse_note"] = "empty or too short"
            return parsed

        try:
            off = 0
            constructor, off = read_u32(blob, off)
            parsed["constructor"] = hex(constructor)

            # First pass: collect visible strings no matter what
            strings = printable_runs(blob)
            parsed["strings"] = strings[:10]

            # Second pass: best-effort TL walk.
            # We do NOT assume one exact message schema for every Telegram build.
            # Instead, we scan for the longest plausible TL string after the constructor.
            best_text = None
            best_len = 0

            scan_off = 4
            while scan_off < min(len(blob), 512):
                try:
                    s, _ = read_tl_string(blob, scan_off)
                    s_clean = s.strip()
                    if len(s_clean) > best_len and any(ch.isalpha() for ch in s_clean):
                        best_text = s_clean
                        best_len = len(s_clean)
                except Exception:
                    pass
                scan_off += 1

            if best_text:
                parsed["text"] = best_text
                parsed["parse_note"] = "best-effort TL string hit"
            elif strings:
                # fallback: longest printable run
                parsed["text"] = max(strings, key=len)
                parsed["parse_note"] = "fallback printable run"
            else:
                parsed["parse_note"] = "no text recovered"

        except Exception as e:
            parsed["parse_note"] = f"blob parse failed: {e!r}"

        return parsed

    conn = sqlite3.connect(cache4db_path)
    conn.row_factory = sqlite3.Row

    try:
        if not table_exists(conn, "messages_v2"):
            return results

        # Optional lookup maps. If these tables/columns differ on your sample, just adjust here.
        user_map = {}
        chat_map = {}

        if table_exists(conn, "users"):
            try:
                cur = conn.execute("SELECT uid, name FROM users")
                for row in cur:
                    user_map[row["uid"]] = row["name"]
            except Exception:
                pass

        if table_exists(conn, "chats"):
            try:
                cur = conn.execute("SELECT uid, name FROM chats")
                for row in cur:
                    chat_map[row["uid"]] = row["name"]
            except Exception:
                pass

        cur = conn.execute("""
            SELECT
                mid,
                uid,
                read_state,
                send_state,
                date,
                data,
                ttl,
                media,
                replydata,
                imp,
                mention,
                forwards,
                replies_data,
                thread_reply_id,
                is_channel,
                reply_to_message_id,
                custom_params,
                group_id,
                reply_to_story_id
            FROM messages_v2
            ORDER BY date
        """)

        for row in cur:
            blob_info = parse_message_blob(row["data"])

            uid = row["uid"]
            peer_name = user_map.get(uid) or chat_map.get(uid) or ""

            results.append({
                "mid": row["mid"],
                "uid": uid,
                "peer_name": peer_name,
                "date_iso": unix_to_iso(row["date"]),
                "read_state": row["read_state"],
                "send_state": row["send_state"],
                "media": row["media"],
                "imp": row["imp"],
                "mention": row["mention"],
                "forwards": row["forwards"],
                "thread_reply_id": row["thread_reply_id"],
                "is_channel": row["is_channel"],
                "reply_to_message_id": row["reply_to_message_id"],
                "group_id": row["group_id"],
                "reply_to_story_id": row["reply_to_story_id"],
                "constructor": blob_info["constructor"],
                "message_text": blob_info["text"] or "",
                "parse_note": blob_info["parse_note"],
                "visible_strings": " | ".join(blob_info["strings"]),
                "has_replydata": 1 if row["replydata"] else 0,
                "has_replies_data": 1 if row["replies_data"] else 0,
                "has_custom_params": 1 if row["custom_params"] else 0,
            })

    finally:
        conn.close()

    return results

def parse_userconfig_xml(files_found, report_folder=1, seeker=1, wrap_text=1):
    # temporarily giving default arguments, will remove before production

    #report = ArtifactHtmlReport("Telegram - User Preferences")
    #report.start_artifact_report(report_folder, "Telegram - User Preferences")
    tree = ET.parse(files_found)
    root = tree.getroot()

    targets = {
        "appLocked",
        "passcodeType",
        "hasSecureData",
        "user",
        "lastContactsSyncTime",
        "last_call_time",
        "last_call_phone_number"
        "selectedAccount",
        "autoLockIn",
        "loginTime",
        "sharingMyLocationUntil",
        "badPasscodeTries",
        "appUpdateBuild",
        "contactsSavedCount",
        # Optional extras worth reporting if present:
        "syncContacts",
        "suggestContacts",
        "showCallsTab",
        "useFingerprint",
        "passcodeRetryInMs",
        "lastPauseTime",
    }

    results = {}

    for child in root:
        name = child.attrib.get("name")
        if name in targets:
            value = child.attrib.get("value")
            if value is None:
                value = (child.text or "").strip()
            results[name] = value

    # used for debugging, will remove.
    # for name, value in results.items():
    #     print(f"{name}: {value}")

    # Creating dictionary for user info.
    user_info = {
        "user_id": "",
        "first_name": "",
        "last_name": "",
        "username": "",
        "phone": "",
    }

    if "user" in results and results["user"]:
        raw = base64.b64decode(results["user"])
        f = io.BytesIO(raw)

        constructor = read_int32(f)
        if constructor == 0x215C4438:
            flags = read_int32(f)
            flags2 = read_int32(f)  # not used directly, but should be ingested.
            user_info["user_id"] = read_int64(f)

            # Fields must be in the exact order Telegram writes them.
            # Refer to: https://core.telegram.org/constructor/user
            if flag_set(flags, 0):  # This bit is for access_hash; not relevant to ALEAPP output.
                _ = read_int64(f)
            if flag_set(flags, 1):
                user_info["first_name"] = read_tl_string(f)
            if flag_set(flags, 2):
                user_info["last_name"] = read_tl_string(f)
            if flag_set(flags, 3):
                user_info["username"] = read_tl_string(f)
            if flag_set(flags, 4):
                user_info["phone"] = read_tl_string(f)
        else:
            print(f"Unsupported Telegram user constructor: 0x{constructor:08x}")
            # This constructor appears to have been changed in 2024, so I am unsure how long this constructor will work.
            # Future work on this plugin should focus on adding support for more constructors for compatability.
            # Per https://github.com/danog/schemas/blob/master/TL_telegram_v172.tl

    passcode_type_raw = results.get("passcodeType")
    if passcode_type_raw == 0:
        passcode_type_display = "PIN"
    elif passcode_type_raw == 1:
        passcode_type_display = "Password"
    elif passcode_type_raw in ("0", "1"):
        passcode_type_display = "PIN" if str(passcode_type_raw) == "0" else "Password"
    elif passcode_type_raw is None:
        passcode_type_display = ""
    else:
        passcode_type_display = f"Unknown ({passcode_type_raw})"

    app_locked_display = "Enabled" if results.get("appLocked") is True else "Disabled" if results.get(
        "appLocked") is False else ""
    has_secure_data_display = "Present" if results.get("hasSecureData") is True else "Not Present" if results.get(
        "hasSecureData") is False else ""

    auto_lock_value = results.get("autoLockIn")
    if isinstance(auto_lock_value, int):
        if auto_lock_value == 0:
            auto_lock_display = "Disabled / immediate value 0"
        elif auto_lock_value < 60:
            auto_lock_display = f"{auto_lock_value} seconds"
        elif auto_lock_value % 3600 == 0:
            auto_lock_display = f"{auto_lock_value // 3600} hour(s)"
        elif auto_lock_value % 60 == 0:
            auto_lock_display = f"{auto_lock_value // 60} minute(s)"
        else:
            auto_lock_display = f"{auto_lock_value} seconds"
    else:
        auto_lock_display = str(auto_lock_value or "")

    # Build rows for ALEAPP.
    data_list = []

    # Account identity from serialized user blob
    data_list.append(("Telegram User ID", user_info["user_id"], "Current Telegram account identifier"))
    data_list.append(("First Name", user_info["first_name"], "Current Telegram account first name"))
    data_list.append(("Last Name", user_info["last_name"], "Current Telegram account last name"))
    data_list.append(("Username", user_info["username"], "Current Telegram account username"))
    data_list.append(("Phone Number", user_info["phone"], "Current Telegram account phone number"))

    # Config values from userconfing.xml
    data_list.append(("App Lock", app_locked_display, "Whether Telegram app lock was enabled"))
    data_list.append(("Passcode Type", passcode_type_display, "App lock mode used by Telegram"))
    data_list.append(("Has Secure Data", has_secure_data_display, "Whether Telegram stored secure data state"))
    data_list.append(("Selected Account", results.get("selectedAccount", ""), "Active Telegram account slot on device"))
    data_list.append(("Auto Lock Interval", auto_lock_display, "Configured Telegram app auto-lock interval"))
    data_list.append(
        ("Bad Passcode Tries", results.get("badPasscodeTries", ""), "Recorded failed Telegram passcode attempts"))
    data_list.append(
        ("Login Time (UTC)", unix_to_iso(results.get("loginTime")), "Stored Telegram login/account timestamp"))
    data_list.append(("Last Contacts Sync Time (UTC)", unix_to_iso(results.get("lastContactsSyncTime")),
                      "Last Telegram contacts synchronization time"))
    data_list.append(("Sharing My Location Until (UTC)", unix_to_iso(results.get("sharingMyLocationUntil")),
                      "Live location sharing end time if non-zero"))
    data_list.append(
        ("Contacts Saved Count", results.get("contactsSavedCount", ""), "Saved/imported contacts count metadata"))
    data_list.append(("App Update Build", results.get("appUpdateBuild", ""), "Telegram app update build metadata"))
    data_list.append(
        ("Last Call Time (UTC)", unix_ms_to_iso(results.get("last_call_time")), "Call-related timestamp if present"))

    # Optional extras if present
    if "syncContacts" in results:
        data_list.append(("Sync Contacts", results.get("syncContacts"), "Whether contact synchronization was enabled"))
    if "suggestContacts" in results:
        data_list.append(
            ("Suggest Contacts", results.get("suggestContacts"), "Whether Telegram contact suggestions were enabled"))
    if "showCallsTab" in results:
        data_list.append(("Show Calls Tab", results.get("showCallsTab"), "Whether the calls tab was enabled"))
    if "useFingerprint" in results:
        data_list.append(("Use Fingerprint", results.get("useFingerprint"),
                          "Whether fingerprint unlock was enabled for Telegram app lock"))
    if "passcodeRetryInMs" in results:
        data_list.append(
            ("Passcode Retry Delay (ms)", results.get("passcodeRetryInMs"), "Current Telegram lockout/backoff delay"))
    if "lastPauseTime" in results:
        data_list.append(
            ("Last Pause Time", results.get("lastPauseTime"), "Last pause time used by Telegram for lock timing"))

    # Debug print for now
    for row in data_list:
        print(row)

    # Replace this with your ALEAPP writer later.
    return data_list

def parse_media():
    pass

def read_int32(f):
    """
    Read a 32-bit little-endian integer from the current stream position.

    Telegram TL serialization uses little-endian integers for constructor IDs,
    flags fields, message IDs, dates, and many other values.
    """
    data = f.read(4)
    if len(data) != 4:
        raise EOFError("Could not read int32")
    return struct.unpack("<I", data)[0]

def read_int64(f):
    """
    Read a 64-bit little-endian integer from the current stream position.

    Telegram uses 64-bit integers for some IDs and access hashes.
    """
    data = f.read(8)
    if len(data) != 8:
        raise EOFError("Could not read int64")
    return struct.unpack("<q", data)[0]

def read_tl_string(f):
    """
    Read a Telegram TL-encoded string.

    Telegram strings are not plain null-terminated strings.
    They use TL encoding:

    - If the first byte is less than 254, that byte is the string length
    - If the first byte is 254, the next 3 bytes store the length
    - Then comes the string data
    - Then padding is added so the total string field ends on a 4-byte boundary
    """
    first = f.read(1)
    if not first:
        raise EOFError("Could not read TL string length")

    l = first[0]
    if l == 254:
        l = int.from_bytes(f.read(3), "little")
        header_len = 4
    else:
        header_len = 1

    data = f.read(l)
    if len(data) != l:
        raise EOFError("Could not read TL string body")

    padding = (4 - ((header_len + l) % 4)) % 4
    if padding:
        f.read(padding)

    return data.decode("utf-8", errors="replace")

def flag_set(value, bit):
    """
    Check whether a specific bit is set in a Telegram flags integer.

    Telegram uses bit flags to indicate whether optional fields exist.
    Example:
    - if bit 1 is set, first_name exists
    - if bit 4 is set, phone exists

    Telegram also relies heavily on flags for cache4.db messages.
    """
    return (value & (1 << bit)) != 0

def unix_to_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None

def unix_ms_to_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc).isoformat()
    except Exception:
        return None

def read_bytes(f, n):
    data = f.read(n)
    if len(data) != n:
        raise EOFError(f"Could not read {n} bytes")
    return data

def read_int32_signed(f):
    data = f.read(4)
    if len(data) != 4:
        raise EOFError("Could not read int32")
    return struct.unpack("<i", data)[0]

def read_int64_unsigned(f):
    data = f.read(8)
    if len(data) != 8:
        raise EOFError("Could not read int64")
    return struct.unpack("<Q", data)[0]

if __name__ == '__main__':

    cache4dbPath= "H:\\Android_14_Public_Image.tar\\Android_14_Public_Image\\UFED Google Pixel 7a 2024_07_28 (001)\\EXTRACTION_FFS 01\\EXTRACTION_FFS\\Dump\\data\\data\\org.telegram.messenger\\files\\cache4.db"
    from collections import Counter


    def inventory_message_constructors(db_path):
        counts = Counter()

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("SELECT data FROM messages_v2 WHERE data IS NOT NULL")
        for (blob,) in cur.fetchall():
            if blob and len(blob) >= 4:
                constructor = struct.unpack("<I", blob[:4])[0]
                counts[f"0x{constructor:08x}"] += 1

        conn.close()
        return counts
    print(inventory_message_constructors(cache4dbPath))

    # results = parse_cache4db(cache4dbPath)
    #
    # for i, row in enumerate(results[:10], 1):
    #     print(f"\n--- Record {i} ---")
    #     print("date:", row.get("date_iso"))
    #     print("mid:", row.get("mid"))
    #     print("uid:", row.get("uid"))
    #     print("peer_name:", row.get("peer_name"))
    #     print("out:", row.get("out"))
    #     print("media:", row.get("media"))
    #     print("ttl:", row.get("ttl"))
    #     print("constructor:", row.get("constructor"))
    #     print("message_text:", row.get("message_text"))
    #     print("visible_strings:", row.get("visible_strings"))
    #     print("parse_note:", row.get("parse_note"))
    #     print("blob_head:", row.get("blob_head"))

    userconfigXMLPath = "H:\\Android_14_Public_Image.tar\\Android_14_Public_Image\\UFED Google Pixel 7a 2024_07_28 (001)\\EXTRACTION_FFS 01\\EXTRACTION_FFS\\Dump\\data\\data\\org.telegram.messenger\\shared_prefs\\userconfing.xml"
    parse_userconfig_xml(userconfigXMLPath)