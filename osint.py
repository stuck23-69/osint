#!/usr/bin/env python3
"""osint — small public-lookup CLI.

Edit the settings below. A platform value is either a URL template
({u} becomes the username) or a dict:

    url      template
    missing  text that means "no such account" (optional)
    absent   status codes that mean "no such account" (optional)

Only public pages are requested. ask / --auto talk to local Ollama.
"""

import argparse
import gzip
import ipaddress
import json
import re
import socket
import ssl
import sys
import textwrap
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests


# --- easy to change ---------------------------------------------------------

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "qwen2.5:1.5b"

SYSTEM_PROMPT = """You are a privacy-focused assistant reviewing OSINT results.
Use only the public information in the result the user provides.
Do not invent accounts, locations, identities, or relationships.
Do not guess private data: home addresses, phone numbers, emails, or workplaces that are not written in the result.
Do not add facts that are not in the result, such as a company's headquarters.
Say what the data shows and what it does not show.
Keep the answer short and practical."""

AUTO_QUESTION = (
    "Summarize this public result. What does it show, what is still unknown, "
    "and what privacy limits apply? Do not infer private details."
)

IP_API = "https://ipwho.is/{ip}"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

REQUEST_TIMEOUT = 12
BODY_LIMIT = 150_000
CHECK_WORKERS = 12
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050

# Challenge pages are not a yes or a no.
BLOCK_MARKERS = (
    "Just a moment...",
    "Attention Required",
    "cf-browser-verification",
)

# Public profile checks. Delete a line to skip a site.
# Status 404 (or "absent") means not present. A normal 200 means present,
# unless "missing" appears in the page.
PLATFORMS = {
    # code and packages
    "GitHub": "https://github.com/{u}",
    "GitHub Gist": "https://gist.github.com/{u}",
    "Codeberg": "https://codeberg.org/{u}",
    "Launchpad": {
        "url": "https://launchpad.net/~{u}",
        "missing": "does not use Launchpad",
    },
    "Docker Hub": "https://hub.docker.com/u/{u}",
    "RubyGems": "https://rubygems.org/profiles/{u}",
    "hex.pm": "https://hex.pm/users/{u}",
    "Packagist": "https://packagist.org/users/{u}/",
    "Read the Docs": "https://readthedocs.org/profiles/{u}/",
    "HackerOne": "https://hackerone.com/{u}",
    "Codewars": "https://www.codewars.com/users/{u}",
    "Kaggle": "https://www.kaggle.com/{u}",
    "Hugging Face": "https://huggingface.co/{u}",
    "Modrinth": "https://api.modrinth.com/v2/user/{u}",
    # blogs and links
    "Dev.to": "https://dev.to/{u}",
    "Hackaday": "https://hackaday.io/{u}",
    "Indie Hackers": "https://www.indiehackers.com/{u}",
    "Wellfound": "https://wellfound.com/u/{u}",
    "About.me": "https://about.me/{u}",
    "Linktree": "https://linktr.ee/{u}",
    "Neocities": "https://{u}.neocities.org",
    "Substack": "https://{u}.substack.com",
    "Gumroad": "https://gumroad.com/{u}",
    "Pastebin": "https://pastebin.com/u/{u}",
    "Hacker News": {
        "url": "https://news.ycombinator.com/user?id={u}",
        "missing": "No such user.",
    },
    # wikis and maps
    "Wikipedia": "https://en.wikipedia.org/wiki/User:{u}",
    "Wikidata": "https://www.wikidata.org/wiki/User:{u}",
    "OpenStreetMap": "https://www.openstreetmap.org/user/{u}",
    # social and media that answer 404 for a missing name
    "X": "https://x.com/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Flickr": "https://www.flickr.com/people/{u}",
    "Dribbble": "https://dribbble.com/{u}",
    "itch.io": "https://{u}.itch.io",
    "Mastodon": "https://mastodon.social/@{u}",
    "Pixelfed": "https://pixelfed.social/{u}",
    "Lemmy": "https://lemmy.world/api/v3/user?username={u}",
    "Bluesky": {
        "url": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
        "absent": (400, 404),
    },
    "Telegram": {
        "url": "https://t.me/{u}",
        "missing": "Telegram: Contact @",
    },
    "Keybase": "https://keybase.io/{u}",
    # games and entertainment
    "Chess.com": "https://www.chess.com/member/{u}",
    "Lichess": "https://lichess.org/api/user/{u}",
    "Scratch": "https://scratch.mit.edu/users/{u}",
    "MyAnimeList": "https://myanimelist.net/profile/{u}",
    "Wattpad": "https://www.wattpad.com/user/{u}",
    "Spotify": "https://open.spotify.com/user/{u}",
    "Minecraft": "https://api.mojang.com/users/profiles/minecraft/{u}",
    "Steam": {
        "url": "https://steamcommunity.com/id/{u}/?xml=1",
        "missing": "could not be found",
    },
    "Duolingo": {
        "url": "https://www.duolingo.com/2017-06-30/users?username={u}",
        "missing": '"users":[]',
    },
}


# --- banner -----------------------------------------------------------------

BANNER_BITS = "01001101011010011100101101001101011001101001011010010110"


def _bit_row(shift, width=16):
    start = shift % len(BANNER_BITS)
    stream = BANNER_BITS + BANNER_BITS
    return stream[start : start + width]


def banner_frames():
    """Eight frames: binary scrolls, a scan mark moves, the figure blinks."""
    frames = []
    eyes = [("o", "o"), ("-", "-"), ("o", "o"), ("^", "^"), ("o", "o"), ("O", "O"), ("-", "o"), ("o", "o")]
    mouths = ["-", "~", "-", "_"]
    for i in range(8):
        left, right = eyes[i]
        mouth = mouths[i % 4]
        scan_at = (i * 2) % 13
        scan = (" " * scan_at + ">>>" + " " * 13)[:16]
        b0 = _bit_row(i * 3)
        b1 = _bit_row(i * 3 + 6)
        b2 = _bit_row(i * 3 + 12)
        frames.append(
            "\n".join(
                [
                    "OSINT",
                    "v1.0",
                    "",
                    "                  .-------.",
                    f"                 /  {left}   {right}  \\",
                    f"                 |    {mouth}    |",
                    "                  \\_______/",
                    "                     _|_",
                    "             _______| |_______",
                    "            /                   \\",
                    "           | +------------------+ |",
                    f"           | | {b0} | |",
                    f"           | | {b1} | |",
                    f"           | | {b2} | |",
                    f"           | | {scan} | |",
                    "           | +------------------+ |",
                    "            \\_____________________/",
                    "                   /     \\",
                    "                  /       \\",
                    "                 /_________\\",
                    "",
                ]
            )
        )
    return frames


def clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def play_banner():
    frames = banner_frames()
    sys.stdout.write("\033[?25l")
    try:
        clear_screen()
        sys.stdout.write("OSINT\nv1.0\n")
        sys.stdout.flush()
        time.sleep(0.4)
        for _ in range(2):
            for frame in frames:
                clear_screen()
                sys.stdout.write(frame)
                sys.stdout.flush()
                time.sleep(0.1)
    finally:
        sys.stdout.write("\033[?25h")
        clear_screen()


# --- http -------------------------------------------------------------------

class HttpResult:
    def __init__(self, status=None, body="", url="", error=None):
        self.status = status
        self.body = body
        self.url = url
        self.error = error


USE_TOR = False


def tor_proxy_is_up():
    try:
        with socket.create_connection((TOR_HOST, TOR_PORT), timeout=2):
            return True
    except OSError:
        return False


def _recv_exact(sock, count):
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def _socks5_connect(host, port, timeout):
    """Open a TCP connection through Tor. Uses the standard library, no PySocks."""
    sock = socket.create_connection((TOR_HOST, TOR_PORT), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        version, method = _recv_exact(sock, 2)
        if version != 5 or method != 0:
            raise ConnectionError("Tor proxy refused the handshake")
        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            raise ConnectionError("hostname is too long for SOCKS5")
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + int(port).to_bytes(2, "big")
        )
        version, reply, _reserved, atyp = _recv_exact(sock, 4)
        if version != 5 or reply != 0:
            raise ConnectionError(f"Tor connect failed (code {reply})")
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length)
        elif atyp == 4:
            _recv_exact(sock, 16)
        else:
            raise ConnectionError("unexpected Tor reply")
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _read_chunked(sock, pending):
    data = pending
    out = bytearray()
    while len(out) < BODY_LIMIT:
        while b"\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return bytes(out)
            data += chunk
        line, data = data.split(b"\r\n", 1)
        size_text = line.split(b";", 1)[0].strip()
        if not size_text:
            continue
        try:
            size = int(size_text, 16)
        except ValueError:
            break
        if size == 0:
            break
        while len(data) < size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        out += data[:size]
        data = data[size + 2 :]
    return bytes(out[:BODY_LIMIT])


def _read_http(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > BODY_LIMIT + 8192:
            break
    raw = bytes(data)
    header_blob, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep:
        raise ConnectionError("no HTTP response")
    lines = header_blob.decode("iso-8859-1", "replace").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ConnectionError("bad HTTP status")
    status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower().strip()] = value.strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _read_chunked(sock, rest)
    elif "content-length" in headers:
        try:
            need = min(int(headers["content-length"]), BODY_LIMIT)
        except ValueError:
            need = BODY_LIMIT
        body = rest
        while len(body) < need:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
        body = body[:need]
    else:
        body = rest
        while len(body) < BODY_LIMIT:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
        body = body[:BODY_LIMIT]
    if headers.get("content-encoding", "").lower() == "gzip":
        try:
            body = gzip.decompress(body)
        except (OSError, EOFError):
            pass
    text = body.decode("utf-8", "replace")
    return status, headers, text


def _request_tor(url, timeout, hops=0):
    if hops > 4:
        return HttpResult(error="too many redirects", url=url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return HttpResult(error="unsupported URL", url=url)
    host = parsed.hostname
    if not host:
        return HttpResult(error="missing host", url=url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    host_header = host if port in (80, 443) else f"{host}:{port}"
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        "Accept: text/html,application/json;q=0.9,*/*;q=0.8\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii", "replace")
    sock = _socks5_connect(host, port, timeout)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        status, headers, text = _read_http(sock)
    finally:
        sock.close()
    if status in (301, 302, 303, 307, 308) and headers.get("location"):
        nxt = urllib.parse.urljoin(url, headers["location"])
        if urllib.parse.urlsplit(nxt).scheme in ("http", "https"):
            return _request_tor(nxt, timeout, hops + 1)
    return HttpResult(status=status, body=text, url=url)


def _request_direct(url, timeout):
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
    }
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
    except requests.Timeout:
        return HttpResult(error="timed out", url=url)
    except requests.ConnectionError:
        return HttpResult(error="connection failed", url=url)
    except requests.RequestException as exc:
        return HttpResult(error=exc.__class__.__name__, url=url)
    try:
        chunks = []
        size = 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size >= BODY_LIMIT:
                break
        raw = b"".join(chunks)[:BODY_LIMIT]
    finally:
        response.close()
    return HttpResult(
        status=response.status_code,
        body=raw.decode("utf-8", "replace"),
        url=response.url,
    )


def fetch(url, timeout=REQUEST_TIMEOUT):
    try:
        if USE_TOR:
            return _request_tor(url, timeout)
        return _request_direct(url, timeout)
    except (OSError, ConnectionError, ssl.SSLError) as exc:
        reason = str(exc).strip() or exc.__class__.__name__
        return HttpResult(error=reason, url=url)


# --- results ----------------------------------------------------------------

LAST_RESULT = Path.home() / ".local" / "share" / "osint" / "last_result.txt"


def save_result(text):
    try:
        LAST_RESULT.parent.mkdir(parents=True, exist_ok=True)
        LAST_RESULT.write_text(text, encoding="utf-8")
    except OSError as exc:
        print(f"Warning: could not save the last result ({exc}).")


def load_result():
    try:
        return LAST_RESULT.read_text(encoding="utf-8")
    except OSError:
        return ""


def paint(text, code):
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def platform_spec(value):
    if isinstance(value, str):
        return {"url": value, "missing": None, "absent": (404, 410)}
    spec = {"url": value["url"], "missing": value.get("missing"), "absent": tuple(value.get("absent", (404, 410)))}
    return spec


def looks_blocked(body):
    return any(marker in body for marker in BLOCK_MARKERS)


def body_has_missing(body, missing):
    if not missing:
        return False
    if missing in body:
        return True
    compact = re.sub(r"\s+", "", body)
    needle = re.sub(r"\s+", "", missing)
    return needle in compact


def judge(result, spec):
    if result.error or result.status is None:
        return "unclear", result.error or "no response"
    if result.status in spec["absent"]:
        return "not_found", ""
    if looks_blocked(result.body):
        return "unclear", "blocked"
    if body_has_missing(result.body, spec["missing"]):
        return "not_found", ""
    if 200 <= result.status < 300:
        return "found", ""
    if result.status in (401, 403, 429, 503):
        return "unclear", f"HTTP {result.status}"
    return "unclear", f"HTTP {result.status}"


def check_username(username):
    specs = [(name, platform_spec(value)) for name, value in PLATFORMS.items()]
    total = len(specs)
    done = 0
    lock = threading.Lock()
    show_progress = sys.stdout.isatty()

    def one(item):
        nonlocal done
        name, spec = item
        url = spec["url"].replace("{u}", urllib.parse.quote(username, safe=""))
        result = fetch(url)
        kind, detail = judge(result, spec)
        if show_progress:
            with lock:
                done += 1
                sys.stdout.write(f"\rChecked {done}/{total}")
                sys.stdout.flush()
        return name, kind, detail, result.url or url

    rows = []
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        futures = [pool.submit(one, item) for item in specs]
        for future in as_completed(futures):
            rows.append(future.result())
    if show_progress:
        sys.stdout.write("\r" + " " * 24 + "\r")
        sys.stdout.flush()
    rows.sort(key=lambda row: row[0].lower())
    return rows


def format_user_report(username, rows):
    found = [row for row in rows if row[1] == "found"]
    missing = [row for row in rows if row[1] == "not_found"]
    unclear = [row for row in rows if row[1] == "unclear"]
    width = max((len(row[0]) for row in found + unclear), default=4)
    lines = [f"username: {username}", f"checked: {len(rows)} public pages", ""]
    lines.append(f"FOUND  {len(found)}")
    if found:
        for name, _kind, _detail, url in found:
            lines.append(f"  {name.ljust(width)}  {url}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"NOT FOUND  {len(missing)}")
    if missing:
        names = ", ".join(row[0] for row in missing)
        lines.append(textwrap.fill(names, width=76, initial_indent="  ", subsequent_indent="  "))
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"UNCLEAR  {len(unclear)}")
    if unclear:
        for name, _kind, detail, url in unclear:
            lines.append(f"  {name.ljust(width)}  {detail}")
    else:
        lines.append("  (none)")
    return "\n".join(lines)


def lookup_ip(address):
    try:
        ipaddress.ip_address(address)
    except ValueError:
        print(f"Not an IP address: {address}")
        return None
    url = IP_API.format(ip=urllib.parse.quote(address, safe=":"))
    result = fetch(url)
    if result.error:
        print(f"Lookup failed: {result.error}")
        return None
    try:
        data = json.loads(result.body)
    except json.JSONDecodeError:
        print("Lookup failed: the IP service did not return JSON.")
        return None
    if not data.get("success", False):
        message = data.get("message") or "the IP service rejected this address"
        print(f"Lookup failed: {message}")
        return None
    connection = data.get("connection") or {}
    timezone = data.get("timezone") or {}
    if isinstance(timezone, dict):
        zone = timezone.get("id") or timezone.get("utc") or ""
    else:
        zone = str(timezone)
    lat = data.get("latitude")
    lon = data.get("longitude")
    coords = ""
    if lat is not None and lon is not None:
        coords = f"{lat}, {lon}"
    rows = [
        ("IP", data.get("ip") or address),
        ("Type", data.get("type") or ""),
        ("Continent", data.get("continent") or ""),
        ("Country", data.get("country") or ""),
        ("Region", data.get("region") or ""),
        ("City", data.get("city") or ""),
        ("Timezone", zone),
        ("ISP", connection.get("isp") or data.get("isp") or ""),
        ("Org", connection.get("org") or data.get("org") or ""),
        ("Coordinates", coords),
    ]
    lines = [f"{label.ljust(12)} {value}".rstrip() for label, value in rows if value]
    lines.append("Source       ipwho.is")
    return "\n".join(lines)


def ask_ollama(question, context):
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Public result:\n{context}\n\nQuestion: {question}",
            },
        ],
    }
    try:
        response = requests.post(
            OLLAMA_URL.rstrip("/") + "/api/chat",
            json=payload,
            timeout=90,
        )
    except requests.RequestException:
        print(
            f"Warning: Ollama is not reachable at {OLLAMA_URL} "
            f"(model {OLLAMA_MODEL})."
        )
        return False
    try:
        data = response.json()
    except ValueError:
        data = {}
    if response.status_code != 200:
        detail = data.get("error") if isinstance(data, dict) else ""
        detail = detail or response.text[:200]
        print(f"Warning: Ollama returned HTTP {response.status_code}. {detail}".rstrip())
        return False
    message = data.get("message") or {}
    answer = (message.get("content") or "").strip()
    if not answer:
        print("Warning: Ollama returned an empty answer.")
        return False
    print(answer)
    return True


def color_report(report):
    if not sys.stdout.isatty():
        return report
    report = report.replace("FOUND", paint("FOUND", "32"), 1)
    report = report.replace("NOT FOUND", paint("NOT FOUND", "2"), 1)
    report = report.replace("UNCLEAR", paint("UNCLEAR", "33"), 1)
    return report


def print_analysis(question, context):
    print()
    print("---")
    print(OLLAMA_MODEL)
    return ask_ollama(question, context)


def valid_username(username):
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,38}", username) is not None


# --- cli --------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="osint",
        description="Public IP lookup, public username checks, and a local Ollama summary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            examples:
              osint.py ip 1.1.1.1
              osint.py --no-banner user torvalds
              osint.py ask "What is public here?"
              osint.py --auto --tor ip 8.8.8.8
            """
        ),
    )
    parser.add_argument("--no-banner", action="store_true", help="skip the intro animation")
    parser.add_argument("--tor", action="store_true", help="send lookups through Tor SOCKS at 127.0.0.1:9050")
    parser.add_argument("--auto", action="store_true", help="after ip or user, ask Ollama a short privacy question")
    sub = parser.add_subparsers(dest="cmd")

    ip_cmd = sub.add_parser("ip", help="look up a public IP address")
    ip_cmd.add_argument("address", help="IPv4 or IPv6 address")

    user_cmd = sub.add_parser("user", help="check a username on public pages")
    user_cmd.add_argument("username", help="letters, numbers, dot, underscore, hyphen")

    ask_cmd = sub.add_parser("ask", help="ask local Ollama about the last result")
    ask_cmd.add_argument("question", nargs="+", help="question for Ollama")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 0

    global USE_TOR
    USE_TOR = False
    if args.tor and args.cmd in ("ip", "user"):
        if not tor_proxy_is_up():
            print(f"Tor SOCKS proxy not running on {TOR_HOST}:{TOR_PORT}")
            return 1
        USE_TOR = True

    if not args.no_banner and sys.stdout.isatty():
        play_banner()

    if args.cmd == "ip":
        report = lookup_ip(args.address.strip())
        if report is None:
            return 1
        print(report)
        save_result(report)
        if args.auto:
            print_analysis(AUTO_QUESTION, report)
        return 0

    if args.cmd == "user":
        username = args.username.strip()
        if not valid_username(username):
            print("Username may only contain letters, numbers, dots, underscores, and hyphens.")
            return 1
        try:
            rows = check_username(username)
        except KeyboardInterrupt:
            print("\nStopped.")
            return 130
        report = format_user_report(username, rows)
        print(color_report(report))
        save_result(report)
        if args.auto:
            print_analysis(AUTO_QUESTION, report)
        return 0

    if args.cmd == "ask":
        question = " ".join(args.question).strip()
        if not question:
            print("Ask needs a question.")
            return 1
        context = load_result()
        if not context.strip():
            print("No previous result. Run an ip or user lookup first.")
            return 1
        return 0 if print_analysis(question, context) else 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stdout.write("\033[?25h")
        print("\nStopped.")
        sys.exit(130)
