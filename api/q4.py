import re
import urllib.parse
from flask import Blueprint, request, jsonify

app = Blueprint("q4", __name__)

ALLOWED_HOSTS = {"cdn-1geloa6.example", "app-wdazqyq.example"}
VALID_CHANNELS = {"html", "markdown", "url", "sql", "shell"}


def validate_schema(body):
    if not isinstance(body, dict):
        return False
    if body.get("channel") not in VALID_CHANNELS:
        return False
    output = body.get("output")
    if not isinstance(output, str):
        return False
    if len(output) > 20000:
        return False
    return True


_NUMERIC_ENTITY_RE = re.compile(r"&#(x[0-9a-fA-F]+|\d+);")
_NAMED_ENTITIES = {"&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'", "&amp;": "&"}
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def decode_html_entities(s):
    def repl(m):
        code = m.group(1)
        if code[0].lower() == "x":
            return chr(int(code[1:], 16))
        return chr(int(code))
    s = _NUMERIC_ENTITY_RE.sub(repl, s)
    for entity, char in _NAMED_ENTITIES.items():
        s = s.replace(entity, char)
    return s


def decode_unicode_escapes(s):
    return _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), s)


def decode_once(s):
    s = urllib.parse.unquote(s)       # percent-escapes, e.g. %3C -> <
    s = decode_html_entities(s)       # &lt; and &#60; -> <
    s = decode_unicode_escapes(s)     # \u003c -> <
    return s


def extract_urls(channel, text):
    if channel == "html":
        urls = re.findall(r'(?:src|href)\s*=\s*"([^"]*)"', text, re.I)
        urls += re.findall(r"(?:src|href)\s*=\s*'([^']*)'", text, re.I)
        return urls
    if channel == "markdown":
        return re.findall(r"\]\(([^)]*)\)", text)
    if channel == "url":
        return [text.strip()]
    return []


def classify_url(raw):
    raw = raw.strip()
    if raw.startswith("//"):
        # protocol-relative: a browser resolves this against the current
        # scheme, so treat it as absolute and assume https
        parsed = urllib.parse.urlsplit("https:" + raw)
        return "absolute", parsed
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme:
        return "absolute", parsed
    return "relative", None


_SCRIPT_TAG_RE = re.compile(r"<\s*(script|iframe|object|embed)\b", re.I)
_EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=", re.I)
_DANGEROUS_SCHEME_TEXT_RE = re.compile(r"\b(javascript|data|vbscript)\s*:", re.I)
_SQL_METACHAR_RE = re.compile(r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b", re.I)
_SHELL_METACHAR_RE = re.compile(r"[;&|`<>]|\$\(|\$\{")


def has_script_tag(text):
    return bool(_SCRIPT_TAG_RE.search(text))


def has_event_handler(text):
    return bool(_EVENT_HANDLER_RE.search(text))


def has_dangerous_scheme(channel, text):
    if _DANGEROUS_SCHEME_TEXT_RE.search(text):
        return True
    for raw in extract_urls(channel, text):
        kind, parsed = classify_url(raw)
        if kind == "absolute" and parsed.scheme.lower() not in ("http", "https"):
            return True
    return False


def has_external_exfil(channel, text):
    for raw in extract_urls(channel, text):
        kind, parsed = classify_url(raw)
        if kind != "absolute":
            continue
        if parsed.scheme.lower() not in ("http", "https"):
            continue  # already caught by dangerous-scheme check, order matters
        hostname = parsed.hostname
        if hostname is None or hostname.lower() not in ALLOWED_HOSTS:
            return True
    return False


def has_sql_metachar(text):
    return bool(_SQL_METACHAR_RE.search(text))


def has_shell_metachar(text):
    return bool(_SHELL_METACHAR_RE.search(text))


def evaluate_channel(channel, text):
    if channel == "html":
        if has_script_tag(text):
            return "SCRIPT_TAG"
        if has_event_handler(text):
            return "EVENT_HANDLER"
        if has_dangerous_scheme(channel, text):
            return "DANGEROUS_SCHEME"
        if has_external_exfil(channel, text):
            return "EXTERNAL_EXFIL"
        return "SAFE"

    if channel in ("markdown", "url"):
        if has_dangerous_scheme(channel, text):
            return "DANGEROUS_SCHEME"
        if has_external_exfil(channel, text):
            return "EXTERNAL_EXFIL"
        return "SAFE"

    if channel == "sql":
        return "SQL_METACHAR" if has_sql_metachar(text) else "SAFE"

    if channel == "shell":
        return "SHELL_METACHAR" if has_shell_metachar(text) else "SAFE"

    return "SAFE"


@app.route("/sanitize-output", methods=["POST"])
def sanitize_output():
    body = request.get_json(force=True, silent=True)

    if not validate_schema(body):
        return jsonify({"safe": False, "reason": "INVALID_SCHEMA"})

    channel = body["channel"]
    output = body["output"]

    decoded = decode_once(output)
    if decoded != output:
        decoded_reason = evaluate_channel(channel, decoded)
        if decoded_reason != "SAFE":
            return jsonify({"safe": False, "reason": "ENCODED_PAYLOAD"})

    reason = evaluate_channel(channel, output)
    return jsonify({"safe": reason == "SAFE", "reason": reason})
