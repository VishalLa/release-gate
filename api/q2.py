import re
from flask import Blueprint, request, jsonify

app = Blueprint("q2")


MY_TENANT = "tenant-1ro51to"
MY_EMAIL_DOMAIN = "notify-3t1hil0.example"

ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}


def check_top_level_schema(body):
    if not isinstance(body, dict):
        return False
        
    if body.get("provenance") not in ("trusted", "untrusted"):
        return False
    
    if not isinstance(body.get("humanApproved"), bool):
        return False
    
    uc = body.get("untrustedContent")
    if uc is not None and not isinstance(uc, str):
        return False

    action = body.get("action")
    if not isinstance(action, dict):
        return False
    
    if not isinstance(action.get("tool"), str):
        return False
    
    if not isinstance(action.get("args"), dict):
        return False
    
    return True


def check_args_schema(tool, args):
    """return true if args exactly match the tool's expected shape"""
    
    if tool == "search":
        if set(args.keys()) != {"query"}:
            return False
        q = args["query"]
        return isinstance(q, str) and 1 <= len(q) <= 200
    
    if tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return False
        tenant_id, record_id = args["tenantId"], args["recordId"]
        return (
            isinstance(tenant_id, str) and len(tenant_id) > 0 and
            isinstance(record_id, str) and len(record_id) > 0
        )
        
    if tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return False
        return all(isinstance(args[k], str) for k in ("to", "subject", "body"))

    if tool == "render_html":
        if set(args.keys()) != {"html"}:
            return False
        return isinstance(args["html"], str)

    return False


def html_is_unsafe(html):
    lowered = html.lower()
    patterns = [
        r"<script",
        r"<iframe",
        r"javascript:",
        r"\son\w+\s*=",   # inline event handlers like onclick=, onerror=
    ]
    return any(re.search(p, lowered) for p in patterns)


@app.route("/action-firewall", methods=["POST"])
def action_firewall():
    
    def fail(reason):
        return {"decision": "block", "reason": reason}
    
    body = request.get_json(force=True, silent=True)

    # 1. Top-level schema
    if not check_top_level_schema(body):
        return jsonify(fail("INVALID_SCHEMA"))

    action = body["action"]
    tool = action["tool"]
    args = action["args"]

    # 2. Tool allowlist
    if tool not in ALLOWED_TOOLS:
        return jsonify(fail("TOOL_NOT_ALLOWED"))

    # 3. Selected tool's argument schema
    if not check_args_schema(tool, args):
        return jsonify(fail("INVALID_SCHEMA"))

    # 4. Tenant scope (only lookup_record)
    if tool == "lookup_record":
        if args["tenantId"] != MY_TENANT:
            return jsonify(fail("TENANT_SCOPE"))

    # 5 & 6. Email domain + approval (only send_email)
    if tool == "send_email":
        to = args["to"]
        domain = to.split("@")[-1] if "@" in to else ""
        if domain != MY_EMAIL_DOMAIN:
            return jsonify(fail("EGRESS_DENIED"))
        if body["humanApproved"] is not True:
            return jsonify(fail("APPROVAL_REQUIRED"))

    # 7. HTML safety (only render_html)
    if tool == "render_html":
        if html_is_unsafe(args["html"]):
            return jsonify(fail("UNSAFE_OUTPUT"))

    return jsonify({"decision": "allow", "reason": "ALLOW"})
