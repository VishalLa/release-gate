import re
from flask import Blueprint, request, jsonify

app = Blueprint("q1", __name__)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

@app.route("/release-gate", methods=["POST"])
def release_gate():
    """
    {
        "target": "preview | production",
        "event": "pull_request | push",
        "ref": "refs/heads/...",
        "workflow": {
            "trigger": "pull_request | pull_request_target | push",
            "permissions": {"contents":"read", "packages":"write", "id-token":"none"},
            "testsPassed": true, "matrixComplete": true, "failFast": false,
            "actions": [{"owner":"actions", "name":"checkout", "ref":"v4"}]
        },
        "image": {
            "multiStage": true, "runsAsRoot": false, "secretMode": "none | buildkit | arg | copy",
            "criticalVulnerabilities": 0, "digestPinned": true
        }
    }
    """
    body = request.get_json(force=True)
    violations = []

    target   = body.get("target")
    event    = body.get("event")
    ref      = body.get("ref")
    workflow = body.get("workflow", {})
    image    = body.get("image", {})

    # 1. Permissions: must be EXACTLY the 3 keys, EXACT values
    perms = workflow.get("permissions", {})
    if perms != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. PR safety: never pull_request_target
    trigger = workflow.get("trigger")
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests: must fully pass, matrix complete, no fail-fast
    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")
    if not tests_passed or not matrix_complete or fail_fast is True:
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning: 3rd-party actions need a full 40-char SHA
    for action in workflow.get("actions", []):
        owner = action.get("owner")
        ref_value = action.get("ref", "")
        
        if owner == "actions":
            continue  # allowed to use a version tag like "v4"
        if not SHA_RE.match(ref_value):
            violations.append("MUTABLE_ACTION")
            break  # one code is enough even if several actions fail

    # 5. Image hardening checks
    if not image.get("multiStage"):
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot"):
        violations.append("ROOT_RUNTIME")

    secret_mode = image.get("secretMode")
    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities", 0) > 0:
        violations.append("CRITICAL_CVE")

    if not image.get("digestPinned"):
        violations.append("UNPINNED_IMAGE")

    # 6. Extra rules ONLY for production
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"
    return jsonify({
        "decision": decision, 
        "violations": violations
    })
