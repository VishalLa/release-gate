import re
from flask import Blueprint, request, jsonify

app = Blueprint("q3", __name__)

MY_WORKSPACE = "prod-7qeppn"
REQUIRED_LABELS = {
    "owner": "student-o0fj0",
    "environment": "production",
    "cost_center": "cc-5sas",
}
VALID_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
DELETE_GUARDED_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}

EXACT_VERSION_RE = re.compile(r"^(=\s*)?\d+\.\d+\.\d+$")
PESSIMISTIC_VERSION_RE = re.compile(r"^~>\s*\d+(\.\d+){1,2}$")
SECRET_REF_RE = re.compile(r"^secret://.+$")

def reject(reason):
    return {"decision": "reject", "reason": reason}

def validate_schema(body):
    if not isinstance(body, dict):
        return False
    if not isinstance(body.get("environment"), str):
        return False

    state = body.get("state")
    if not isinstance(state, dict):
        return False
    if not isinstance(state.get("backend"), str):
        return False
    if not isinstance(state.get("locked"), bool):
        return False

    if not isinstance(body.get("providerVersion"), str):
        return False
    if not isinstance(body.get("destroyApproved"), bool):
        return False

    resource = body.get("resource")
    if not isinstance(resource, dict):
        return False
    if not isinstance(resource.get("address"), str):
        return False
    if not isinstance(resource.get("type"), str):
        return False
    if resource.get("action") not in ("create", "update", "delete"):
        return False

    labels = resource.get("labels")
    if not isinstance(labels, dict):
        return False
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items()):
        return False

    secret = resource.get("secret")
    if secret is not None and not isinstance(secret, str):
        return False

    if not isinstance(resource.get("forceDestroy"), bool):
        return False

    return True


def provider_version_ok(version):
    return bool(EXACT_VERSION_RE.match(version) or PESSIMISTIC_VERSION_RE.match(version))


def secret_ok(secret):
    if secret is None:
        return True
    return bool(SECRET_REF_RE.match(secret))


@app.route("/terraform/plan", methods=["POST"])
def terraform_plan():
    body = request.get_json(force=True, silent=True)

    # 1. Schema / types
    if not validate_schema(body):
        return jsonify(reject("INVALID_PLAN"))

    resource = body["resource"]

    # 2. Environment match
    if body["environment"] != MY_WORKSPACE:
        return jsonify(reject("ENVIRONMENT_MISMATCH"))

    # 3. State safety
    state = body["state"]
    if state["backend"] not in VALID_BACKENDS or state["locked"] is not True:
        return jsonify(reject("STATE_UNSAFE"))

    # 4. Provider pinning
    if not provider_version_ok(body["providerVersion"]):
        return jsonify(reject("UNPINNED_PROVIDER"))

    # 5. Required labels
    labels = resource["labels"]
    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return jsonify(reject("MISSING_LABELS"))

    # 6. Secret handling
    if not secret_ok(resource["secret"]):
        return jsonify(reject("PLAINTEXT_SECRET"))

    # 7. Guarded deletes
    if resource["action"] == "delete" and resource["type"] in DELETE_GUARDED_TYPES:
        if body["destroyApproved"] is not True:
            return jsonify(reject("DELETE_NOT_APPROVED"))

    # 8. Force-destroy on production storage buckets
    if resource["type"] == "storage_bucket" and resource["forceDestroy"] is True:
        return jsonify(reject("FORCE_DESTROY"))

    return jsonify({"decision": "approve", "reason": "APPROVE"})
