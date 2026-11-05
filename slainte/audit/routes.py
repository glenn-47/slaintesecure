"""Pages for the integrity and audit section."""

from flask import render_template, request

from ..auth.decorators import role_required
from ..db import get_db
from . import bp
from .log import verify_chain

# Newest entries shown on the page. "Verify chain" always checks the WHOLE
# log, not just these, because tampering can be anywhere.
PAGE_LIMIT = 200


@bp.route("/")
@role_required("admin")
def log_page():
    """
    The audit log, newest first, with an optional chain check.

    Admins only (least privilege): the log reveals WHO viewed WHICH
    patient's records and when. That's sensitive in itself, even though
    no medical content is stored in it.

    Verifying is a plain GET link (?verify=1) rather than a POST form,
    because it only reads data and changes nothing. GET is the right HTTP
    method for read-only actions, and it needs no CSRF token.
    """
    entries = get_db().execute(
        # LEFT JOIN, so entries with no user (failed logins) or whose user
        # was deleted still appear, just with no username.
        "SELECT audit_log.*, users.username FROM audit_log "
        "LEFT JOIN users ON users.id = audit_log.user_id "
        "ORDER BY audit_log.id DESC LIMIT ?",
        (PAGE_LIMIT,),
    ).fetchall()

    result = verify_chain() if request.args.get("verify") else None

    return render_template(
        "audit/log.html", entries=entries, result=result, limit=PAGE_LIMIT
    )