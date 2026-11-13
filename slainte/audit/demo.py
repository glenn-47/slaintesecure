

import click

from ..db import get_db
from . import bp


@bp.cli.command("tamper-log")
@click.argument("entry_id", type=int)
def tamper_log(entry_id):
    """Edit an audit entry. 'Verify chain' should then fail at this entry."""
    db = get_db()
    db.execute("UPDATE audit_log SET details = 'edited by attacker' WHERE id = ?", (entry_id,))
    db.commit()
    click.echo(f"Audit entry {entry_id} edited. Now click Verify chain.")


@bp.cli.command("tamper-signature")
@click.argument("record_id", type=int)
def tamper_signature(record_id):
    """
    Change a signed records date. The encryption still works (the date
    isnt partof check) but the signature covers the date
    so the signature check fails.
    """
    db = get_db()
    db.execute("UPDATE records SET created_at = '2020-01-01 00:00:00' WHERE id = ?", (record_id,))
    db.commit()
    click.echo(f"Record {record_id}'s date changed. Now open the record.")


@bp.cli.command("tamper-ciphertext")
@click.argument("record_id", type=int)
def tamper_ciphertext(record_id):
    """Flip one bit of the encrypted record. AES-GCM's check should catch it."""
    db = get_db()
    row = db.execute("SELECT encrypted_body FROM records WHERE id = ?", (record_id,)).fetchone()
    if row is None:
        raise click.ClickException(f"No record {record_id}.")
    body = bytearray(row["encrypted_body"])
    body[-1] ^= 0x01   # flip the lowest bit of the last byte
    db.execute("UPDATE records SET encrypted_body = ? WHERE id = ?", (bytes(body), record_id))
    db.commit()
    click.echo(f"One bit of record {record_id} flipped. Now open the record.")