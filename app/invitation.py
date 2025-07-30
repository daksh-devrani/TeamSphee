from app.models import db, TeamInvitation
from app.email_utils import send_email
from flask import url_for, current_app
from datetime import datetime, timedelta


def create_and_send_invite(team, recipient_email, role='member'):
    # Create invitation record
    invitation = TeamInvitation(
        team_id=team.id,
        email=recipient_email,
        role=role,
        expires_at=datetime.utcnow() + timedelta(days=3)
    )
    db.session.add(invitation)
    db.session.commit()

    # Generate invite link
    invite_url = url_for('main.accept_invite', token=invitation.token, _external=True)

    # Email content
    subject = f"You're invited to join {team.name} on Teamsphee!"
    body = f"""Hi,

You've been invited to join the team **{team.name}** on Teamsphee.

Click the link below to accept the invitation:
{invite_url}

This link expires in 3 days.

If you were’t expecting this, you can ignore the email.

– Teamsphee
"""
    send_email(recipient_email, subject, body)
    return invitation
