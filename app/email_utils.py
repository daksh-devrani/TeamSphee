import smtplib
from email.mime.text import MIMEText
from flask import current_app
import os


def send_email(to_email, subject, body):
    from_email = os.getenv('SMTP_EMAIL')
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_password = os.getenv('SMTP_PASSWORD')

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, smtp_password)
        server.send_message(msg)
        server.quit()
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {e}")
