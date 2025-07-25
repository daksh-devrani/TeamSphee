from itsdangerous import URLSafeTimedSerializer
import os

# This should match your app’s SECRET_KEY
SECRET_KEY = os.getenv("SECRET_KEY")
SECURITY_SALT = os.getenv("SECURITY_SALT", "email-confirm-salt")  # You can customize this

serializer = URLSafeTimedSerializer(SECRET_KEY)


def generate_verification_token(email):
    return serializer.dumps(email, salt=SECURITY_SALT)


def confirm_verification_token(token, expiration=3600):  # 1 hour default
    try:
        email = serializer.loads(token, salt=SECURITY_SALT, max_age=expiration)
    except Exception:
        return None
    return email
