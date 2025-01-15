import uuid
from django.core.mail import EmailMessage
from django.conf import settings


def generate_verification_token():
    return str(uuid.uuid4())


def send_email_dynamic(subject, message, recipient_email):
    try:
        email = EmailMessage(
            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient_email],
        )
        email.content_subtype = "html"
        email.send(fail_silently=False)
        return {"success": True, "message": "Email sent successfully."}
    except Exception as e:
        return {"success": False, "message": str(e)}
