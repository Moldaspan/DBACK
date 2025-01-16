import uuid
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.utils import timezone
from datetime import timedelta

import hashlib
from . import serializers
from .models import User, PasswordResetToken
from .serializers import UserRegistrationSerializer
from .utils import generate_verification_token, send_email_dynamic
from django.core.mail import send_mail
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.http import JsonResponse
def custom_ratelimit_handler(view):
    def wrapped_view(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except Ratelimited:
            return JsonResponse(
                {"detail": "Too many requests. Please try again later."},
                status=429
            )
    return wrapped_view
def send_verification_email(user):
    token = generate_verification_token()
    user.set_verification_token(token)
    user.verification_token_expiry = timezone.now() + timedelta(hours=24)
    user.save()

    verification_url = f"{settings.SITE_URL}/accounts/verify-email/{token}/"
    subject = "Email Verification"
    html_message = f"""
        <html>
            <body>
                <p>Thank you for registering on our site!</p>
                <p>Please confirm your email by clicking the button below:</p>
                <a href="{verification_url}" style="display: inline-block; padding: 10px 20px; color: white; background-color: #007BFF; text-decoration: none; border-radius: 5px;">
                    Confirm Email
                </a>
            </body>
        </html>
    """
    send_email_dynamic(subject, html_message, user.email)


@api_view(['POST'])
@custom_ratelimit_handler
@ratelimit(key='ip', rate='5/m', block=True)  # Ограничиваем до 5 запросов в минуту на IP
def user_registration(request):
    email = request.data.get('email')

    if User.objects.filter(email=email).exists():
        return Response(
            {"email": "The user with this email already exists."},
            status=status.HTTP_400_BAD_REQUEST
        )

    serializer = UserRegistrationSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()

        if settings.SIGNUP_EMAIL_CONFIRMATION:
            try:
                send_verification_email(user)
            except Exception as e:
                return Response({"error": f"Failed to send verification email: {str(e)}"},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response(
                {
                    "message": "The user has been successfully registered. Please check your email for confirmation.",
                    "user": {
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "email": user.email
                    }
                },
                status=status.HTTP_201_CREATED
            )
        else:
            user.is_verified = True
            user.is_active = True
            user.save()
            return Response(
                {
                    "message": "User registered successfully without email verification.",
                    "user": {
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "email": user.email
                    }
                },
                status=status.HTTP_201_CREATED
            )

    return Response(
        {"errors": serializer.errors},
        status=status.HTTP_400_BAD_REQUEST
    )


@api_view(['GET'])
@ratelimit(key='ip', rate='5/h', block=True)
def verify_email(request, token):
    try:
        # Генерируем хэш токена
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Ищем пользователя по хэшу токена
        user = User.objects.get(verification_token_hash=token_hash)

        if user.verification_token_expiry and timezone.now() > user.verification_token_expiry:
            return Response(
                {"error": "The verification token has expired. Please request a new confirmation email."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Подтверждаем email
        user.is_verified = True
        user.is_active = True
        user.verification_token_hash = None
        user.verification_token_expiry = None
        user.save()

        # Генерируем JWT-токены
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        return Response(
            {
                "message": "Your email has been successfully verified!",
                "access_token": str(access_token),
                "refresh_token": str(refresh),
            },
            status=status.HTTP_200_OK
        )
    except User.DoesNotExist:
        return Response(
            {"error": "Invalid verification token."},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["POST"])
@ratelimit(key='ip', rate='10/m', block=True)  # Ограничиваем до 10 запросов в минуту на IP
def login_user(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email=email).first()
    if not user:
        return Response({"error": "Invalid email."}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_verified:
        return Response({"error": "Email not verified. Please verify your email."}, status=status.HTTP_401_UNAUTHORIZED)

    if user.lockout_time and user.lockout_time > timezone.now():
        remaining_time = user.lockout_time - timezone.now()
        minutes = remaining_time.seconds // 60
        return Response({
            "error": f"Account is locked. Try again in {minutes} minutes."
        }, status=status.HTTP_403_FORBIDDEN)

    user_authenticated = authenticate(request, email=email, password=password)

    if user_authenticated is None:
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.lockout_time = timezone.now() + timedelta(minutes=15)
            send_mail(
                'Account Locked',
                'Your account has been locked due to too many failed login attempts.',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        user.save()
        return Response({"error": "Invalid password."}, status=status.HTTP_401_UNAUTHORIZED)

    user.reset_lockout()

    refresh = RefreshToken.for_user(user_authenticated)
    access_token = refresh.access_token

    return Response(
        {
            "message": "Login successful.",
            "access_token": str(access_token),
            "refresh_token": str(refresh),
        },
        status=status.HTTP_200_OK
    )


@api_view(['POST'])
@ratelimit(key='post:email', rate='3/h', block=True)  # Лимитируем по email
def request_password_reset(request):
    email = request.data.get('email')
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)

    token = generate_verification_token()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = timezone.now() + timedelta(hours=1)

    PasswordResetToken.objects.create(user=user, token_hash=token_hash, expires_at=expires_at)

    reset_url = f"{settings.SITE_URL}/accounts/reset-password/{token}/"
    subject = "Password Reset Request"
    html_message = f"""
        <html>
            <body>
                <p>You requested a password reset.</p>
                <p>Please click the button below to reset your password:</p>
                <a href="{reset_url}" style="display: inline-block; padding: 10px 20px; color: white; background-color: #007BFF; text-decoration: none; border-radius: 5px;">
                    Reset Password
                </a>
            </body>
        </html>
    """
    send_email_dynamic(subject, html_message, user.email)
    return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)


@api_view(['POST'])
def reset_password(request, token):
    try:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        reset_token = PasswordResetToken.objects.get(token_hash=token_hash)

        if reset_token.is_expired():
            return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if new_password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(new_password)
        except serializers.ValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user = reset_token.user
        user.set_password(new_password)
        user.save()

        reset_token.delete()

        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        return Response({
            "message": "Your password has been successfully reset.",
            "access_token": str(access_token),
            "refresh_token": str(refresh)
        }, status=status.HTTP_200_OK)

    except PasswordResetToken.DoesNotExist:
        return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)