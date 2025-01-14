import uuid
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.utils import timezone
from datetime import timedelta

from . import serializers
from .models import User, PasswordResetToken
from .serializers import UserRegistrationSerializer
from .utils import generate_verification_token
from django.core.mail import send_mail
from django.conf import settings


def send_verification_email(user):
    token = generate_verification_token()
    user.verification_token = token
    user.verification_token_expiry = timezone.now() + timedelta(hours=24)  # Токен истекает через 24 часа
    user.save()

    verification_url = f"{settings.SITE_URL}/verify-email/{token}/"

    send_mail(
        'Email confirmation',
        f"Please confirm your email by clicking on the link: {verification_url}",
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


@api_view(['POST'])
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

        # Отправить письмо с подтверждением email
        send_verification_email(user)

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

    return Response(
        {"errors": serializer.errors},
        status=status.HTTP_400_BAD_REQUEST
    )


@api_view(['GET'])
def verify_email(request, token):
    try:
        user = User.objects.get(verification_token=token)
        if user.verification_token_expiry and timezone.now() > user.verification_token_expiry:
            return Response(
                {"error": "The verification token has expired."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.is_verified = True
        user.is_active = True
        user.verification_token = None
        user.verification_token_expiry = None
        user.save()

        return Response(
            {"message": "Your email has been successfully verified!"},
            status=status.HTTP_200_OK
        )
    except User.DoesNotExist:
        return Response(
            {"error": "Invalid verification token."},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["POST"])
def login_user(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email=email).first()
    if not user:
        return Response({"error": "Invalid email."}, status=status.HTTP_401_UNAUTHORIZED)

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
            user.lockout_time = timezone.now() + timedelta(minutes=15)  # Блокировка на 15 минут
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
def request_password_reset(request):
    email = request.data.get('email')

    # Проверяем, существует ли пользователь с таким email
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)

    # Генерируем токен для сброса пароля
    token = str(uuid.uuid4())
    expires_at = timezone.now() + timedelta(hours=1)  # Токен будет действовать 1 час
    reset_token = PasswordResetToken.objects.create(
        user=user,
        token=token,
        expires_at=expires_at
    )

    # Формируем ссылку для сброса пароля
    reset_url = f"{settings.SITE_URL}/reset-password/{token}/"

    # Отправляем email с ссылкой для сброса пароля
    send_mail(
        'Password Reset Request',
        f'Click the following link to reset your password: {reset_url}',
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )

    return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)



@api_view(['POST'])
def reset_password(request, token):
    try:
        reset_token = PasswordResetToken.objects.get(token=token)
    except PasswordResetToken.DoesNotExist:
        return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

    if reset_token.is_expired():
        return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

    # Получаем новый пароль
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')

    if new_password != confirm_password:
        return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

    # Валидация пароля через встроенные валидаторы
    try:
        validate_password(new_password)
    except serializers.ValidationError as e:
        return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

    # Обновляем пароль пользователя
    user = reset_token.user
    user.set_password(new_password)
    user.save()

    # Удаляем токен
    reset_token.delete()

    return Response({"message": "Your password has been successfully reset."}, status=status.HTTP_200_OK)