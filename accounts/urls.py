from django.urls import path
from .views import user_registration, login_user, verify_email, request_password_reset, reset_password

urlpatterns = [
    path('register/', user_registration, name='register'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
    path('login/', login_user, name='login'),
    path('request-password-reset/', request_password_reset, name='request_password_reset'),
    path('reset-password/<str:token>/', reset_password, name='reset_password'),
]

