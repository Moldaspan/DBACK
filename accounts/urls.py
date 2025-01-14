from django.urls import path
from .views import user_registration, login_user, verify_email

urlpatterns = [
    path('register/', user_registration, name='register'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
    path('login/', login_user, name='login'),
]