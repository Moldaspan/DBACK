from django.urls import path
from .views import publication_list, publication_detail, privacy_policy

urlpatterns = [
    path('', publication_list, name='publication-list'),
    path('<int:pk>/', publication_detail, name='publication-detail'),
    path('privacy-policy/', privacy_policy, name='privacy-policy'),
]