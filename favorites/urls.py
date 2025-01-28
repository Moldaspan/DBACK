from django.urls import path
from .views import favorite_publication_list_create,favorite_publication_delete,favorite_user_list_create,\
    favorite_user_delete

urlpatterns = [
    path('publications/', favorite_publication_list_create, name='favorite-publications'),
    path('publications/<int:pk>/', favorite_publication_delete, name='favorite-publication-delete'),
    path('users/', favorite_user_list_create, name='favorite-users'),
    path('users/<int:pk>/', favorite_user_delete, name='favorite-user-delete'),
]
