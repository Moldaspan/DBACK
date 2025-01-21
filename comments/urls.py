from django.urls import path
from .views import comment_list_create, comment_detail

urlpatterns = [
    path('publication/<int:publication_id>/comments/', comment_list_create, name='comment-list-create'),
    path('comments/<int:pk>/', comment_detail, name='comment-detail'),
]