from rest_framework import serializers
from .models import FavoritePublication, FavoriteUser
from publications.serializers import PublicationSerializer
from accounts.models import User


class FavoritePublicationSerializer(serializers.ModelSerializer):
    publication = PublicationSerializer(read_only=True)
    user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = FavoritePublication
        fields = ['id', 'publication', 'user', 'created_at']
        read_only_fields = ['id', 'created_at']


class FavoriteUserSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    favorite_user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = FavoriteUser
        fields = ['id', 'user', 'favorite_user', 'created_at']
        read_only_fields = ['id', 'created_at']