from rest_framework import serializers
from .models import Profile
from accounts.models import User
from datetime import date


class ProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', read_only=True)  # Email из модели User
    first_name = serializers.CharField(source='user.first_name', read_only=True)  # Имя из модели User
    last_name = serializers.CharField(source='user.last_name', read_only=True)  # Фамилия из модели User
    age = serializers.SerializerMethodField()  # Добавляем вычисляемое поле

    class Meta:
        model = Profile
        fields = [
            'email', 'first_name', 'last_name',  # Поля из модели User
            'country', 'city', 'phone_number', 'bio',
            'instagram', 'linkedin', 'facebook', 'twitter',
            'birth_date', 'age',  # birth_date из модели Profile, age вычисляется
            'avatar'
        ]

    def get_age(self, obj):
        """Вычисляем возраст на основе даты рождения."""
        if obj.birth_date:
            today = date.today()
            return today.year - obj.birth_date.year - ((today.month, today.day) < (obj.birth_date.month, obj.birth_date.day))
        return None
