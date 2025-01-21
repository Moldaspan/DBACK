from rest_framework import serializers
from .models import Publication, PublicationImage, PublicationVideo


class PublicationImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PublicationImage
        fields = ['id', 'image']


class PublicationVideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PublicationVideo
        fields = ['id', 'video']


class PublicationSerializer(serializers.ModelSerializer):
    images = PublicationImageSerializer(many=True, read_only=True)
    videos = PublicationVideoSerializer(many=True, read_only=True)
    uploaded_images = serializers.ListField(
        child=serializers.ImageField(), write_only=True, required=False
    )
    uploaded_videos = serializers.ListField(
        child=serializers.FileField(), write_only=True, required=False
    )

    class Meta:
        model = Publication
        fields = [
            'id', 'author', 'title', 'category', 'description',
            'bank_details', 'amount', 'contact_name', 'contact_email',
            'contact_phone', 'created_at', 'updated_at', 'images',
            'videos', 'uploaded_images', 'uploaded_videos'
        ]
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        uploaded_videos = validated_data.pop('uploaded_videos', [])
        publication = Publication.objects.create(**validated_data)

        # Save images
        for image in uploaded_images:
            PublicationImage.objects.create(publication=publication, image=image)

        # Save videos
        for video in uploaded_videos:
            PublicationVideo.objects.create(publication=publication, video=video)

        return publication
