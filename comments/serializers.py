from rest_framework import serializers
from .models import Comment
from publications.models import Publication


class CommentSerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Comment
        fields = ['id', 'publication', 'author', 'content', 'created_at', 'updated_at']
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']

    def create(self, validated_data):
        publication_id = self.context['publication_id']
        publication = Publication.objects.get(id=publication_id)

        comment = Comment.objects.create(publication=publication, **validated_data)
        return comment
