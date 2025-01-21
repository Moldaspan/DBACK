from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Publication
from .serializers import PublicationSerializer


class IsAuthenticatedOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user and request.user.is_authenticated


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def publication_list(request):
    if request.method == 'GET':
        publications = Publication.objects.all()
        serializer = PublicationSerializer(publications, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = PublicationSerializer(data=request.data)
        if serializer.is_valid():
            publication = serializer.save(author=request.user)
            response_data = serializer.data
            response_data["privacy_policy"] = "Ваши данные хранятся в соответствии с нашей политикой конфиденциальности."
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticatedOrReadOnly])
def publication_detail(request, pk):
    try:
        publication = Publication.objects.get(pk=pk)
    except Publication.DoesNotExist:
        return Response({"error": "Publication not found."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = PublicationSerializer(publication)
        return Response(serializer.data)

    elif request.method == 'PUT':
        if publication.author != request.user:
            return Response({"error": "You do not have permission to edit this publication."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = PublicationSerializer(publication, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        if publication.author != request.user:
            return Response({"error": "You do not have permission to delete this publication."},
                            status=status.HTTP_403_FORBIDDEN)

        publication.delete()
        return Response({"message": "Publication deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def privacy_policy(request):
    return Response({
        "privacy_policy": "Мы уважаем вашу конфиденциальность. Все данные защищены и используются "
                          "только в рамках нашего сервиса."
    })