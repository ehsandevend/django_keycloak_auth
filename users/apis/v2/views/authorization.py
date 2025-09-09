from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response
from users.apis.v2.permissions.auth_permissions import *

class HelloView(APIView):
    dispature = None
    permission_classes = [IsAuthenticated, HasPermissionToChangeGallary]
    def get(self, request, format=None):
        return Response(
            {
                'msg':
                'it seems okey'
            },
            status=status.HTTP_200_OK)
