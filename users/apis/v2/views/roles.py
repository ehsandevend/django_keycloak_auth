from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated
from users.apis.v2.permissions.auth_permissions import *
from users.apis.v2.serializers.user_serializers import CustomUserSerializer
from users.models import *

class AssignSignUserView(RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = CustomUserSerializer
    lookup_field = 'id'
