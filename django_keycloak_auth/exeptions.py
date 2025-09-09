from rest_framework import exceptions, status
from django.utils.translation import gettext_lazy as _


class InvalidCredentials(exceptions.AuthenticationFailed):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Incorrect authentication credentials.')
    default_code = "invalid_credentials"
