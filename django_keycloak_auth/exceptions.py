from rest_framework import exceptions, status
from django.utils.translation import gettext_lazy as _


class InvalidCredentials(exceptions.AuthenticationFailed):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Incorrect authentication credentials.')
    default_code = "invalid_credentials"


class KeycloakUserExistException(exceptions.APIException):
    status_code = 404
    default_detail = 'user not exists'
    default_code = 'user_exist_error'


class KeycloakUserUnauthorizedException(exceptions.APIException):
    status_code = 401
    default_detail = 'unauthorized user'
    default_code = 'user_unauthorized_error'
