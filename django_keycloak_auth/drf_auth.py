from django.core.exceptions import SuspiciousOperation
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from rest_framework import exceptions
from django.contrib.auth.backends import ModelBackend
from rest_framework import authentication, exceptions

from requests.exceptions import HTTPError
from django.utils.module_loading import import_string
from django.contrib.auth import get_backends
from urllib.request import parse_http_list, parse_keqv_list

from django_keycloak_auth.keycloak_admin import KeycloakAdmin
from django.apps import apps

django_keycloak_auth_config = apps.get_app_config("django_keycloak_auth")
keycloak_configs = django_keycloak_auth_config.keycloak_configs


def parse_www_authenticate_header(header):
    """
    Convert a WWW-Authentication header into a dict that can be used
    in a JSON response.
    """
    items = parse_http_list(header)
    return parse_keqv_list(items)


def get_backend():
    """
    Get the Django auth backend that uses OIDC.
    """
    from django_keycloak_auth.auth import KeycloakAuth
    # allow the user to force which back backend to use. this is mostly
    # convenient if you want to use OIDC with DRF but don't want to configure
    # OIDC for the "normal" Django auth.
    backend_setting = keycloak_configs.get("OIDC_DRF_AUTH_BACKEND", None)
    if backend_setting:
        backend = import_string(backend_setting)()
        if not isinstance(backend, KeycloakAuth):
            msg = (
                "Class configured in OIDC_DRF_AUTH_BACKEND "
                "does not extend OIDCAuthenticationBackend!"
            )
            raise ImproperlyConfigured(msg)
        return backend

    # if the backend setting is not set, look through the list of configured
    # backends for one that is an OIDCAuthenticationBackend.
    backends = [b for b in get_backends() if isinstance(b, KeycloakAuth)]

    if not backends:
        msg = (
            "No backends extending OIDCAuthenticationBackend found - "
            "add one to AUTHENTICATION_BACKENDS or set OIDC_DRF_AUTH_BACKEND!"
        )
        raise ImproperlyConfigured(msg)
    if len(backends) > 1:
        raise ImproperlyConfigured(
            "More than one OIDCAuthenticationBackend found!")
    return backends[0]


class CustomOIDCAuthentication(ModelBackend):
    www_authenticate_realm = "api"

    def __init__(self, backend=None):
        self.backend = backend or get_backend()

    def authenticate(self, request):
        """
        Authenticate the request and return a tuple of (user, token) or None
        if there was no authentication attempt.
        """
        keycloak_admin = KeycloakAdmin()
        access_token = self.get_access_token(request)

        if not access_token:
            return None
        payload = keycloak_admin.introspect(access_token)
        if not payload['active']:
            raise exceptions.AuthenticationFailed(detail="token is inactive")
        try:
            user = self.backend.get_or_create_user(payload)
        except HTTPError as exc:
            resp = exc.response

            # if the oidc provider returns 401, it means the token is invalid.
            # in that case, we want to return the upstream error message (which
            # we can get from the www-authentication header) in the response.
            if resp.status_code == 401 and "www-authenticate" in resp.headers:
                data = parse_www_authenticate_header(
                    resp.headers["www-authenticate"])
                raise exceptions.AuthenticationFailed(
                    data.get("error_description",
                             "no error description in www-authenticate"))

            # for all other http errors, just re-raise the exception.
            raise exceptions.AuthenticationFailed('token has been expired')
        except SuspiciousOperation as exc:
            raise exceptions.AuthenticationFailed("Login failed")

        if not user:
            msg = "Login failed: No user found for the given access token."
            raise exceptions.AuthenticationFailed(msg)

        return user, access_token

    def get_access_token(self, request):
        """
        Get the access token based on a request.

        Returns None if no authentication details were provided. Raises
        AuthenticationFailed if the token is incorrect.
        """
        header = authentication.get_authorization_header(request)
        if header:
            header = header.decode(authentication.HTTP_HEADER_ENCODING)

            auth = header.split()

            if auth[0].lower() != "bearer":
                return None

            if len(auth) == 1:
                msg = 'Invalid "bearer" header: No credentials provided.'
                raise exceptions.AuthenticationFailed(msg)
            elif len(auth) > 2:
                msg = (
                    'Invalid "bearer" header: Credentials string should not contain spaces.'
                )
                raise exceptions.AuthenticationFailed(msg)

            return auth[1]
        else:
            return ''

    def authenticate_header(self, request):
        """
        If this method returns None, a generic HTTP 403 forbidden response is
        returned by DRF when authentication fails.

        By making the method return a string, a 401 is returned instead. The
        return value will be used as the WWW-Authenticate header.
        """
        return 'Bearer realm="%s"' % self.www_authenticate_realm
