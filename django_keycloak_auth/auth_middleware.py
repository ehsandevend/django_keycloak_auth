import datetime
from django_keycloak_auth.keycloak_admin import KeycloakAdmin
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.utils import timezone


class KeycloakMiddleware:

    def _get_access_token_from_refresh_token(self, refresh_token):
        token_info = self.keycloak_admin.get_user_access_token_from_refresh(
            refresh_token)
        return token_info

    def __init__(self, get_response):
        # One-time configuration and initialization
        self.get_response = get_response
        self.keycloak_admin = KeycloakAdmin()
        self.jwks = self.keycloak_admin.get_jwks()

    def __call__(self, request):
        # Code to be executed for each request before the view is called
        print("Before view")
        has_access_token_exired = False
        res = None
        access_token = request.session.get('oidc_access_token')
        if access_token:
            try:
                res = self.keycloak_admin.verify_keycloak_token(
                    access_token, self.jwks)
            except Exception as e:
                has_access_token_exired = True

            if res:
                exp_time = timezone.datetime.fromtimestamp(
                    res['exp'], tz=datetime.timezone.utc)
                now = timezone.now()
                if now >= exp_time:
                    has_access_token_exired = True

            if has_access_token_exired:
                try:
                    token_info = self._get_access_token_from_refresh_token(
                        request.session.get('oidc_refresh_token'))
                    request.session["oidc_access_token"] = token_info["access_token"]
                    request.session["created_token_timestamp"] = timezone.now(
                    ).timestamp()
                except Exception as e:
                    logout(request)
                    return redirect('django_keycloak_auth:login')

        response = self.get_response(request)

        # Code to be executed for each response after the view is called
        print("After view")

        return response
