from django.apps import apps
import requests
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils import timezone
from rest_framework import exceptions, status
from django.core.exceptions import SuspiciousOperation
from django_keycloak_auth.exeptions import InvalidCredentials
from django_keycloak_auth.models import AccessToken

UserModel = get_user_model()


django_keycloak_auth_config = apps.get_app_config("django_keycloak_auth")


class KeycloakAdmin():

    def __init__(self):
        self.keycloak_configs = django_keycloak_auth_config.keycloak_configs
        self.OIDC_OP_TOKEN_ENDPOINT = self.keycloak_configs.get(
            "OIDC_OP_TOKEN_ENDPOINT")
        self.OIDC_OP_VERIFY_TOKEN_ENDPOINT = self.keycloak_configs.get(
            "OIDC_OP_VERIFY_TOKEN_ENDPOINT")
        self.OIDC_OP_MASTER_TOKEN_ENDPOINT = self.keycloak_configs.get(
            "OIDC_OP_MASTER_TOKEN_ENDPOINT")
        self.OIDC_OP_USER_ENDPOINT = self.keycloak_configs.get(
            "OIDC_OP_USER_ENDPOINT")
        self.OIDC_OP_JWKS_ENDPOINT = self.keycloak_configs.get(
            "OIDC_OP_JWKS_ENDPOINT")
        self.OIDC_RP_CLIENT_ID = self.keycloak_configs.get("OIDC_RP_CLIENT_ID")
        self.OIDC_RP_CLIENT_SECRET = self.keycloak_configs.get(
            "OIDC_RP_CLIENT_SECRET")
        self.OIDC_OP_LOGOUT_TOKEN_ENDPOINT = self.keycloak_configs.get(
            "OIDC_OP_LOGOUT_TOKEN_ENDPOINT")
        self.OICD_REALM = self.keycloak_configs.get(
            "OICD_REALM")
        self.OICD_HOST = self.keycloak_configs.get(
            "OICD_HOST")
        self.OIDC_VERIFY_SSL = self.keycloak_configs.get(
            "OIDC_VERIFY_SSL", True)
        self.OIDC_TIMEOUT = self.keycloak_configs.get("OIDC_TIMEOUT", None)
        self.OIDC_PROXY = self.keycloak_configs.get("OIDC_PROXY", None)

    def introspect(self, token):
        payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "token": token,
        }

        response = requests.post(
            self.OIDC_OP_VERIFY_TOKEN_ENDPOINT,
            data=payload,
            verify=self.OIDC_VERIFY_SSL,
            timeout=self.OIDC_TIMEOUT,
            proxies=self.OIDC_PROXY,
        )
        response.raise_for_status()
        token_info = response.json()
        return token_info

    def _request_admin_token(self):
        payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "grant_type": "client_credentials",
            "scope": "openid profile"
        }

        response = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            verify=self.OIDC_VERIFY_SSL,
            timeout=self.OIDC_TIMEOUT,
            proxies=self.OIDC_PROXY,
        )
        response.raise_for_status()
        token_info = response.json()
        return token_info

    def _save_admin_access_token(self, token_info, curr_access_token=None):
        _curr_access_token = curr_access_token
        if _curr_access_token:
            _curr_access_token.token = token_info['access_token']
            _curr_access_token.expires_at = timezone.now(
            ) + timezone.timedelta(seconds=token_info["expires_in"])
            _curr_access_token.save()
            return _curr_access_token

        access_token_obj = AccessToken.objects.create(
            **{
                'token':
                token_info['access_token'],
                'expires_at':
                timezone.now() +
                timezone.timedelta(seconds=token_info["expires_in"])
            })
        return access_token_obj

    def _get_admin_access_token(self):
        access_token_entry = AccessToken.objects.order_by('-pk').last()
        token_info = None

        if access_token_entry:
            token = access_token_entry.token
            try:
                res = self.introspect(token)
                if 'active' in res and not res['active']:
                    token_info = self._request_admin_token()
                    access_token_entry = self._save_admin_access_token(
                        token_info, access_token_entry)
            except Exception as e:
                token_info = self._request_admin_token()
                access_token_entry = self._save_admin_access_token(
                    token_info, access_token_entry)
        else:
            token_info = self._request_admin_token()
            access_token_entry = self._save_admin_access_token(
                token_info, access_token_entry)

        return access_token_entry.token

    def get_user_access_token(self, username, password):

        if not username or not password:
            return

        payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "grant_type": "password",
            "username": username,
            "password": password
        }

        response = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            verify=self.OIDC_VERIFY_SSL,
            timeout=self.OIDC_TIMEOUT,
            proxies=self.OIDC_PROXY,
        )
        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            raise InvalidCredentials()
        elif response.status_code == status.HTTP_403_FORBIDDEN:
            raise exceptions.PermissionDenied()
        elif status.is_server_error(response.status_code):
            raise exceptions.AuthenticationFailed()
        elif status.is_client_error(response.status_code):
            raise exceptions.AuthenticationFailed()
        token_info = response.json()
        return token_info

    def get_user_access_token_from_refresh(self, refresh_token):
        payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        response = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            verify=self.OIDC_VERIFY_SSL,
            timeout=self.OIDC_TIMEOUT,
            proxies=self.OIDC_PROXY,
        )
        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            raise InvalidCredentials()
        elif response.status_code == status.HTTP_403_FORBIDDEN:
            raise exceptions.PermissionDenied()
        elif status.is_server_error(response.status_code):
            raise exceptions.AuthenticationFailed()
        elif status.is_client_error(response.status_code):
            raise exceptions.AuthenticationFailed()
        token_info = response.json()
        return token_info

    def get_roles(self, payload):
        realm_roles = payload.get("realm_access", {}).get("roles", [])
        client_roles = payload.get("resource_access", {}).get(
            self.OIDC_RP_CLIENT_ID, {}).get("roles", [])
        return {"realm_roles": realm_roles, "client_roles": client_roles}

    def get_userinfo(self, user_id=None, username=None):
        """Return user details dictionary. The id_token and payload are not used in
        the default implementation, but may be used when overriding this method"""
        admin_access_token = self._get_admin_access_token()
        if username:
            user_response = requests.get(
                f"{self.OIDC_OP_USER_ENDPOINT}/?username={username}",
                headers={"Authorization": "Bearer {0}".format(
                    admin_access_token)},
                verify=self.OIDC_VERIFY_SSL,
                timeout=self.OIDC_TIMEOUT,
                proxies=self.OIDC_PROXY,
            )
        elif user_id:
            user_response = requests.get(
                f"{self.OIDC_OP_USER_ENDPOINT}/{user_id}",
                headers={"Authorization": "Bearer {0}".format(
                    admin_access_token)},
                verify=self.OIDC_VERIFY_SSL,
                timeout=self.OIDC_TIMEOUT,
                proxies=self.OIDC_PROXY,
            )
        else:
            raise ValueError("Must provide either user_id or username")

        user_response.raise_for_status()
        user_info = user_response.json()
        return user_info

    def get_jwks(self):
        response = requests.get(self.OIDC_OP_JWKS_ENDPOINT)
        response.raise_for_status()
        jwks = response.json()
        return jwks

    def verify_keycloak_token(self, token: str,  jwks: str = None):
        jwks = self.get_jwks()
        try:
            claims = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                options={"verify_aud": False},
                issuer=f"{self.OICD_HOST}/realms/{self.OICD_REALM}"
            )
            return claims
        except ExpiredSignatureError:
            raise Exception("Token expired")
        except JWTError as e:
            raise Exception(f"Invalid token: {str(e)}")

    def decode(self, token: str,  jwks: str = None):
        jwks = self.get_jwks()
        try:
            claims = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                options={"verify_aud": False},
                issuer=f"{self.OICD_HOST}/realms/{self.OICD_REALM}"
            )
            return claims
        except ExpiredSignatureError:
            raise Exception("Token expired")
        except JWTError as e:
            raise Exception(f"Invalid token: {str(e)}")

    def log_out_user(self, refresh_token):
        payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "refresh_token": refresh_token,
        }
        endpoint = self.OIDC_OP_LOGOUT_TOKEN_ENDPOINT
        response = requests.post(
            endpoint,
            data=payload,
            verify=self.OIDC_VERIFY_SSL,
            timeout=self.OIDC_TIMEOUT,
            proxies=self.OIDC_PROXY,
        )
        response.raise_for_status()

    def roles_from_token(self, token, raise_exception=True):
        """
        Get roles from token

        Args:
            token (string): The string value of the token.
            raise_exception: Raise exception if the request ended with a status >= 400.

        Returns:
            list: List of roles.
        """
        token_decoded = self.introspect(token)

        realm_access = token_decoded.get("realm_access", None)
        resource_access = token_decoded.get("resource_access", None)
        client_access = (
            resource_access.get(self.client_id, None)
            if resource_access is not None
            else None
        )

        client_roles = (
            client_access.get(
                "roles", None) if client_access is not None else None
        )
        realm_roles = (
            realm_access.get(
                "roles", None) if realm_access is not None else None
        )

        if client_roles is None:
            return realm_roles
        if realm_roles is None:
            return client_roles
        return client_roles + realm_roles

    def get_or_create_user(self, payload=None, user_info=None):
        from django_keycloak_auth.auth import KeyCloakUser
        if not user_info:
            user_info = self.get_userinfo(payload['sub'])
        
        if not user_info:
            raise Exception("user info hasn't fetched")

        roles = self.get_roles(payload)

        users = self.filter_users_by_claims(user_info)
        keycloak_user = KeyCloakUser(
            user_info=user_info, roles=roles['client_roles'])
        if len(users) == 1:
            return keycloak_user.update_user(users[0], user_info)
        elif len(users) > 1:
            # In the rare case that two user accounts have the same email address,
            # bail. Randomly selecting one seems really wrong.
            msg = "Multiple users returned"
            raise SuspiciousOperation(msg)
        elif self.keycloak_configs.get("OIDC_CREATE_USER", True):
            user = keycloak_user.create_user()
            return user
        else:
            return None

    def filter_users_by_claims(self, claims):
        if 'id' in claims:
            user_id = claims.get("id")
            if not user_id:
                return UserModel.objects.none()
            return UserModel.objects.filter(id=user_id)
        elif 'username' in claims:
            username = claims.get("username")
            if not username:
                return UserModel.objects.none()
            return UserModel.objects.filter(username=username)
        return UserModel.objects.none()
