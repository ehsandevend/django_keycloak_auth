import json
import logging
import requests

from django.utils.encoding import force_bytes
from django.contrib.auth.backends import ModelBackend
from josepy.b64 import b64decode
from josepy.jwk import JWK
from josepy.jws import JWS, Header
from django.utils.encoding import smart_bytes, smart_str
from django.core.exceptions import SuspiciousOperation
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.module_loading import import_string
from django.utils import timezone

from django.apps import apps



django_keycloak_auth_config = apps.get_app_config("django_keycloak_auth")

UserModel = get_user_model()

LOGGER = logging.getLogger(__name__)


class KeyCloakUser():

    def __init__(self, user_info, roles):
        self.keycloak_configs = django_keycloak_auth_config.keycloak_configs
        profile_module = self.keycloak_configs.get("USER_PROFILE_MODEL", None)
        self.ProfileModel = None

        if profile_module:
            try:
                self.ProfileModel = import_string(profile_module)
            except ImportError:
                LOGGER.error("profile can't be imported")

        self.user_info = user_info
        self.KEYCLOAK_ATTRIBUTES_MAPPER = self.keycloak_configs.get(
            "KEYCLOAK_ATTRIBUTES_MAPPER", {})
        self._user_meta_fields = [f.name for f in UserModel._meta.get_fields()]
        self.profile_model = None
        self.client_roles = roles

        self._user_profile_meta_fields = [
            f.name for f in self.ProfileModel._meta.get_fields()] if self.ProfileModel else []

        self.KEYCLOAK_CAST_ATTRIBUTES = self.keycloak_configs.get(
            "KEYCLOAK_CAST_ATTRIBUTES", [])

    def get_user_model_fields(self):
        return self._user_meta_field

    def has_profile(self, user_id):
        return self.ProfileModel.objects.filter(user_id=user_id).exists() if self.ProfileModel else False

    def get_keycloak_attribute(self, field_name):
        """
            return the name of the attribute corresponding to the model field
        """
        return self.KEYCLOAK_ATTRIBUTES_MAPPER.get(field_name, field_name)

    def create_user(self):
        user_extra_fields = {}
        profile_extra_fields = {}
        user = None
        for field in self._user_meta_fields:
            attr = {}
            keycloak_attr_key = self.KEYCLOAK_ATTRIBUTES_MAPPER.get(field)
            if not keycloak_attr_key:
                continue
            keycloak_attr_val = self.get_user_attribute(keycloak_attr_key)
            if self.KEYCLOAK_CAST_ATTRIBUTES:
                for cast in self.KEYCLOAK_CAST_ATTRIBUTES:
                    casted_class = import_string(cast)
                    obj = casted_class(keycloak_attr_key, keycloak_attr_val)
                    attr.update({field: obj.apply()})
            else:
                attr.update({field: keycloak_attr_val})
            user_extra_fields.update(attr)

        user_extra_fields.update({
            "is_staff": self.has_roles(['staff', 'superuser']),
            "is_superuser": self.has_roles(['superuser']),
        })

        attributes = self.user_info.get('attributes')
        if attributes and self.ProfileModel:
            for field in self._user_profile_meta_fields:
                attr = {}
                keycloak_attr_key = self.KEYCLOAK_ATTRIBUTES_MAPPER.get(
                    field, None)
                if not keycloak_attr_key:
                    continue

                keycloak_attr_val = self.user_info.get(
                    keycloak_attr_key) | attributes.get(keycloak_attr_key)

                if self.KEYCLOAK_CAST_ATTRIBUTES:
                    for cast in self.KEYCLOAK_CAST_ATTRIBUTES:
                        casted_class = import_string(cast)
                        obj = casted_class(
                            keycloak_attr_key, keycloak_attr_val)
                        attr.update({field: obj.apply()})
                else:
                    attr.update({field: keycloak_attr_val})

                profile_extra_fields.update(attr)

        with transaction.atomic():
            user = UserModel.objects.create_user(id=self.user_info.get('id'),
                                                 username=user_extra_fields.pop(
                'username'),
                email=user_extra_fields.pop(
                'email'),
                **user_extra_fields)
            if self.ProfileModel and profile_extra_fields:
                profile, created = self.ProfileModel.objects.get_or_create(
                    user=user, defaults=profile_extra_fields)
                if not created:
                    for key, value in profile_extra_fields.items():
                        setattr(profile, key, value)
                    profile.save()
        return user

    def get_user_attribute(self, keycloak_attr_key):
        attributes = self.user_info.get('attributes')
        res = self.user_info.get(keycloak_attr_key, None)
        if not res:
            res = attributes.get(keycloak_attr_key)
        if isinstance(res, list):
            return  res[0] if len(res) <= 1 else res
        return  res
    
    def update_user(self, user, user_info):
        user_extra_fields = {}
        profile_extra_fields = {}
        for field in self._user_meta_fields:
            attr = {}
            keycloak_attr_key = self.KEYCLOAK_ATTRIBUTES_MAPPER.get(field)
            if not keycloak_attr_key:
                continue
            keycloak_attr_val = self.get_user_attribute(keycloak_attr_key)
            if self.KEYCLOAK_CAST_ATTRIBUTES:
                for cast in self.KEYCLOAK_CAST_ATTRIBUTES:
                    casted_class = import_string(cast)
                    obj = casted_class(keycloak_attr_key, keycloak_attr_val)
                    attr.update({field: obj.apply()})
            else:
                attr.update({field: keycloak_attr_val})
            user_extra_fields.update(attr)

        user_extra_fields.update({
            "is_staff": self.has_roles(['staff', 'superuser']),
            "is_superuser": self.has_roles(['superuser']),
        })

        attributes = self.user_info.get('attributes')
        if attributes:
            for field in self._user_profile_meta_fields:
                attr = {}
                keycloak_attr_key = self.KEYCLOAK_ATTRIBUTES_MAPPER.get(field)
                if not keycloak_attr_key:
                    continue
                keycloak_attr_val = self.user_info.get(
                    keycloak_attr_key) | attributes.get(keycloak_attr_key)

                if self.KEYCLOAK_CAST_ATTRIBUTES:
                    for cast in self.KEYCLOAK_CAST_ATTRIBUTES:
                        casted_class = import_string(cast)
                        obj = casted_class(
                            keycloak_attr_key, keycloak_attr_val)
                        attr.update({field: obj.apply()})
                else:
                    attr.update({field: keycloak_attr_val})

                profile_extra_fields.update(attr)

        with transaction.atomic():
            username = user_extra_fields.pop(
                'username'),
            email = user_extra_fields.pop(
                'email')
            user.email = email
            user.username = username
            for key, value in user_extra_fields.items():
                setattr(user, key, value)
            user.save()

            if profile_extra_fields:
                profile, created = self.ProfileModel.objects.get_or_create(
                    user=user, defaults=profile_extra_fields)
                if not created:
                    for key, value in profile_extra_fields.items():
                        setattr(profile, key, value)
                    profile.save()
        return user

    def create_profile(self, user_info):

        attributes = {key: value[0] for key, value in attributes.items()}

        for key, val in attributes.items():
            for cast in self.KEYCLOAK_CAST_ATTRIBUTES:
                casted_class = import_string(cast)
                attributes[key] = casted_class(key, val)

        return {}

    def has_roles(self, roles=[]):
        return any(role in self.client_roles for role in roles)

    def _update_permissions():
        pass


class KeycloakAuth(ModelBackend):

    def __init__(self):
        super().__init__()
        from django_keycloak_auth.keycloak_admin import KeycloakAdmin
        self.keycloak_manager = KeycloakAdmin()
        self.keycloak_configs = django_keycloak_auth_config.keycloak_configs
        self.OIDC_OP_JWKS_ENDPOINT = self.keycloak_configs.get(
            "OIDC_OP_JWKS_ENDPOINT")
        self.OIDC_RP_SIGN_ALGO = self.keycloak_configs.get(
            "OIDC_RP_SIGN_ALGO")
        self.OIDC_RP_IDP_SIGN_KEY = self.keycloak_configs.get(
            "OIDC_RP_IDP_SIGN_KEY")
        self.OIDC_RP_CLIENT_ID = self.keycloak_configs.get(
            "OIDC_RP_CLIENT_ID")
        self.token_info = None

    def retrieve_matching_jwk(self, token):
        """Get the signing key by exploring the JWKS endpoint of the OP."""
        response_jwks = requests.get(
            self.OIDC_OP_JWKS_ENDPOINT,
            verify=self.keycloak_configs.get("OIDC_VERIFY_SSL", True),
            timeout=self.keycloak_configs.get("OIDC_TIMEOUT", None),
            proxies=self.keycloak_configs.get("OIDC_PROXY", None),
        )
        response_jwks.raise_for_status()
        jwks = response_jwks.json()

        # Compute the current header from the given token to find a match
        jws = JWS.from_compact(token)
        json_header = jws.signature.protected
        header = Header.json_loads(json_header)

        key = None
        for jwk in jwks["keys"]:
            if self.keycloak_configs.get("OIDC_VERIFY_KID", True) and jwk[
                "kid"
            ] != smart_str(header.kid):
                continue
            if "alg" in jwk and jwk["alg"] != smart_str(header.alg):
                continue
            key = jwk
        if key is None:
            raise SuspiciousOperation("Could not find a valid JWKS.")
        return key

    def _verify_jws(self, payload, key):
        """Verify the given JWS payload with the given key and return the payload"""
        jws = JWS.from_compact(payload)

        try:
            alg = jws.signature.combined.alg.name
        except KeyError:
            msg = "No alg value found in header"
            raise SuspiciousOperation(msg)

        if alg != self.OIDC_RP_SIGN_ALGO:
            msg = (
                "The provider algorithm {!r} does not match the client's "
                "OIDC_RP_SIGN_ALGO.".format(alg)
            )
            raise SuspiciousOperation(msg)

        if isinstance(key, str):
            # Use smart_bytes here since the key string comes from settings.
            jwk = JWK.load(smart_bytes(key))
        else:
            # The key is a json returned from the IDP JWKS endpoint.
            jwk = JWK.from_json(key)

        if not jws.verify(jwk):
            msg = "JWS token verification failed."
            raise SuspiciousOperation(msg)

        return jws.payload

    def get_payload_data(self, token, key):
        """Helper method to get the payload of the JWT token."""
        if self.keycloak_configs.get("OIDC_ALLOW_UNSECURED_JWT", False):
            header, payload_data, signature = token.split(b".")
            header = json.loads(smart_str(b64decode(header)))

            # If config allows unsecured JWTs check the header and return the decoded payload
            if "alg" in header and header["alg"] == "none":
                return b64decode(payload_data)

        # By default fallback to verify JWT signatures
        return self._verify_jws(token, key)

    def get_roles(self, payload):
        realm_roles = payload.get("realm_access", {}).get("roles", [])
        client_roles = payload.get("resource_access", {}).get(
            self.OIDC_RP_CLIENT_ID, {}).get("roles", [])
        return {"realm_roles": realm_roles, "client_roles": client_roles}

    def close_session_in_failed_condition(self):
        if self.token_info:
            self.keycloak_manager.log_out_user(
                self.token_info.get('refresh_token'))

    def authenticate(self, request=None, username=None, password=None, **kwargs):
        """Authenticates a user based on the OIDC code flow."""

        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        if username is None or password is None:
            return

        self.token_info = self.keycloak_manager.get_user_access_token(
            username=username, password=password)
        self.token_info.update(
            {"created_timestamp": timezone.now().timestamp()})
        try:
            payload = self.keycloak_manager.introspect(self.token_info.get("access_token"))
            if payload:
                self.store_tokens(request=request, token_info=self.token_info)

            return self.get_or_create_user(payload)
        except Exception as e:
            self.close_session_in_failed_condition()
            raise e

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

    def get_or_create_user(self, payload):

        user_info = self.keycloak_manager.get_userinfo(payload['sub'])

        if not user_info:
            raise Exception("user info hasn't fetched")

        roles = self.get_roles(payload)

        # email based filtering
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

    def store_tokens(self, request, token_info: dict):
        """Store OIDC tokens."""
        if not request:
            return 
        session = request.session
        session["created_token_timestamp"] = token_info.get(
            'created_timestamp')
        if self.keycloak_configs.get("OIDC_STORE_ACCESS_TOKEN", False):
            session["oidc_access_token"] = token_info.get('access_token')
            session["oidc_access_expires_in"] = token_info.get('expires_in')

        if self.keycloak_configs.get("OIDC_STORE_REFRESH_TOKEN", False):
            session["oidc_refresh_token"] = token_info.get('refresh_token')
            session["oidc_refresh_expires_in"] = token_info.get(
                'refresh_expires_in')
