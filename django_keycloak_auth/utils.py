import datetime
import re
from django.conf import settings


class KeycloakConfig:

    MONDATORY_SETTINGS = [
        "OIDC_RP_CLIENT_ID", "OIDC_RP_CLIENT_SECRET", "OICD_REALM", "OICD_HOST"
    ]

    _DEFAULTS = {}
    KEYCLOAK_AUTH_CONFIG = None

    def __init__(self):
        pass

    def check(self):
        if not hasattr(settings, 'KEYCLOAK_AUTH_CONFIG'):
            raise RuntimeError(
                f"A dictionary named KEYCLOAK_AUTH_CONFIG representing configurations of keycloak should be in settings.py: "
            )

        self.KEYCLOAK_AUTH_CONFIG = getattr(settings, 'KEYCLOAK_AUTH_CONFIG')

        missing = [
            s for s in self.MONDATORY_SETTINGS if not s in self.KEYCLOAK_AUTH_CONFIG]
        if missing:
            raise RuntimeError(
                f"The following settings must be defined in your Django settings.py: {', '.join(missing)}"
            )

    def get_config(self, key, default=None):
        return self.KEYCLOAK_AUTH_CONFIG.get(key, default)

    def get_default_config(self):
        self._DEFAULTS = {
            "OIDC_OP_AUTHORIZATION_ENDPOINT": self.get_config("OIDC_OP_AUTHORIZATION_ENDPOINT", f"{self.KEYCLOAK_AUTH_CONFIG['OICD_HOST']}/realms/{self.KEYCLOAK_AUTH_CONFIG['OICD_REALM']}/protocol/openid-connect/auth"),
            "OIDC_OP_TOKEN_ENDPOINT": self.get_config("OIDC_OP_TOKEN_ENDPOINT", f"{self.KEYCLOAK_AUTH_CONFIG['OICD_HOST']}/realms/{self.KEYCLOAK_AUTH_CONFIG['OICD_REALM']}/protocol/openid-connect/token"),
            "OIDC_OP_USER_ENDPOINT": self.get_config("OIDC_OP_USER_ENDPOINT", f"{self.KEYCLOAK_AUTH_CONFIG['OICD_HOST']}/admin/realms/{self.KEYCLOAK_AUTH_CONFIG['OICD_REALM']}/users"),
            "OIDC_OP_JWKS_ENDPOINT": self.get_config("OIDC_OP_JWKS_ENDPOINT", f"{self.KEYCLOAK_AUTH_CONFIG['OICD_HOST']}/realms/{self.KEYCLOAK_AUTH_CONFIG['OICD_REALM']}/protocol/openid-connect/certs"),
            "OIDC_OP_VERIFY_TOKEN_ENDPOINT": self.get_config("OIDC_OP_VERIFY_TOKEN_ENDPOINT", f"{self.KEYCLOAK_AUTH_CONFIG['OICD_HOST']}/realms/{self.KEYCLOAK_AUTH_CONFIG['OICD_REALM']}/protocol/openid-connect/token/introspect"),
            "OIDC_OP_MASTER_TOKEN_ENDPOINT": self.get_config("OIDC_OP_MASTER_TOKEN_ENDPOINT", f"{self.KEYCLOAK_AUTH_CONFIG['OICD_HOST']}/realms/{self.KEYCLOAK_AUTH_CONFIG['OICD_REALM']}/protocol/openid-connect/token"),
            "OIDC_OP_LOGOUT_TOKEN_ENDPOINT": self.get_config("OIDC_OP_LOGOUT_TOKEN_ENDPOINT", f"{self.KEYCLOAK_AUTH_CONFIG['OICD_HOST']}/realms/{self.KEYCLOAK_AUTH_CONFIG['OICD_REALM']}/protocol/openid-connect/logout"),
            "OIDC_RP_CLIENT_ID": self.get_config("OIDC_RP_CLIENT_ID"),
            "OIDC_DRF_AUTH_BACKEND": self.get_config("OIDC_DRF_AUTH_BACKEND"),
            "OIDC_RP_CLIENT_SECRET": self.get_config("OIDC_RP_CLIENT_SECRET"),
            "OICD_REALM": self.get_config('OICD_REALM'),
            "OICD_HOST": self.get_config("OICD_HOST"),
            "OIDC_RP_SIGN_ALGO": self.get_config("OIDC_RP_SIGN_ALGO", "RS256"),
            "OIDC_RP_IDP_SIGN_KEY": self.get_config("OIDC_RP_IDP_SIGN_KEY", ""),
            "OIDC_STORE_ACCESS_TOKEN": self.get_config("OIDC_STORE_ACCESS_TOKEN", False),
            "OIDC_STORE_REFRESH_TOKEN": self.get_config("OIDC_STORE_REFRESH_TOKEN", False),
            "KEYCLOAK_CAST_ATTRIBUTES": self.get_config("KEYCLOAK_CAST_ATTRIBUTES", []),
            "KEYCLOAK_ATTRIBUTES_MAPPER": self.get_config("KEYCLOAK_ATTRIBUTES_MAPPER", {}),
        }
        return self._DEFAULTS


class CommonUtils(object):
    @staticmethod
    def get_formated_datetime(datetime):
        try:
            return datetime.strftime('%Y/%m/%d %I:%M %p')
        except:
            return ''

    @staticmethod
    def get_formated_date(datetime):
        return datetime.strftime('%Y/%m/%d')

    @staticmethod
    def is_date_string(date_string):
        try:
            datetime.strptime(date_string, '%Y-%m-%d')
            return True
        except:
            return False

    @staticmethod
    def is_datetime_string(date_string):
        try:
            datetime.strptime(date_string, '%Y/%m/%d %H:%M:%S')
            return True
        except:
            return False

    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]  # Get the first IP in the list
        else:
            ip = request.META.get('REMOTE_ADDR')  # Fallback to REMOTE_ADDR
        return ip
