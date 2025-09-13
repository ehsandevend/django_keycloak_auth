from django.apps import AppConfig
from . import utils



class DjangoKeycloakAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_keycloak_auth'
    keycloak_configs = None

    def ready(self):
        self.keycloak_config_loader = utils.KeycloakConfig()
        self.keycloak_config_loader.check()
        self.keycloak_configs = self.keycloak_config_loader.get_default_config()