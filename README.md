Django Keycloak Authentication Configuration

This Django configuration demonstrates how to integrate Keycloak for OpenID Connect (OIDC) authentication, map Keycloak attributes to Django’s user model, and configure DRF authentication.

1. Keycloak Authentication Settings

The Keycloak integration is managed using the KEYCLOAK_AUTH_CONFIG dictionary:

KEYCLOAK_AUTH_CONFIG = {
    "OIDC_RP_CLIENT_ID": "client id",  # Your Keycloak client ID
    "OIDC_RP_CLIENT_SECRET": "secret key",  # Client secret
    "OICD_REALM": "example",  # Keycloak realm
    "OICD_HOST": "https://auth.example.com",  # Keycloak server URL
    "USER_PROFILE_MODEL": None,  # Optional custom profile model
    "OIDC_STORE_ACCESS_TOKEN": True,  # Store access token in Django session
    "OIDC_STORE_REFRESH_TOKEN": True,  # Store refresh token in Django session
    "KEYCLOAK_CAST_ATTRIBUTES": [
        'django_keycloak_auth.cast_attributes.CastDateKeycloakAttribute'
    ],  # Attribute casting
    "KEYCLOAK_ATTRIBUTES_MAPPER": {
        "username": "username",
        "email": "email",
        "last_name": "lastName",
        "first_name": "firstName",
        "report_count": "reportCount",
        # Add additional mappings as needed
    }
}

Notes:

OIDC_STORE_ACCESS_TOKEN and OIDC_STORE_REFRESH_TOKEN: Store the tokens in the session for use in API calls or DRF authentication.

KEYCLOAK_ATTRIBUTES_MAPPER: Maps Keycloak attributes to Django CustomUser model fields.

KEYCLOAK_CAST_ATTRIBUTES: Provides custom casting of attributes if required (e.g., dates).

2. Authentication Backends

Add the following backends to support both Keycloak and default Django authentication:

AUTHENTICATION_BACKENDS = (
    'django_keycloak_auth.auth.KeycloakAuth',
    'django.contrib.auth.backends.ModelBackend'
)


KeycloakAuth handles Keycloak OIDC authentication.

ModelBackend ensures fallback to Django’s default authentication.

3. Django REST Framework Integration

Configure DRF to use Keycloak OIDC authentication:

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'django_keycloak_auth.drf_auth.CustomOIDCAuthentication',
    ],
    'DEFAULT_FILTER_BACKENDS': (
        # Add your filter backends here
    ),
}


CustomOIDCAuthentication allows API endpoints to authenticate requests using the stored access token.

Filters can be customized as needed for your application.

4. Login and Logout Redirects
LOGIN_REDIRECT_URL = '/'  # Redirect after successful login
LOGOUT_REDIRECT_URL = '/'  # Redirect after logout

5. Custom User Model

If using a custom user model:

AUTH_USER_MODEL = 'users.CustomUser'


Ensure the custom user model is fully migrated before running the application.

6. Static Files Configuration
STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')


Defines the URL and root directory for serving static files.

7. Setup Instructions

Install dependencies:

pip install django-keycloak-auth


Configure KEYCLOAK_AUTH_CONFIG with your Keycloak client credentials.

Ensure your Keycloak client has the correct redirect URIs (/oidc/callback/ by default).

Apply migrations for the custom user model:

python manage.py migrate django_keycloak_auth


Start the Django server:

python manage.py runserver


Navigate to your app and test login/logout with Keycloak.

8. Additional Notes

You can add additional Keycloak attribute mappings in KEYCLOAK_ATTRIBUTES_MAPPER.

Access tokens stored in the session can be used for making API calls to Keycloak-protected resources.

Make sure django_keycloak_auth is included in INSTALLED_APPS.

9: add Middleware

MIDDLEWARE = [
    ....
    'django_keycloak_auth.auth_middleware.KeycloakMiddleware'
]