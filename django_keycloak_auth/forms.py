import logging
import traceback
import unicodedata
import requests

from rest_framework import status
from django.utils.translation import gettext_lazy as _
from django import forms
from django.core.exceptions import SuspiciousOperation
from django.contrib.auth import authenticate, get_user_model

UserModel = get_user_model()
LOGGER = logging.getLogger(__name__)


class UsernameField(forms.CharField):

    def to_python(self, value):
        return unicodedata.normalize("NFKC", super().to_python(value))

    def widget_attrs(self, widget):
        return {
            **super().widget_attrs(widget),
            "autocapitalize": "none",
            "autocomplete": "username",
        }


class CustomAuthenticationForm(forms.Form):
    """
    Base class for authenticating users. Extend this to get a form that accepts
    username/password logins.
    """

    username = UsernameField(widget=forms.TextInput(attrs={"autofocus": True}))
    password = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )

    error_messages = {
        "invalid_login":
        _("Please enter a correct %(username)s and password. Note that both "
          "fields may be case-sensitive."),
        "inactive":
        _("This account is inactive."),
        "backend":
        _("internal error. %(backend_message)s"),
    }

    def __init__(self, request=None, *args, **kwargs):
        """
        The 'request' parameter is set for custom auth use by subclasses.
        The form data comes in via the standard 'data' kwarg.
        """
        self.username_field = UserModel._meta.get_field(
            UserModel.USERNAME_FIELD)
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

    def clean(self):
        username = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")

        if username and password:
            try:
                self.user_cache = authenticate(
                    self.request,
                    username=username,
                    password=password,
                )
                if self.user_cache is None:
                    raise self.get_invalid_login_error()
                else:
                    self.confirm_login_allowed(self.user_cache)
            except requests.exceptions.ConnectionError as e:
                traceback.print_exc()
                raise self.get_backend_error(
                    'Connection error occurred. please try later')
            except requests.exceptions.Timeout as e:
                traceback.print_exc()
                raise self.get_backend_error(
                    'Request timed out. please try later')
            except requests.exceptions.HTTPError as e:
                traceback.print_exc()
                if e.response.status_code == status.HTTP_401_UNAUTHORIZED:
                    raise self.get_invalid_login_error()
                elif e.response.status_code == status.HTTP_403_FORBIDDEN:
                    raise self.get_backend_error('You do not have permission')
                else:
                    raise self.get_backend_error(str(e))
            except SuspiciousOperation as exc:
                traceback.print_exc()
                LOGGER.warning("failed to get or create user: %s", exc)
            except Exception as e:
                traceback.print_exc()
                raise self.get_backend_error(str(e))

        return self.cleaned_data

    def confirm_login_allowed(self, user):
        """
        Controls whether the given User may log in. This is a policy setting,
        independent of end-user authentication. This default behavior is to
        allow login by active users, and reject login by inactive users.

        If the given user cannot log in, this method should raise a
        ``ValidationError``.

        If the given user may log in, this method should return None.
        """
        if not user.is_active:
            raise forms.ValidationError(
                self.error_messages["inactive"],
                code="inactive",
            )

    def get_user(self):
        return self.user_cache

    def get_invalid_login_error(self):
        return forms.ValidationError(
            self.error_messages["invalid_login"],
            code="invalid_login",
            params={"username": self.username_field.verbose_name},
        )

    def get_backend_error(self, message):
        return forms.ValidationError(
            self.error_messages["backend"],
            code="backend_error_login",
            params={"backend_message": message},
        )
