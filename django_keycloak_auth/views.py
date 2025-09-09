from django_keycloak_auth.forms import CustomAuthenticationForm
from django.contrib.auth import login as auth_login
from django.http import HttpResponseRedirect
from django.contrib.auth.views import LoginView
from django.contrib.auth import logout
from django.shortcuts import redirect

from django_keycloak_auth.keycloak_admin import KeycloakAdmin

class CustomLoginView(LoginView):
    form_class = CustomAuthenticationForm
    template_name = 'auth/login.html'

    def form_valid(self, form):
        """Security check complete. Log the user in."""
        auth_login(self.request, form.get_user())
        return HttpResponseRedirect(self.get_success_url())
    
def logout_view(request):
    refresh_token = request.session.get('oidc_refresh_token')
    keycloak_admin = KeycloakAdmin()
    keycloak_admin.log_out_user(refresh_token)
    logout(request)  # Logs out the user and clears session
    return redirect('django_keycloak_auth:login') 