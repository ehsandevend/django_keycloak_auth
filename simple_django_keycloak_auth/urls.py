"""
URL configuration for simple_django_keycloak_auth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
import datetime

from django.contrib import admin
from django.urls import path, include
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse


@login_required(login_url='/user/login/')
def home(request):
    created_token_timestamp = datetime.datetime.fromtimestamp(request.session.get('created_token_timestamp'))
    html_string = f"""
    <h1> Hello {request.user.username}</h1>
    <h3> refresh token: {request.session.get('oidc_refresh_token')}</h3>
    <h3> access token: {request.session.get('oidc_access_token')}</h3>
    <h3> now: {timezone.now()}</h3>
    <h3> created datetime: {created_token_timestamp}</h3>
    <h3> expired access token datetime: {created_token_timestamp + datetime.timedelta(seconds=request.session.get('oidc_access_expires_in'))}</h3>
    <h3> expired refresh token datetime: {created_token_timestamp + datetime.timedelta(seconds=request.session.get('oidc_refresh_expires_in'))}</h3>
    <a href='/keycloak/logout/'> logout </a>
"""
    return HttpResponse(html_string)

urlpatterns = [
    path('', home),
    path('admin/', admin.site.urls),
    path('keycloak/', include('django_keycloak_auth.urls')),
    path('drf/', include('users.apis.v2.urls')),

]