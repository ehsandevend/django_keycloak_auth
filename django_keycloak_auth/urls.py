from django.urls import include, path
from . import views 

app_name = 'django_keycloak_auth'

urlpatterns = [
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
]