from django.urls import path
from users.apis.v2.views.authorization import *
from users.apis.v2.views.roles import AssignSignUserView

urlpatterns = [
    path(
        r"hello/",
        HelloView.as_view(),
        name="hello-url",
    ),
    path(
        "assign-user-sign/<uuid:id>/",
        AssignSignUserView.as_view(),
        name="assign-sign-user-url",
    )
]