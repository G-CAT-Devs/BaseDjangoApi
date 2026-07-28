from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    ChangePasswordView,
    LogoutView,
    MyTokenObtainPairView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    UserRegisterView,
)

urlpatterns = [
    path("register/", UserRegisterView.as_view(), name="auth_register"),
    path("login/", MyTokenObtainPairView.as_view(), name="auth_login"),
    path("login/refresh/", TokenRefreshView.as_view(), name="auth_refresh"),
    path("logout/", LogoutView.as_view(), name="auth_logout"),
    path("change-password/", ChangePasswordView.as_view(), name="auth_change_password"),
    path("password-reset/", PasswordResetRequestView.as_view(), name="auth_password_reset"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="auth_password_reset_confirm"),
]
