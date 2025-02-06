from django.urls import path
from .views import (
    RegisterAPIView, LoginView, ProtectedView,
    LogoutView, RefreshTokenView, ForgotPasswordView, GoogleLoginView, GoogleAuthCallbackView, PasswordChangeView, ResetPasswordView, ProfileView
)

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('protected-endpoint/', ProtectedView.as_view(), name='protected'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('password-change/', PasswordChangeView.as_view(), name='password_change'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/<uidb64>/<token>/',
         ResetPasswordView.as_view(), name='reset_password'),
    # ---- google auth
    path('google/', GoogleLoginView.as_view(), name='google_login'),
    path('google/callback/',
         GoogleAuthCallbackView.as_view(), name='google_callback'),
]
