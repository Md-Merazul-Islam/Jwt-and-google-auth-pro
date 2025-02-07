from django.http import JsonResponse
from django.contrib.auth import authenticate, login
import requests
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .serializers import (
    UserRegisterSerializer, LoginSerializer, UserSerializer,
    TokenSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, PasswordChangeSerializer
)
from django.contrib.auth import update_session_auth_hash

from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login
from .serializers import LoginSerializer
from .serializers import UserSerializer
User = get_user_model()


def success_response(message, data, status_code=status.HTTP_200_OK):
    return Response({
        "success": True,
        "statusCode": status_code,
        "message": message,
        "data": data
    }, status=status_code)


def failure_response(message, error, status_code=status.HTTP_400_BAD_REQUEST):
    return Response({
        "success": False,
        "statusCode": status_code,
        "message": message,
        "error": error
    }, status=status_code)


class ProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

    # def retrieve(self, request, *args, **kwargs):
    #     instance = self.get_object()
    #     serializer = self.get_serializer(instance)
    #     return success_response("Profile retrieved successfully", serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return success_response("Profile updated successfully", serializer.data)


class RegisterAPIView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return success_response("Registration successful. You can now log in.", response.data, status.HTTP_201_CREATED)





class CustomRefreshToken(RefreshToken):
    @classmethod 
    def for_user(self, user):
        refresh_token = super().for_user(user)

        # Add custom claims
        refresh_token.payload['username'] = user.username
        refresh_token.payload['email'] = user.email
        # refresh_token.payload['id'] = user.id
        # Assuming 'role' is an attribute of the user
        refresh_token.payload['role'] = user.role

        return refresh_token


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            refresh = CustomRefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response = Response({
                'success': True,
                'statusCode': status.HTTP_200_OK,
                'message': 'Login successful',
                'data': {
                    'access': access_token,
                    'refresh': refresh_token,
                }
            })

            # Set HttpOnly cookie for refresh token
            response.set_cookie('refresh_token', refresh_token,
                                httponly=True, secure=True)

            login(request, user)
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You have access!"}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Add the refresh token to the blacklist

                response = success_response("Logout successful")
                response.delete_cookie('refresh_token')  # Delete the refresh token cookie
                return response
            return failure_response("Refresh token not provided")
        except Exception as e:
            return failure_response("Logout failed", str(e), status.HTTP_400_BAD_REQUEST)


class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            try:
                new_access = RefreshToken(refresh_token).access_token
                return success_response("Token refreshed successfully", {"access": str(new_access)}, status.HTTP_200_OK)
            except Exception as e:
                return failure_response("Failed to refresh token", str(e), status.HTTP_400_BAD_REQUEST)
        return failure_response("Refresh token not provided", {}, status.HTTP_400_BAD_REQUEST)

class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        # Check if the old password is correct
        if not user.check_password(old_password):
            return failure_response("Incorrect old password", {"detail": "Incorrect old password"}, status.HTTP_400_BAD_REQUEST)

        # Update password
        user.set_password(new_password)
        user.save()

        # Update session to prevent logout after password change
        update_session_auth_hash(request, user)

        return success_response({"message": "Password changed successfully"}, status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['email']
        token = PasswordResetTokenGenerator().make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://127.0.0.1:8000/api/v1/auth/reset-password/{uidb64}/{token}/"

        # Log reset link for debugging
        # print(f"Generated Reset Link: {reset_link}")

        return success_response("Password reset link generated", {"reset_link": reset_link}, status.HTTP_200_OK)

class ResetPasswordView(APIView):
    def post(self, request, uidb64, token):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError):
            return Response({"error": "Invalid link"}, status=status.HTTP_400_BAD_REQUEST)

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)

# googel auth




class GoogleLoginView(APIView):
    def get(self, request):
        # Google OAuth authorization URL
        google_auth_url = (
            f"https://accounts.google.com/o/oauth2/auth?response_type=code"
            f"&client_id={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY}"
            f"&redirect_uri={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI}"
            f"&scope=email%20profile"
        )
        # Respond with the Google auth URL to redirect the user
        return Response({"auth_url": google_auth_url})


class GoogleAuthCallbackView(APIView):
    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return Response({"error": "No authorization code found."}, status=400)

        # print(settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY)
        # print(settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET)
        # print(settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI)
        # Exchange authorization code for access token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            "client_secret": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            "redirect_uri": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI,
            "grant_type": "authorization_code",
        }

        # Get the access token from Google
        token_response = requests.post(token_url, data=data)
        if token_response.status_code != 200:
            return Response({"error": "Failed to get access token."}, status=400)

        token_response_data = token_response.json()
        access_token = token_response_data.get("access_token")

        # Get user info from Google API using the access token
        user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        user_info_response = requests.get(
            user_info_url, headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_info_response.status_code != 200:
            return Response({"error": "Failed to fetch user information."}, status=400)

        user_data = user_info_response.json()
        email = user_data.get("email")
        name = user_data.get("name")

        # Create or get the user
        user, created = User.objects.get_or_create(
            username=email, defaults={"email": email, "first_name": name})

        # Create JWT token for the user
        refresh = RefreshToken.for_user(user)

        # Respond with the JWT tokens and user information
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "id": user.id,
                "name": user.first_name,
                "email": user.email
            }
        })
