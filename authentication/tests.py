from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

User = get_user_model()


class AuthenticationTestCase(APITestCase):
    def setUp(self):
        cache.clear()
        self.register_url = reverse("auth_register")
        self.login_url = reverse("auth_login")
        self.refresh_url = reverse("auth_refresh")
        self.logout_url = reverse("auth_logout")
        self.change_password_url = reverse("auth_change_password")
        self.password_reset_url = reverse("auth_password_reset")
        self.password_reset_confirm_url = reverse("auth_password_reset_confirm")
        self.google_login_url = reverse("auth_google")
        self.github_login_url = reverse("auth_github")
        self.apple_login_url = reverse("auth_apple")

        self.user_data = {
            "username": "authuser",
            "email": "authuser@example.com",
            "password": "strongpassword123",
            "password_confirm": "strongpassword123",
            "first_name": "Auth",
            "last_name": "User",
        }

    def test_user_registration_success(self):
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify user was created in DB
        self.assertTrue(User.objects.filter(username=self.user_data["username"]).exists())

        # Verify response formatting
        json_data = response.json()
        self.assertTrue(json_data["status"])
        self.assertEqual(json_data["message"], "The operation was successful")
        self.assertEqual(json_data["data"]["username"], self.user_data["username"])

    def test_user_registration_password_mismatch(self):
        bad_data = self.user_data.copy()
        bad_data["password_confirm"] = "differentpassword"

        response = self.client.post(self.register_url, bad_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        json_data = response.json()
        self.assertFalse(json_data["status"])
        self.assertIn("password", json_data["errors"])

    def test_user_login_success(self):
        # First, create the user
        User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password=self.user_data["password"],
        )

        # Post to login
        response = self.client.post(
            self.login_url,
            {"username": self.user_data["username"], "password": self.user_data["password"]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        json_data = response.json()
        self.assertTrue(json_data["status"])
        self.assertIn("access", json_data["data"])
        self.assertIn("refresh", json_data["data"])
        self.assertEqual(json_data["data"]["user"]["username"], self.user_data["username"])

    def test_user_login_invalid_credentials(self):
        response = self.client.post(
            self.login_url, {"username": "nonexistent", "password": "wrongpassword"}
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        json_data = response.json()
        self.assertFalse(json_data["status"])

    def test_token_refresh(self):
        # Create user & login to get refresh token
        User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password=self.user_data["password"],
        )
        login_response = self.client.post(
            self.login_url,
            {"username": self.user_data["username"], "password": self.user_data["password"]},
        )
        refresh_token = login_response.json()["data"]["refresh"]

        # Post to refresh
        response = self.client.post(self.refresh_url, {"refresh": refresh_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        json_data = response.json()
        self.assertTrue(json_data["status"])
        self.assertIn("access", json_data["data"])

    def test_user_logout_blacklists_token(self):
        # Create user & login
        User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password=self.user_data["password"],
        )
        login_response = self.client.post(
            self.login_url,
            {"username": self.user_data["username"], "password": self.user_data["password"]},
        )
        access_token = login_response.json()["data"]["access"]
        refresh_token = login_response.json()["data"]["refresh"]

        # Authenticate with JWT token
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        # Logout
        response = self.client.post(self.logout_url, {"refresh": refresh_token})
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify refresh token is blacklisted in database
        self.assertTrue(BlacklistedToken.objects.exists())

    def test_user_logout_requires_refresh_token(self):
        user = User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password=self.user_data["password"],
        )
        self.client.force_authenticate(user=user)

        response = self.client.post(self.logout_url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("refresh", response.json()["errors"])

    def test_change_password_success(self):
        user = User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password="oldpassword123",
        )
        self.client.force_authenticate(user=user)

        response = self.client.post(
            self.change_password_url,
            {
                "old_password": "oldpassword123",
                "new_password": "newpassword456",
                "new_password_confirm": "newpassword456",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user.refresh_from_db()
        self.assertTrue(user.check_password("newpassword456"))

    def test_change_password_incorrect_old_password(self):
        user = User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password="oldpassword123",
        )
        self.client.force_authenticate(user=user)

        response = self.client.post(
            self.change_password_url,
            {
                "old_password": "wrongoldpassword",
                "new_password": "newpassword456",
                "new_password_confirm": "newpassword456",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_request_sends_email(self):
        user = User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password=self.user_data["password"],
        )

        response = self.client.post(self.password_reset_url, {"email": user.email})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Password Reset Requested", mail.outbox[0].subject)

    def test_password_reset_confirm_success(self):
        user = User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password="oldpassword123",
        )
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        response = self.client.post(
            self.password_reset_confirm_url,
            {
                "uidb64": uidb64,
                "token": token,
                "new_password": "brandnewpassword123",
                "new_password_confirm": "brandnewpassword123",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user.refresh_from_db()
        self.assertTrue(user.check_password("brandnewpassword123"))

    def test_password_reset_confirm_invalid_token(self):
        user = User.objects.create_user(
            username=self.user_data["username"],
            email=self.user_data["email"],
            password="oldpassword123",
        )
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        response = self.client.post(
            self.password_reset_confirm_url,
            {
                "uidb64": uidb64,
                "token": "invalid-token-123",
                "new_password": "brandnewpassword123",
                "new_password_confirm": "brandnewpassword123",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_auth_rate_limiting_throttles_excessive_requests(self):
        for _ in range(5):
            self.client.post(self.password_reset_url, {"email": "test@example.com"})

        response = self.client.post(self.password_reset_url, {"email": "test@example.com"})
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_google_social_login_invalid_token(self):
        response = self.client.post(self.google_login_url, {"access_token": "invalid-token"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_github_social_login_invalid_token(self):
        response = self.client.post(self.github_login_url, {"access_token": "invalid-token"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_apple_social_login_invalid_token(self):
        response = self.client.post(self.apple_login_url, {"id_token": "invalid-token"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)








