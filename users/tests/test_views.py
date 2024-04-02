from users.models import User
from .test_setup import TestSetUp
import base64
from django.contrib.auth.tokens import default_token_generator
"""
> For debugging:

import pdb
pdb.set_trace()

> For coverage:

coverage run --source='users' manage.py test && coverage report
coverage run --source='users' manage.py test && coverage report && coverage html
"""


class RegisterViews(TestSetUp):
    """Testing Signup endpoint"""

    def test_user_cannot_register_with_no_data(self):
        res = self.client.post(self.register_url)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json(), {
            "username": [
                "This field is required."
            ],
            "first_name": [
                "This field is required."
            ],
            "last_name": [
                "This field is required."
            ],
            "email": [
                "This field is required."
            ],
            "password": [
                "This field is required."
            ],
            "gender": [
                "This field is required."
            ],
            "date_of_birth": [
                "This field is required."
            ],
            "profile_picture": [
                "This field is required."
            ]
        })

    def test_user_can_register_correctly(self):
        # Sending request
        res = self.client.post(
            self.register_url, self.user_data, format="json")
        """ Test 1: Check status code """
        self.assertEqual(res.status_code, 200)

        """ Test 2: Check response object """
        """ Changing user_data and res.data from json to dictionary for comparison """
        # Adding id in user data and sorting it again
        user_data_dict = sorted(self.user_data.items())
        user_data_dict.append(("id", 1))
        user_data_dict = sorted(user_data_dict)
        # Adding password in response data and sorting it again
        response_data_dict = sorted(res.data.items())
        response_data_dict.append(("password", "test123"))
        user_data_dict.append(("verified", False))
        response_data_dict = sorted(response_data_dict)
        self.assertEqual(user_data_dict, response_data_dict)


class LoginViews(TestSetUp):
    """Testing login endpoint"""

    def test_user_valid_credentials(self):
        """Test 1: Testing login with valid login credentials"""
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login with registered email and password
        res = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": self.user_data["password"]}, format="json")
        # Check for status
        self.assertEqual(res.status_code, 200)
        # Check for returned response data
        response_dict = sorted(res.data.items())
        self.assertEqual(response_dict[0][0], 'access')
        self.assertEqual(len(response_dict[0][1]), 228)
        self.assertEqual(response_dict[1][0], 'refresh')
        self.assertEqual(len(response_dict[1][1]), 229)

    def test_user_invalid_email(self):
        """Test 2: Testing login with wrong email"""
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login with wrong email
        res = self.client.post(self.login_url, {
            "email": "abc@xyz.com", "password": self.user_data["password"]}, format="json")
        # Check for status
        self.assertEqual(res.status_code, 401)
        # Check for response
        self.assertEqual(res.data['detail'].code, 'no_active_account')
        self.assertEqual(res.data['detail'].title(
        ), 'No Active Account Found With The Given Credentials')

    def test_user_invalid_password(self):
        """Test 3: Testing login with wrong password"""
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login with wrong password
        res = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": "abc"}, format="json")
        # Check for status
        self.assertEqual(res.status_code, 401)
        # Check for response
        self.assertEqual(res.data['detail'].code, 'no_active_account')
        self.assertEqual(res.data['detail'].title(
        ), 'No Active Account Found With The Given Credentials')


class GetAccessTokenView(TestSetUp):
    """Testing access token from refresh token endpoint"""

    def test_get_access_token_from_refresh_token(self):
        """Test 1: Testing if receiving fresh access token"""
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login
        response = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": self.user_data["password"]}, format="json")
        response_dict = sorted(response.data.items())
        refresh_token = response_dict[1][1]
        # Sending request
        res = self.client.post(
            self.getNewAccessToken_url, {"refresh": refresh_token}, format="json")
        self.assertEqual(res.status_code, 200)
        res_dict = sorted(res.data.items())
        self.assertEqual(res_dict[0][0], 'access')
        self.assertEqual(len(res_dict[0][1]), 228)

    def test_dont_get_access_token_from_invalid_refresh_token(self):
        """Test 2: Testing should not receive access token on invalid refresh token"""
        # Sending request
        res = self.client.post(
            self.getNewAccessToken_url, {"refresh": "invalid_refresh_token"}, format="json")
        self.assertEqual(res.status_code, 401)
        res_dict = sorted(res.data.items())
        self.assertNotEqual(res_dict[0][0], 'access')
        self.assertNotEqual(len(res_dict[0][1]), 228)
        self.assertEqual(res.data['detail'].code, 'token_not_valid')
        self.assertEqual(res.data['detail'].title(),
                         'Token Is Invalid Or Expired')


class UserDataView(TestSetUp):
    """Testing user details end point"""

    def test_get_user_details_from_access_token(self):
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login
        response = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": self.user_data["password"]}, format="json")
        response_dict = sorted(response.data.items())
        access_token = response_dict[0][1]
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        res = self.client.get(self.getUserData_url, **auth_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data['first_name'], self.user_data['first_name'])
        self.assertEqual(res.data['last_name'], self.user_data['last_name'])
        self.assertEqual(res.data['username'], self.user_data['username'])
        self.assertEqual(res.data['email'], self.user_data['email'])
        self.assertEqual(res.data['gender'], self.user_data['gender'])
        self.assertEqual(res.data['date_of_birth'],
                         self.user_data['date_of_birth'])
        self.assertEqual(res.data['profile_picture'],
                         self.user_data['profile_picture'])
        self.assertEqual(res.data['verified'], False)

    def test_not_get_user_details_from_invalid_access_token(self):
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + 'invalid_access_token',
        }
        res = self.client.get(self.getUserData_url, **auth_headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.data['detail'].code, 'token_not_valid')
        self.assertEqual(res.data['detail'].title(),
                         'Given Token Not Valid For Any Token Type')


class TestAuthenticatedView(TestSetUp):
    """Testing authenticated route view"""

    def test_authenticated_route(self):
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login
        response = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": self.user_data["password"]}, format="json")
        response_dict = sorted(response.data.items())
        access_token = response_dict[0][1]
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        res = self.client.get(self.testAuthenticated_url, **auth_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data, {'message': 'Test, Successful'})

    def test_authenticated_route_without_token(self):
        res = self.client.get(self.testAuthenticated_url)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.data['detail'].code, 'not_authenticated')
        self.assertEqual(res.data['detail'].title(
        ), 'Authentication Credentials Were Not Provided.')

    def test_authenticated_route_with_invalid_token(self):
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + 'invalid_access_token',
        }
        res = self.client.get(self.testAuthenticated_url, **auth_headers)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.data['detail'].code, 'token_not_valid')
        self.assertEqual(res.data['detail'].title(
        ), 'Given Token Not Valid For Any Token Type')


class LogoutView(TestSetUp):
    """Testing logout view"""

    def test_logout(self):
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login with registered email and password
        response = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": self.user_data["password"]}, format="json")

        response_dict = sorted(response.data.items())

        access_token = response_dict[0][1]
        refresh_token = response_dict[1][1]

        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        # Logout request
        res = self.client.post(
            self.logout_url, {"refresh": refresh_token}, format="json", **auth_headers)
        # Check for status
        self.assertEqual(res.status_code, 205)
        # Try getting access token from refresh token since it shoul be blacklisted
        res_refresh = self.client.post(
            self.getNewAccessToken_url, {"refresh": refresh_token}, format="json")

        self.assertEqual(res_refresh.status_code, 401)
        self.assertEqual(res_refresh.data['detail'].code, 'token_not_valid')
        self.assertEqual(
            res_refresh.data['detail'].title(), 'Token Is Blacklisted')

    def test_invalid_refresh_token_logout(self):
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login with registered email and password
        response = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": self.user_data["password"]}, format="json")

        response_dict = sorted(response.data.items())

        access_token = response_dict[0][1]
        refresh_token = response_dict[1][1]

        auth_headers = {
            'HTTP_AUTHORIZATION': 'Bearer ' + access_token,
        }
        # Logout request
        res = self.client.post(
            self.logout_url, {"refresh": refresh_token+'making_token_invalid'}, format="json", **auth_headers)
        # Check for status
        self.assertEqual(res.status_code, 400)

    def test_logout_without_authentication(self):
        # First register the email and password
        self.client.post(
            self.register_url, self.user_data, format="json")
        # Then login with registered email and password
        response = self.client.post(self.login_url, {
            "email": self.user_data["email"], "password": self.user_data["password"]}, format="json")

        response_dict = sorted(response.data.items())

        # access_token = response_dict[0][1]
        refresh_token = response_dict[1][1]

        # Logout request
        res = self.client.post(
            self.logout_url, {"refresh": refresh_token+'making_token_invalid'}, format="json")
        # Check for status
        self.assertEqual(res.status_code, 401)


class TestForgotPasswordView(TestSetUp):
    """Testing forgot-password endpoint"""

    def test_invalid_email(self):
        """Sending invalid email"""
        res = self.client.post(self.forgot_password_url, {
            "email": self.user_data["email"]}, format="json")
        self.assertEqual(res.status_code, 501)
        self.assertEqual(
            res.data, {'success': False, 'message': 'email not registered'})

    def test_valid_unregistered_email(self):
        """Sending unregistered email"""
        res = self.client.post(self.forgot_password_url, {
            "email": self.user_data["email"]}, format="json")
        self.assertEqual(res.status_code, 501)
        self.assertEqual(
            res.data, {'success': False, 'message': 'email not registered'})

    def test_valid_registered_email(self):
        """Sending registered email"""
        self.client.post(
            self.register_url, self.user_data, format="json")
        res = self.client.post(self.forgot_password_url, {
            "email": self.user_data["email"]}, format="json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data, {'success': True})


class VerifyForgotPasswordTokenView(TestSetUp):
    """Testing Forgot Password token endpoint"""

    def test_invalid_forgot_password_token(self):
        """Sending invalid token"""
        res = self.client.post(self.verify_forgot_password_token_url, {
                               'token': 'invalid-token', 'uid': 1}, format="json")
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.data, {'valid': False})

    def test_valid_forgot_password_token(self):
        """Sending valid token"""
        # Registering user
        user_obj = self.client.post(
            self.register_url, self.user_data, format="json")

        # generating Forgot password token
        user_object = User.objects.filter(id=user_obj.data["id"]).get()
        token = default_token_generator.make_token(user_object)

        # Sending request to verify token
        res = self.client.post(self.verify_forgot_password_token_url, {
                               'token': token, 'uid': user_obj.data["id"]}, format="json")
        # Verifying response
        self.assertEqual(res.status_code, 200)
        self.assertEqual(
            res.data, {'valid': True, 'email': user_obj.data['email']})


class ResetForgotPasswordView(TestSetUp):
    """Testing reset forgot password endpoint"""

    def test_sending_valid_password_reset_token_and_uid(self):
        test_password = "thisIsATestPassword100"
        # Registering user
        user_obj = self.client.post(
            self.register_url, self.user_data, format="json")

        # generating Forgot password token
        user_object = User.objects.filter(id=user_obj.data["id"]).get()
        token = default_token_generator.make_token(user_object)

        # Sending request to reset password
        res = self.client.post(self.reset_forgot_password_url, {
                               'token': token, 'uid': user_obj.data["id"], 'newPassword': test_password}, format="json")

        # Testing response
        self.assertEqual(res.status_code, 202)
        self.assertEqual(
            res.data, {'success': True})

        # Testing if login works with new password
        response = self.client.post(self.login_url, {
            "email": user_obj.data['email'], "password": test_password}, format="json")
        self.assertEqual(response.status_code, 200)
        response_dict = sorted(response.data.items())
        self.assertEqual(response_dict[0][0], 'access')
        self.assertEqual(len(response_dict[0][1]), 228)
        self.assertEqual(response_dict[1][0], 'refresh')
        self.assertEqual(len(response_dict[1][1]), 229)
