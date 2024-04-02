from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import AccessToken
from users.serializers import UserSerializer
from .models import User
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
import jwt
from django.core import mail
from backend.settings import APP_ENV, FROM_EMAIL, TEST_RECEPIENT, FRONTEND_LINK


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class TestView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        content = {'message': 'Test, Successful'}
        return Response(content)


class UserView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        token = request.META['HTTP_AUTHORIZATION'].split(" ")[1]
        try:
            access_token_obj = AccessToken(token)
            user_id = access_token_obj['user_id']
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed(
                'Could not verify token\'s authenticity!')
        user = User.objects.filter(id=user_id).first()
        return Response(UserSerializer(user).data)


class VerifyUserView(APIView):
    def patch(self, request):
        verified = request.data["verified"]
        verification_token = request.data["verification_token"]
        user_id = int(force_text(urlsafe_base64_decode(verification_token)))
        user_object = User.objects.filter(id=user_id).get()
        user_object.verified = verified
        user_object.save()
        return Response({"success": verified, "email": user_object.email})


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            refresh_token = RefreshToken(refresh_token)
            refresh_token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordView(APIView):
    """Takes the request of forgot password and issues a token and sends it via mail"""

    def post(self, request):
        try:
            # Extracting email
            email = request.data["email"]
            # Extracting user object from email
            try:
                user_object = User.objects.filter(email=email).get()
                print("user_object")
                print(user_object)
            except:
                return Response({"success": False, "message": "email not registered"},
                                status=status.HTTP_501_NOT_IMPLEMENTED)
            # Generating token
            token = default_token_generator.make_token(user_object)
            print("Link: "+FRONTEND_LINK + "/reset-forgot-password/" + token + "/" + str(user_object.id))
            # sending email with token and link
            msg_text = "Hi " + user_object.first_name + \
                       ",<br/>" + "This is password reset for <b>" + user_object.email + "</b>, if this is your email.<br>Go to below link:<br><a href=\"" + \
                       FRONTEND_LINK + "/reset-forgot-password/" + \
                       token + "/" + str(user_object.id) + "\">Click here</a>"
            if (APP_ENV != "DEV"):
                mail.send_mail('Reset Forgot password', msg_text, FROM_EMAIL, [
                    user_object.email], html_message=msg_text)
            else:
                mail.send_mail('Reset Forgot password', msg_text, FROM_EMAIL, [
                    TEST_RECEPIENT], html_message=msg_text)

            # Returning response
            return Response({"success": True}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response(status=status.HTTP_501_NOT_IMPLEMENTED)


class VerifyForgotPasswordTokenView(APIView):
    """Simply verifies if token is valid or not"""

    def post(self, request):
        token = request.data["token"]
        user_id = request.data["uid"]

        # Get user object
        try:
            user_object = User.objects.filter(id=user_id).get()
        except Exception as err:
            print(err)
            return Response({"valid": False}, status=status.HTTP_401_UNAUTHORIZED)
        # Check the validity of token
        response = default_token_generator.check_token(user_object, token)
        if response:
            return Response({"valid": True, "email": user_object.email}, status=status.HTTP_200_OK)
        else:
            return Response({"valid": False}, status=status.HTTP_401_UNAUTHORIZED)


class ResetForgotPasswordView(APIView):
    """Resets the password via forgot token"""

    def post(self, request):
        try:
            token = request.data["token"]
            user_id = request.data["uid"]
            newPassword = request.data["newPassword"]

            # Get user object
            user_object = User.objects.filter(id=user_id).get()
            # Check the validity of token
            response = default_token_generator.check_token(user_object, token)
            if (response):
                # If token is valid, reset password
                user_object.set_password(newPassword)
                user_object.save()
                return Response({"success": True}, status=status.HTTP_202_ACCEPTED)
            else:
                # If token is invalid, send Error response
                return Response({"success": False, "message": "Invalid token"}, status=status.HTTP_502_BAD_GATEWAY)
        except Exception as e:
            # If exception occurs, send Error response
            print("Error occurred")
            print(e)
            return Response({"success": False, "message": "Error occurred"}, status=status.HTTP_502_BAD_GATEWAY)
