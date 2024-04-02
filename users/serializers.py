from pathlib import Path
from rest_framework import serializers
from .models import User
from django.core import mail
# from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from backend.settings import APP_ENV, FROM_EMAIL, TEST_RECEPIENT, FRONTEND_LINK


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name',
                  'last_name', 'email', 'password', 'gender', 'date_of_birth', 'profile_picture', 'verified']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)

        instance.save()

        user_primary_key = instance.pk
        verification_token = urlsafe_base64_encode(
            force_bytes(user_primary_key))

        user_email = validated_data.get('email')
        user_first_name = validated_data.get('first_name')
        msg_text = "Hi "+user_first_name + \
            ",<br/>"+"This is confirmation message for signing up for ABC.<br>We want to verify <b>" + \
            user_email+"</b>, if this is your email.<br>Go to below link:<br><a href=\"" + \
            FRONTEND_LINK + "/verify-user/" + \
            verification_token + "\">Click here</a>"
        try:
            if APP_ENV != "DEV":
                mail.send_mail('User confirmation', msg_text, FROM_EMAIL, [
                    user_email], html_message=msg_text)
            else:
                mail.send_mail('User confirmation', msg_text, FROM_EMAIL, [
                    TEST_RECEPIENT], html_message=msg_text)
        except Exception as e:
            print("EXCEPTION OCCURRED")
            print(e)
        return instance
