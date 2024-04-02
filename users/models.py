import datetime
from typing_extensions import Required
from xmlrpc.client import DateTime
from django.db import models
from django.contrib.auth.models import AbstractUser
from pkg_resources import require

# Create your models here.


class User(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    verified = models.BooleanField(default=False)
    gender = models.CharField(max_length=255)
    profile_picture = models.CharField(max_length=1000)
    date_of_birth = models.CharField(max_length=11)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name', 'gender', 'date_of_birth']
