from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):

    class Plan(models.TextChoices):
        FREE = "free", "Free"
        PLUS = "plus", "Plus"
        PRO = "pro", "Pro"

    email = models.EmailField(unique=True)
    plan = models.CharField(max_length=10, choices=Plan.choices, default=Plan.FREE)
    is_verified = models.BooleanField(default=False)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
