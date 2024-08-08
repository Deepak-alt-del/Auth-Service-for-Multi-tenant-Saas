# models.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser ,BaseUserManager, PermissionsMixin
from django.utils import timezone
import json



class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)


class Organization(models.Model):
    name = models.CharField(max_length=255, null=False)
    status = models.IntegerField(default=0, null=False)
    personal = models.BooleanField(default=False, null=True)
    settings = models.JSONField(default=dict, null=True, blank=True)
    created_at = models.BigIntegerField(null=True, blank=True)
    updated_at = models.BigIntegerField(null=True, blank=True)

    def __str__(self):
        return self.name

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, null=False)
    password = models.CharField(max_length=255, null=False)
    profile = models.JSONField(default=dict, null=False, blank=True)
    status = models.IntegerField(default=0, null=False)
    settings = models.JSONField(default=dict, null=True, blank=True)
    created_at = models.BigIntegerField(null=True, blank=True)
    updated_at = models.BigIntegerField(null=True, blank=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


    objects = CustomUserManager()

    def __str__(self):
        return self.email

class Role(models.Model):
    name = models.CharField(max_length=255, null=False)
    description = models.TextField(null=True, blank=True)
    org = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

class Member(models.Model):
    org = models.ForeignKey(Organization, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    status = models.IntegerField(default=0, null=False)
    settings = models.JSONField(default=dict, null=True, blank=True)
    created_at = models.BigIntegerField(null=True, blank=True)
    updated_at = models.BigIntegerField(null=True, blank=True)

    class Meta:
        unique_together = ('org', 'user', 'role')

    def __str__(self):
        return f'{self.user.email} - {self.org.name}'

