import uuid
from django.db import models
from django.urls import reverse
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser, User
)
from datetime import datetime
from django.db.models import signals


class TimeStampModel(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UserManager(BaseUserManager):

    def create_user(self, email=None, password=None):
        """
        Creates and saves a User with the given email and password.
        """
        user = self.model(
            email=self.normalize_email(email),
        )

        user.set_password(password)
        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)
        return user

    def create_staffuser(self, email, password):
        """
        Creates and saves a staff user with the given email and password.
        """
        user = self.create_user(
            email=email,
            password=password,
        )
        user.is_active = True
        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        # import pdb; pdb.set_trace()
        """
        Creates and saves a superuser with the given username and password.
        """
        user = self.create_user(
            email=email,
            password=password,
        )
        user.email = email
        user.is_staff = True
        user.is_admin = True
        user.role = 'admin'
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True
    )
    first_name = models.CharField(
        ('first_name'), max_length=30, blank=True, null=True)
    last_name = models.CharField(
        ('last_name'), max_length=30, blank=True, null=True)
    username = models.CharField(max_length=30, blank=True, null=True)
    role = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_email_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()

    def __str__(self):
        return str(self.get_full_name())

    def get_full_name(self):
        '''
        Returns the first_name plus the last_name, with a space in between.
        '''
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        '''
        Returns the short name for the user.
        '''
        return self.first_name

    def is_staff(self):
        "Is the user a member of staff?"
        return self.is_staff

    def is_admin(self):
        "Is the user a admin member?"
        return self.is_admin

    def is_active(self):
        "Is the user active?"
        return self.is_active

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

def user_post_save(sender, instance, signal, *args, **kwargs):

    if not instance.is_email_verified:
        # Send verification email
        pass
        # send_verification_email.delay(instance.pk)

signals.post_save.connect(user_post_save, sender=User)
