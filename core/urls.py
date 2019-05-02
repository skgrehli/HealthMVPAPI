#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
# Python imports.
import logging

# Django imports.
from django.conf.urls import url, include

# Rest Framework imports.
from rest_framework.routers import DefaultRouter

# Third Party Library imports

# local imports.
from core.views import *
# from core.swagger import schema_view

app_name = 'core'

urlpatterns = [
    url(r'^forget/reset$', ForgetResetAPIView.as_view(), name='forget-reset'),
    url(r'^forget/$', ForgetAPIView.as_view(), name='forget'),
    url(r'^resend/$', ResendAPIView.as_view(), name='resend'),
    url(r'^email/$', EmailAPIView.as_view(), name='email'),
    url(r'register/', RegistrationAPIView.as_view(), name='register-api'),
    url(r'login/', LoginView.as_view(), name='login-api'),
    url(r'^logout/$', LogoutView.as_view(), name='logout-api'),
    
]
