#!/usr/bin/env python

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# Python imports.
import logging
import datetime
import calendar

# Django imports.
from django.db import transaction
from django.http import Http404
# Rest Framework imports.
from rest_framework import serializers

# Third Party Library imports


# local imports.
from core.models import User


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    def validate(self, data, *args, **kwargs):
        return super(UserCreateSerializer, self).validate(data, *args, **kwargs)

    @transaction.atomic()
    def create(self, validated_data):
        username = validated_data['username']
        first_name = validated_data['first_name']
        last_name = validated_data['last_name']
        email = validated_data['email']
        user = User.objects.create(**validated_data)
        user.set_password(validated_data['password'])
        user.is_active = False
        user.save()
        return user

    class Meta:
        model = User
        fields = ('email', 'username', 'id',
                  'password', 'first_name', 'last_name')


class UserListSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'role')
