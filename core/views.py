# python imports

# Django imports
from django.shortcuts import render
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.http import HttpResponse, HttpResponseNotFound, Http404, HttpResponseRedirect
from django.core.mail import send_mail
from django.conf import settings

# Rest Framework imports
from rest_framework import status, viewsets
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_jwt.serializers import JSONWebTokenSerializer
from rest_framework_jwt.views import JSONWebTokenAPIView

# local imports
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
# from .token import account_activation_token

from core.models import User
from core.serializers import (UserCreateSerializer,
                              UserListSerializer,

                              )
from core.utils import generate_jwt_token


class RegistrationAPIView(APIView):
    serializer_class = UserCreateSerializer
    permission_classes = (AllowAny,)
    authentication_classes = []

    __doc__ = "Registration API for user"

    def post(self, request, *args, **kwargs):

        try:
            user_serializer = UserCreateSerializer(data=request.data)
            if user_serializer.is_valid():
                user = user_serializer.save()
                data = generate_jwt_token(user, {})
                user_serializer = UserListSerializer(user)
                # send_verification_email.delay(user.pk)
                return Response({
                    'status': True,
                    'token': data['token'],
                    'data': user_serializer.data,
                }, status=status.HTTP_200_OK)
            else:
                message = ''
                for error in user_serializer.errors.values():
                    message += " "
                    message += error[0]
                return Response({'status': False,
                                 'message': message},
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': False,
                             'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class LoginView(JSONWebTokenAPIView):
    serializer_class = JSONWebTokenSerializer

    __doc__ = "Log In API for user which returns token"

    @staticmethod
    def post(request):

        try:
            serializer = JSONWebTokenSerializer(data=request.data)
            if serializer.is_valid():
                serialized_data = serializer.validate(request.data)
                # from custom_logger import DatabaseCustomLogger
                # d = DatabaseCustomLogger()
                # d.database_logger(123)
                username = request.data.get('username')
                user = User.objects.get(username=username)
                if not user.is_email_verified:
                    return Response({
                        'status': False,
                        'data': "Email Verification is pending",
                    }, status=status.HTTP_200_OK)
                user_serializer = UserListSerializer(user)
                return Response({
                    'status': True,
                    'token': serialized_data['token'],
                    'data': user_serializer.data,
                }, status=status.HTTP_200_OK)
            else:
                message = ''
                for error in serializer.errors.values():
                    message += " "
                    message += error[0]
                return Response({'status': False,
                                 'message': message},
                                status=status.HTTP_400_BAD_REQUEST)
        except (AttributeError, ObjectDoesNotExist):
            return Response({'status': False,
                             'message': "User doesnot exists"},
                            status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    @staticmethod
    def post(request):
        """
        Logout API for user
        """
        try:
            user = request.data.get('user', None)
            logout(request)
            return Response({'status': True,
                             'message': "logout successfully"},
                            status=status.HTTP_200_OK)
        except (AttributeError, ObjectDoesNotExist):
            return Response({'status': False},
                            status=status.HTTP_400_BAD_REQUEST)


class SettingAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        try:
            return Response({'status': True,
                             'message': "successfully Update"},
                            status=status.HTTP_200_OK)
        except (AttributeError, ObjectDoesNotExist):
            return Response({'status': False},
                            status=status.HTTP_400_BAD_REQUEST)


class UserAPIView(GenericAPIView):
    serializer_class = UserListSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        """
        List all the users.
        """
        try:
            users = User.objects.all()
            user_serializer = UserListSerializer(users, many=True)

            users = user_serializer.data
            return Response({'status': True,
                             'Response': users},
                            status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': False, 'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class EmailAPIView(APIView):

    __doc__ = "EmailAPIView API for user"

    def get(self, request, format=None):
        email = request.query_params.get('email')
        user = User.objects.filter(email=email)
        if user:
            return Response({'status': False,
                             'message': "Email Already Present"}, status=status.HTTP_200_OK)

        return Response({'status': True,
                         'message': ""}, status=status.HTTP_200_OK)


class ActivateApi(GenericAPIView):

    serializer_class = UserCreateSerializer

    __doc__ = "Activation API for user"

    def get(self, request, uidb64, token):

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.is_email_verified = True
            user.save()
        # return redirect('home')
            return HttpResponseRedirect("http://18.223.218.199:3000")
        else:
            return HttpResponse('Activation link is invalid!')


class ForgetAPIView(APIView):

    __doc__ = "ForgetAPIView API for user"

    def get(self, request, format=None):
        email = request.query_params.get('email')
        try:
            user = User.objects.get(email=email)
        except Exception as e:
            return Response({'status': False,
                             'message': "Email Not Present"}, status=status.HTTP_200_OK)

        subject = 'Thank you for registering to our site'
        message = render_to_string('registration/password_reset_email1.html', {
            'user': user,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
        })
        from_email = settings.EMAIL_HOST_USER

        recipient_list = [user.email]

        send_mail(subject=subject, message=message, from_email=from_email,
                  recipient_list=recipient_list, fail_silently=False)

        return Response({'status': True,
                         'message': ""}, status=status.HTTP_200_OK)


class ForgetResetAPIView(APIView):

    __doc__ = "ForgetResetAPIView API for user"

    def post(self, request, format=None):

        code = request.data.get('code')
        password = request.data.get('password')

        try:

            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):

            return HttpResponseRedirect("http://18.223.218.199:3000")
        else:
            return HttpResponse('Activation link is invalid!')

        #     return Response({'status': False,
        #                      'message': "Email Already Present"}, status=status.HTTP_200_OK)

        # return Response({'status': True,
        #                  'message': ""}, status=status.HTTP_200_OK)


class ResendAPIView(APIView):

    __doc__ = "ResendAPIView API for user"

    def get(self, request, format=None):
        email = request.query_params.get('email')
        try:
            user = User.objects.get(email=email)
        except Exception as e:
            return Response({'status': False,
                             'message': "Email not Present"}, status=status.HTTP_200_OK)

        subject = "Thank you for registering to our site"
        message = render_to_string('send/index.html', {
            'user': user,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
        })
        from_email = settings.EMAIL_HOST_USER

        recipient_list = [user.email]

        send_mail(subject=subject, message=message, from_email=from_email,
                  recipient_list=recipient_list, fail_silently=False)

        return Response({'status': True,
                         'message': ""}, status=status.HTTP_200_OK)
