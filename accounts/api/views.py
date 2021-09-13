from django.contrib.auth import (
    logout as django_logout,
    login as django_login,
    authenticate as django_authenticate
)
from django.contrib.auth.models import User
from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.api.serializers import UserSerializer, LoginSerializer, SingupSerizlizer


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class AccountViewSet(viewsets.ViewSet):
    serializer_class = SingupSerizlizer

    @action(methods=['POST'], detail=False)
    def signup(self, request):
        serializer = SingupSerizlizer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': 'please check input',
                'errors': serializer.errors,
            }, status=400)

        user = serializer.save()
        django_login(request, user)
        return Response({
            'success': True,
            'user': UserSerializer(user).data,
        }, status=201)

    @action(methods=['POST'], detail=False)
    def login(self, request):
        # get username and password in request
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'message': 'please check input',
                'errors': serializer.errors,
            }, status=400)

        # validation ok, login
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        # change to LoginSerializer validate
        # if not User.objects.filter(username=username):
        #     return Response({
        #         'success': False,
        #         'message': 'User dose not exists',
        #     }, status=400)

        user = django_authenticate(username=username, password=password)
        if not user or user.is_anonymous:
            return Response({
                'success': False,
                'message': 'Username and password does not match',
            }, status=400)

        django_login(request, user)
        return Response({
            'success': True,
            'user': UserSerializer(instance=user).data,
        })

    @action(methods=['POST'], detail=False)
    def logout(self, request):
        django_logout(request)
        return Response({'success': True})

    @action(methods=['GET'], detail=False)
    def login_status(self, request):
        data = {'has_logged_in': request.user.is_authenticated}
        if request.user.is_authenticated:
            data['user'] = UserSerializer(request.user).data
        return Response(data)
