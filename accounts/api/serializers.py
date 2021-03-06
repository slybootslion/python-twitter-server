from django.contrib.auth.models import User
from rest_framework import serializers, exceptions


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        if not User.objects.filter(username=data['username'].lower()).exists():
            raise exceptions.ValidationError({
                'username': 'User does not exist'
            })
        return data


class SingupSerizlizer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=20, min_length=6)
    email = serializers.EmailField()
    password = serializers.CharField(max_length=20, min_length=6)

    class Meta:
        model = User
        fields = ('username', 'password', 'email')

    # will be called when is_valid is called
    def validate(self, data):
        if User.objects.filter(username=data['username'].lower()).exists():
            raise exceptions.ValidationError({
                'username': 'This email address has been occupied'
            })
        if User.objects.filter(email=data['email'].lower()).exists():
            raise exceptions.ValidationError({
                'email': 'This email address has been occupied'
            })
        return data

    def create(self, validated_data):
        username = validated_data['username'].lower()
        email = validated_data['email'].lower()
        password = validated_data['password']
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )
        return user
