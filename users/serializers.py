import uuid
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.password_validation import validate_password



User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    class Meta:
        model = User
        fields = ["email", "password", "first_name", "last_name"]

    def validate_email(self, value: str) -> str:
        # 1) normalize email
        email = (value or "").strip().lower()
        if not email:
            raise serializers.ValidationError("ایمیل الزامی است.")
        return email

    def validate_password(self, value: str) -> str:
        # 2) django password validators (min length, common password, etc.)
        validate_password(password=value, user=None)
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")

        username = f"user_{uuid.uuid4().hex[:10]}"

        user = User.objects.create(
            username=username,
            **validated_data
        )
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email", "").strip().lower()
        password = attrs.get("password")

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"detail": "email or password is incorrect"})

        if not user.is_active:
            raise serializers.ValidationError({"detail": "the account is deactive."})

        if not user.check_password(password):
            raise serializers.ValidationError({"detail": "ایمیل یا رمز عبور اشتباه است."})


        attrs["user"] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs["refresh"]
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            raise serializers.ValidationError()