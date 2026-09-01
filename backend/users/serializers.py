from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import APIException

from .models import EmailVerificationCode, Notification
from .utils import (
    generate_otp_code,
    send_verification_email,
    validate_email_deliverability,
    validate_password_strength,
)

User = get_user_model()


class EmailDeliveryError(APIException):
    status_code = 503
    default_detail = "We could not send a verification email. Please try again later."
    default_code = "email_delivery_failed"


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "avatar_url"]


class UserWithProjectsSerializer(serializers.ModelSerializer):
    projects_count = serializers.SerializerMethodField()
    assigned_issues_count = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "username", "email", "first_name", "last_name", "avatar_url",
            "projects_count", "assigned_issues_count", "date_joined"
        ]

    def get_projects_count(self, obj):
        return obj.project_memberships.count()

    def get_assigned_issues_count(self, obj):
        return getattr(obj, "assigned_issues", []).count() if hasattr(obj, "assigned_issues") else 0


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, allow_blank=False)
    password = serializers.CharField(write_only=True, min_length=8)
    username = serializers.CharField(required=True, allow_blank=False, min_length=3, max_length=20)

    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "first_name", "last_name"]

    def validate_username(self, value):
        import re
        value = value.strip()
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError(
                "Username may only contain letters, numbers, and underscores."
            )
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError(
                "This username is already taken. Please choose a different one."
            )
        return value

    def validate_email(self, value):
        email = value.strip().lower()
        if not email:
            raise serializers.ValidationError("Email address is required.")

        # 1. Format & Deliverability / Disposable domain validation
        is_valid, err_msg = validate_email_deliverability(email)
        if not is_valid:
            raise serializers.ValidationError(err_msg)

        # 2. Check duplicate email in database
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError(
                "An account with this email address already exists. Please log in or use a different email."
            )
        return email

    def validate_password(self, value):
        is_valid, err_msg = validate_password_strength(value)
        if not is_valid:
            raise serializers.ValidationError(err_msg)
        return value

    def create(self, validated_data):
        email = validated_data["email"]
        username = validated_data["username"]

        # Create user in pending/inactive state until email is verified
        user = User.objects.create_user(
            username=username,
            email=email,
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            is_active=False,
        )

        # Generate 6-digit OTP code & dispatch email
        code = generate_otp_code(6)
        EmailVerificationCode.objects.create(
            email=user.email,
            user=user,
            code=code,
            purpose="REGISTRATION",
        )
        email_sent = send_verification_email(
            email=user.email,
            code=code,
            purpose="REGISTRATION",
            username=user.username,
        )
        if not email_sent:
            # Do not leave an unusable inactive account behind when SMTP fails.
            user.delete()
            raise EmailDeliveryError(detail=email_sent.reason)

        return user




class NotificationSerializer(serializers.ModelSerializer):
    actor = UserSerializer(read_only=True)

    class Meta:
        model = Notification
        fields = ["id", "recipient", "actor", "action", "target", "read", "created_at"]
        read_only_fields = ["recipient"]
