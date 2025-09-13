from django.contrib.auth import authenticate
from django.core.validators import FileExtensionValidator
from django.db.models import Q
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from shared.utility import check_email_or_phone_number, valid_username
from .models import CustomUser, VIA_EMAIL, VIA_PHONE, DONE, PHOTO_DONE
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = "email"

    def validate(self, data):
        identifier = data.get("email") or data.get("phone") or data.get("username")
        password = data.get("password")

        login_type = check_email_or_phone_number(identifier)

        if login_type == "email":
            user = User.objects.filter(email=identifier).first()
        elif login_type == "phone":
            user = User.objects.filter(phone=identifier).first()
        else:
            user = None

        if user and user.check_password(password):
            data["email"] = user.email  
            return super().validate(data)

        raise serializers.ValidationError("Email/Telefon yoki parol noto‘g‘ri.")


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    auth_type = serializers.CharField(required=False, read_only=True)
    auth_status = serializers.CharField(required=False, read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = CustomUser
        fields = ['id', 'auth_type', 'auth_status']


    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            # send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            # send_email(user.phone_number, code)
            # send_phone_code(user.phone_number, code)
        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        print(data)
        user_input = str(data.get('email_phone_number')).lower()
        input_type = check_email_or_phone_number(user_input)
        print(input_type)
        if input_type == "email":
            data = {
                "email": user_input,
                "auth_type": VIA_EMAIL
            }
        elif input_type == "phone":
            data = {
                "phone_number": user_input,
                "auth_type": VIA_PHONE
            }
        else:
            data = {
                'success': False,
                'message': "To'g'ri telefon raqam yoki email kiriting"
            }
            raise ValidationError(data)

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and CustomUser.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif value and CustomUser.objects.filter(phone_number=value).exists():
            data = {
                "success": False,
                "message": "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data

class ChangeInfo(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        if data.get('password') != data.get('password_cpnfirm'):
            raise ValidationError('parrolllar mos emas')

        # current_user = CustomUser.objects.filter(username=data.get('username')).exists()
        # if current_user:
        #     raise ValidationError('bu username bor')

        if not valid_username(data.get('username')):
            raise ValidationError('username mukkammal emas')

        return data


    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', )
        instance.password = validated_data.get('password', None)

        if instance.password:
            instance.set_password(validated_data.get('password'))
        if instance.auth_status:
            instance.auth_status=DONE
            instance.save()

        return instance

class UserPhotoSerializer(TokenObtainSerializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=['img', 'jpg', 'png'])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.photo = photo
            instance.auth_status=PHOTO_DONE
            instance.sava()
        return instance

class LoginSerializers(serializers.Serializer):
    password = serializers.CharField(max_length=154)

    def __init__(self, *args, **kwargs):
        super(LoginSerializers, self).__init__(*args, **kwargs)
        self.fields['user_input']=serializers.CharField(required=True)
        self.fields['username']=serializers.CharField(required=False, read_only=True)


    def auth_validate(self, data):
        user_input = data.get("user_input")
        if check_email_or_phone_number(user_input)=='email':
            user = CustomUser.objects.filter(email__iexact=user_input).first()
            username = user.username
        elif check_email_or_phone_number(user_input) == 'phone':
            user = CustomUser.objects.filter(phone_number=user_input).first()
            username = user.username
        elif valid_username(user_input):
            username = user_input
        else:
            raise ValidationError('Notogri malumot kiritdingiz')

        user = authenticate(username=username, password=data.get('password'))
        if user is None:
            raise ValidationError('Siz notogri username/parol kiritdingiz')
        self.user = user

        def validate(self, data):
            self.auth_validate(data)

            refresh_token=RefreshToken.for_user(self.user)
            data = {
                'msg':'Login qildingiz',
                'refresh_token':str(refresh_token),
                'access_token':str(refresh_token.access_token),
                'status':status.HTTP_200_OK
            }


            return data

class LogoutSerializers(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=540)

class ForgotPasswordSerializer(serializers.Serializer):
    phone_email = serializers.CharField(required=True, write_only=True)
    def auth_validate(self, data):
        user_input = data.get('phone_email')
        user = CustomUser.objects.filter(Q(email__iexact=user_input)|Q(phone_number=user_input))
        if user is None:
            raise ValidationError("siz noto'g'ri email yoki raqam kiritdingiz")
        data['user'] = user
        return data
    def validate(self, data):
        self.auth_validate(data)
        super(ForgotPasswordSerializer, self).validate(data)
        return data
class ResetPassword(serializers.Serializer):
    pass