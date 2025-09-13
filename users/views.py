from datetime import datetime

from django.shortcuts import render
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import SignUpSerializer, ChangeInfo, UserPhotoSerializer, LoginSerializers, LogoutSerializers, \
    ForgotPasswordSerializer
from rest_framework.generics import ListCreateAPIView, UpdateAPIView
from .models import CustomUser, NEW, CODE_VERIFIED, VIA_PHONE, VIA_EMAIL
from rest_framework.views import APIView
from shared.utility import create_verify_code
from .serializers import MyTokenObtainPairSerializer

# Create your views here.
class SignUpView(ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = SignUpSerializer


class VerifyCodeApi(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request, *args, **kwargs):
        code = self.request.code.get('code')
        user = self.request.user

        self.check_verify(user, code)


        data= {
            'success':True,
            'code_status':user.verify_codes.filter(code=code).first().code_status,
            'auth_status':user.auth_status,
            'access_token':user.token()['access'],
            'refresh_token':user.token()['refresh_token']
        }
        return Response(data=data, status=status.HTTP_200_OK)

    @staticmethod
    def check_verify(user, code):
        verify = user.verify_codes.filter(code=code, code_status=False, expiration_time__gte=datetime.now())
        if not verify.exists():
            data = {
                'success':False,
                'msg':"tasdiqlash kodi noto'g'ri"
            }
            raise ValidationError(data)
        else:
            verify.update(code_status=True)
        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True





class GetNewVerifyCode(APIView):
    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verifications(user)

        if user.auth_type == VIA_PHONE:
            code = user,create_verify_code(VIA_PHONE)
            print(f'Via_phone_code {code}')
        elif user.auth_type == VIA_EMAIL:
            code = user,create_verify_code(VIA_EMAIL)
            print(f'Via_email_code {code}')
        else:
            raise ValidationError('Telefon yoki email xato')
        data={
            'status': status.HTTP_200_OK,
            'access_token': user.token()['access'],
            'refresh_token': user.token()['refresh_token']
        }
        return data
    @staticmethod
    def check_verifications(user):
        verify = user.verify_codes.filter(expiration_time__gte=datetime.now(), code_status=False)
        if verify.exists():
            data={
                'msg':"Sizda activ code bor shundan foydalaning yoki keyinroq urinib ko'ring"
            }
            raise ValidationError(data)
        return True

class ChangeInfoApi(UpdateAPIView):
    serializer_class = ChangeInfo
    http_method_names = ['PUT', 'PATCH']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeInfoApi, self).update(request,*args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        super(ChangeInfoApi, self).partial_update(request,*args, **kwargs)

class UserPhotoApi(UpdateAPIView):
    serializer_class = UserPhotoSerializer
    http_method_names = ['PATCH']

    def get_object(self):
        return self.request.user

    def partial_update(self, request, *args, **kwargs):
        user = request.user
        data = {
            'status': status.HTTP_200_OK,
            'access_token': user.token()['access'],
            'refresh_token': user.token()['refresh_token']
        }
        return Response(data)

class LoginApi(TokenObtainPairView):
    serializer_class = LoginSerializers
    permission_classes = [AllowAny, ]

class LogoutApi(APIView):
    def post(self, request):
        refresh = request.data.get('refresh_token')

        serializer = LogoutSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            token=RefreshToken(refresh)
            token.blacklist()
            return Response({'msg':"siz logout qildingiz"})
        except Exception as e:
            raise ValidationError(e)
class ForgotPasswordApi(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"data":serializer.data})



class LoginView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


