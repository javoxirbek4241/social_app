from django.urls import path
from .views import SignUpView, VerifyCodeApi, GetNewVerifyCode, ChangeInfoApi, UserPhotoApi, LoginApi, LogoutApi, \
    ForgotPasswordApi

urlpatterns = [
    path('', SignUpView.as_view()),
    path('code_verify/', VerifyCodeApi.as_view()),
    path('new_code_verify/', GetNewVerifyCode.as_view()),
    path('update/', ChangeInfoApi.as_view()),
    path('user_photo/', UserPhotoApi.as_view()),
    path('login/', LoginApi.as_view()),
    path('logout/', LogoutApi.as_view()),
    path('forgot-pass/', ForgotPasswordApi.as_view()),
]