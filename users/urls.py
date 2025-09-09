from django.urls import path
from .views import SignUpView, VerifyCodeApi, GetNewVerifyCode, ChangeInfoApi

urlpatterns = [
    path('', SignUpView.as_view()),
    path('code_verify/', VerifyCodeApi.as_view()),
    path('new_code_verify/', GetNewVerifyCode.as_view()),
    path('update/', ChangeInfoApi.as_view())
]