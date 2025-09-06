from django.shortcuts import render

from .serializers import SignUpSerializer
from rest_framework.generics import ListCreateAPIView
from .models import CustomUser


# Create your views here.
class SignUpView(ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = SignUpSerializer
