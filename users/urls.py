# users/urls.py 
from django.urls import path, include, re_path
from .views import CreateUserAPIView, TestAPIAUTH
app_name = 'users'


urlpatterns = [
    re_path(r'^create/$', CreateUserAPIView.as_view()),
    re_path(r'^testAuth/$', TestAPIAUTH.as_view()),

]