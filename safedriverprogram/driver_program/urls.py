from django.urls import path
from . import views

urlpatterns = [
    path('', views.homepage, name='homepage'),
    path('login/', views.login_page, name='login'),
    path('signup/', views.signup_page, name='signup'),
]