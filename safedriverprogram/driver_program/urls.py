from django.urls import path
from . import views

urlpatterns = [
    path('', views.homepage, name='homepage'),
    path('login/', views.login_page, name='login'),
    path('signup/', views.signup_page, name='signup'),
    path('account/', views.account_page, name='account'),
    path('account/edit/', views.edit_account, name='edit_account'),
    path('change-password/', views.change_password, name='change_password'),
    path('database_status/', views.database_status, name='database_status'),
    path('sponsor-application/', views.sponsor_application, name='sponsor_application'),
    path('application-success/', views.application_success, name='success'),
    path('addresses/', views.manage_addresses, name='manage_addresses'),
    path('addresses/edit/<int:address_id>/', views.edit_address, name='edit_address'),
    path('addresses/delete/<int:address_id>/', views.delete_address, name='delete_address'),
]