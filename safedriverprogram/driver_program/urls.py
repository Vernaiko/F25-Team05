from django.urls import path
from . import views

urlpatterns = [
    # Basic pages
    path('', views.homepage, name='homepage'),
    path('login/', views.login_page, name='login_page'),
    path('logout/', views.logout_view, name='logout'),
    path('signup/', views.signup_page, name='signup_page'),
    
    # Account management
    path('account/', views.account_page, name='account_page'),
    path('account/edit/', views.edit_account, name='edit_account'),
    path('account/change-password/', views.change_password, name='change_password'),
    path('dashboard/add-admin/', views.add_admin, name='add_admin'),
    path('dashboard/admin-list/', views.admin_list, name='admin_list'),
    path('dashboard/delete-admin/<int:admin_id>/', views.delete_admin, name='delete_admin'),
    path('dashboard/drivers/', views.driver_list, name='driver_list'),
    path('useradmin/add/', views.add_admin, name='add_admin'),
    path('useradmin/list/', views.admin_list, name='admin_list'),
    path('useradmin/delete/<int:admin_id>/', views.delete_admin, name='delete_admin'),
    path('drivers/', views.driver_list, name='driver_list'),
    path('account/delete/', views.delete_account, name='delete_account'),
    path('organzation_page/', views.to_organization_page, name='organization_page'),

    
    # Applications
    path('sponsor-application/', views.sponsor_application, name='sponsor_application'),
    path('application-success/', views.application_success, name='application_success'),
    
    # Driver-specific pages
    path('sponsor-change-request/', views.sponsor_change_request, name='sponsor_change_request'),
    path('sponsor-requests/', views.view_sponsor_requests, name='view_sponsor_requests'),
    
    # System pages
    path('database-status/', views.database_status, name='database_status'),
    
    # Address management
    path('addresses/', views.manage_addresses, name='manage_addresses'),
    path('addresses/edit/<int:address_id>/', views.edit_address, name='edit_address'),
    path('addresses/delete/<int:address_id>/', views.delete_address, name='delete_address'),

    # Admin sponsor management
    path('useradmin/sponsors/', views.admin_sponsor_list, name='admin_sponsor_list'),
    path('useradmin/sponsors/<int:sponsor_id>/', views.admin_sponsor_details, name='admin_sponsor_details'),
    path('useradmin/sponsors/<int:sponsor_id>/update-status/', views.admin_update_sponsor_status, name='admin_update_sponsor_status'),
    path('useradmin/sponsors/<int:sponsor_id>/delete/', views.admin_delete_sponsor, name='admin_delete_sponsor'),

    # Sponsor-specific pages - FIXED: Remove duplicates
    path('sponsor/home/', views.sponsor_home, name='sponsor_home'),
    path('sponsor/profile/', views.sponsor_profile, name='sponsor_profile'),
    path('sponsor/drivers/', views.sponsor_drivers, name='sponsor_drivers'),
    path('sponsor/adjust-points/', views.sponsor_adjust_points, name='sponsor_adjust_points'),
    path('sponsor/applications/', views.sponsor_manage_applications, name='sponsor_manage_applications'),
    path('sponsor/application/<int:application_id>/', views.sponsor_view_application, name='sponsor_view_application'),
    path('sponsor-application-action/<int:application_id>/', views.sponsor_application_action, name='sponsor_application_action'),

    # Admin review pages
    path('review/admins/', views.review_admin_status, name='review_admin_status'),
    path('review/drivers/', views.review_driver_status, name='review_driver_status'),
    path('review/sponsors/', views.review_sponsor_status, name='review_sponsor_status'),
    
    # Products
    path('products/', views.view_products, name='view_products'),
    path('products/<int:product_id>/', views.view_product, name='view_product'),
    path('wishlist/', views.wishlist_page, name='wishlist'),
    path('wishlist/add/<int:product_id>', views.add_to_wishlist, name='add_to_wishlist'),
]