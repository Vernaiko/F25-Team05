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
    path('useradmin/drivers/', views.admin_driver_dashboard, name='admin_driver_dashboard'),
    path('useradmin/drivers/export-csv/', views.admin_drivers_csv_export, name='admin_drivers_csv_export'),
    path('useradmin/drivers/delete/<int:user_id>/', views.admin_delete_driver, name='admin_delete_driver'),
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
    
    # Admin admin management
    path('useradmin/admins/', views.admin_list, name='admin_manage_admins'),
    path('useradmin/admins/<int:admin_id>/update-status/', views.admin_update_admin_status, name='admin_update_admin_status'),
    
    # Admin security log
    path('useradmin/failed-login-log/', views.admin_failed_login_log, name='admin_failed_login_log'),
    
    #Admin user management
    path('useradmin/change-user-type/', views.admin_change_user_type, name='admin_change_user_type'),

    # Sponsor-specific pages - FIXED: Remove duplicates
    path('sponsor/home/', views.sponsor_home, name='sponsor_home'),
    path('sponsor/profile/', views.sponsor_profile, name='sponsor_profile'),
    path('sponsor/drivers/', views.sponsor_drivers, name='sponsor_drivers'),
    path('sponsor/adjust-points/', views.sponsor_adjust_points, name='sponsor_adjust_points'),
    path('sponsor/adjust-point-exchange-rate/', views.sponsor_adjust_point_exchange_rate, name='sponsor_adjust_point_exchange_rate'),
    path('sponsor/adjust-catalogue/', views.adjust_catalogue, name='sponsor_adjust_catalogue'),
    path('sponsor/applications/', views.sponsor_manage_applications, name='sponsor_manage_applications'),
    path('sponsor/application/<int:application_id>/', views.sponsor_view_application, name='sponsor_view_application'),
    path('sponsor-application-action/<int:application_id>/', views.sponsor_application_action, name='sponsor_application_action'),
    
    # Wallet history pages
    path('sponsor/wallet-history/', views.sponsor_wallet_history, name='sponsor_wallet_history'),
    path('sponsor/wallet-history/<int:driver_id>/', views.sponsor_wallet_history, name='sponsor_wallet_history_driver'),
    path('useradmin/wallet-history/', views.admin_wallet_history, name='admin_wallet_history'),
    path('useradmin/wallet-history/<int:driver_id>/', views.admin_wallet_history, name='admin_wallet_history_driver'),

    # Admin review pages
    path('review/admins/', views.review_admin_status, name='review_admin_status'),
    path('review/drivers/', views.review_driver_status, name='review_driver_status'),
    path('review/sponsors/', views.review_sponsor_status, name='review_sponsor_status'),
    path('review/driver-points/', views.review_driver_points, name='review_driver_points'),
    
    # Products and driver store pages
    path('products/', views.view_products, name='view_products'),
    path('products/<int:product_id>/', views.view_product, name='view_product'),
    path('wishlist/', views.wishlist_page, name='wishlist'),
    path('wishlist/add/<int:product_id>', views.add_to_wishlist, name='add_to_wishlist'),

    # Sponsor user management
    path('sponsor/create-user/', views.sponsor_create_user, name='sponsor_create_user'),
    path('sponsor/deactivate-member/<int:member_id>/', views.sponsor_deactivate_organization_member, name='sponsor_deactivate_organization_member'),

    path('wishlist/add/<int:product_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('wishlist/delete/<int:product_id>/', views.delete_from_wishlist, name='delete_from_wishlist'),

    # Shopping cart
    path('cart/add/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/', views.view_cart, name='view_cart'),

    # Reports and Account Review
    path('sponsor/driver-point-report/', views.generate_driver_point_report, name='generate_driver_point_report'),
    path('driver/order-history/', views.driver_order_history, name='driver_order_history'),
    path('admin/review-all-accounts/', views.review_all_accounts, name='review_all_accounts'),
]
