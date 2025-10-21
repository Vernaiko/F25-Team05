from django.contrib.auth.decorators import user_passes_test

def admin_required(view_func):
    """Decorator to allow only admins (staff or superusers) to access a view."""
    return user_passes_test(lambda u: u.is_staff or u.is_superuser)(view_func)
