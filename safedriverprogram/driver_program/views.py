from django.shortcuts import render

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash

# Rendering the home login page:
def homepage(request):
    return render(request, 'homepage.html')

def login_page(request):
    return render(request, 'login.html')

def signup_page(request):
    return render(request, 'signup.html')


# Updated Account Page View (passes user to template)
#@login_required
def account_page(request):
    return render(request, 'account_page.html', {'user': request.user})

#@login_required
def edit_account(request):
    # For now, just render a placeholder template
    return render(request, 'edit_account.html', {'user': request.user})


# NEW Change Password View
@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Validate current password
        if not request.user.check_password(current_password):
            messages.error(request, "Current password is incorrect.")
            return render(request, 'account_page.html', {'user': request.user})

        # Validate password confirmation
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return render(request, 'account_page.html', {'user': request.user})

        # Save new password and keep user logged in
        request.user.set_password(new_password)
        request.user.save()
        update_session_auth_hash(request, request.user)

        messages.success(request, "Password updated successfully.")
        return render(request, 'account_page.html', {'user': request.user})