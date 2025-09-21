from .models import Profile
from django import forms
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.models import User


# Form to allow drivers to add or update their delivery address in their profile
class DeliveryAddressForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['delivery_address']
        widgets = {
            'delivery_address': forms.Textarea(attrs={
                'rows': 2,
                'placeholder': 'Enter your delivery address'
            })
        }

# Form for editing account info (phone, address, delivery address)
class EditAccountForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['phone_number', 'address', 'delivery_address']
        widgets = {
            'phone_number': forms.TextInput(attrs={'placeholder': 'Enter phone number'}),
            'address': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Enter your address'}),
            'delivery_address': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Enter your delivery address'}),
        }
        
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
    # Ensure user has a profile object
    profile, created = Profile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = EditAccountForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Account info updated successfully.")
            return redirect('account')  # Redirect to account page after saving
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = EditAccountForm(instance=profile)
    return render(request, 'edit_account.html', {'form': form})


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
    
    