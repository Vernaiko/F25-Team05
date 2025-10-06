from .models import Profile, DeliveryAddress
from django import forms
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.db import connection
from django.conf import settings
from django.contrib.auth import authenticate, login
from .models import SponsorProfile
import time
import sys

# ---------------------------
# FORMS
# ---------------------------

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
        

# Forms for delivery address management (CRUD)
class AddDeliveryAddressForm(forms.ModelForm):
    class Meta:
        model = DeliveryAddress
        fields = ['address']
        widgets = {
            'address': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Enter new delivery address'})
        }


class EditDeliveryAddressForm(forms.ModelForm):
    class Meta:
        model = DeliveryAddress
        fields = ['address']
        widgets = {
            'address': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Update your delivery address'})
        }

# ---------------------------
# BASIC PAGES
# ---------------------------

# Rendering the home login page:
def homepage(request):
    return render(request, 'homepage.html')

def login_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            # If this user is a sponsor, redirect to sponsor home
            if hasattr(user, 'sponsor_profile'):
                return redirect('sponsor_home')

            # Otherwise, treat as normal user/driver
            return redirect('account')

        else:
            messages.error(request, "Invalid username or password.")
            return redirect('login')

    return render(request, 'login.html')

def signup_page(request):
    return render(request, 'signup.html')

def sponsor_application(request):
    return render(request, 'sponsor_application.html')

def application_success(request):
    return render(request, 'application_success.html')

# ---------------------------
# ACCOUNT PAGES
# ---------------------------

# Updated Account Page View (passes user to template)
#@login_required
def account_page(request):
    return render(request, 'account_page.html', {'user': request.user})

@login_required
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

# ---------------------------
# DATABASE STATUS PAGE
# ---------------------------

def database_status(request):
    """View to display database connection status"""
    
    # Initialize status data
    status_data = {
        'connection_status': 'Unknown',
        'database_info': {},
        'table_info': {},
        'performance_metrics': {},
        'errors': [],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Add debug information
    print(f"Debug: Starting database status check at {status_data['timestamp']}")
    
    try:
        # Test 1: Basic connection
        print("Debug: Testing basic connection...")
        cursor = connection.cursor()
        status_data['connection_status'] = 'Connected'
        print("Debug: Connection successful!")
        
        # Test 2: Database configuration
        db_config = settings.DATABASES['default']
        status_data['database_info'] = {
            'engine': db_config.get('ENGINE', 'Unknown'),
            'name': db_config.get('NAME', 'Unknown'),
            'host': db_config.get('HOST', 'Unknown'),
            'port': db_config.get('PORT', 'Unknown'),
            'user': db_config.get('USER', 'Unknown')
        }
        print(f"Debug: Database config loaded: {status_data['database_info']}")
        
        # Test 3: Get database version and info
        try:
            start_time = time.time()
            cursor.execute("SELECT VERSION() as version")
            version_result = cursor.fetchone()
            query_time = round((time.time() - start_time) * 1000, 2)
            
            cursor.execute("SELECT DATABASE() as db_name")
            db_result = cursor.fetchone()
            
            status_data['database_info'].update({
                'version': version_result[0] if version_result else 'Unknown',
                'current_database': db_result[0] if db_result else 'Unknown',
                'query_response_time': f"{query_time} ms"
            })
            print(f"Debug: Version info: {version_result}, DB: {db_result}")
            
        except Exception as e:
            status_data['errors'].append(f"Database info error: {str(e)}")
            print(f"Debug: Database info error: {e}")
        
        
        # Test 5: Performance metrics
        try:
            start_time = time.time()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            ping_time = round((time.time() - start_time) * 1000, 2)
            
            cursor.execute("SHOW STATUS LIKE 'Connections'")
            connections_result = cursor.fetchone()
            
            cursor.execute("SHOW STATUS LIKE 'Uptime'")
            uptime_result = cursor.fetchone()
            
            status_data['performance_metrics'] = {
                'ping_time': f"{ping_time} ms",
                'total_connections': connections_result[1] if connections_result else 'Unknown',
                'server_uptime': f"{int(uptime_result[1]) // 3600} hours" if uptime_result else 'Unknown'
            }
            
        except Exception as e:
            status_data['errors'].append(f"Performance metrics error: {str(e)}")
            print(f"Debug: Performance metrics error: {e}")

        
    except Exception as e:
        status_data['connection_status'] = 'Failed'
        status_data['errors'].append(f"Connection error: {str(e)}")
        print(f"Debug: Main connection error: {e}")
    
    print(f"Debug: Final status_data: {status_data}")
    
    # Return the render with debug
    return render(request, 'database_status.html', {'status': status_data})

# ---------------------------
# DELIVERY ADDRESS CRUD VIEWS
# ---------------------------

# View to manage all delivery addresses (list + add new)
#@login_required
def manage_addresses(request):
    addresses = DeliveryAddress.objects.filter(user=request.user)

    if request.method == 'POST' and 'add_address' in request.POST:
        add_form = AddDeliveryAddressForm(request.POST)
        if add_form.is_valid():
            new_address = add_form.save(commit=False)
            new_address.user = request.user
            new_address.save()
            messages.success(request, "New delivery address added!")
            return redirect('manage_addresses')
    else:
        add_form = AddDeliveryAddressForm()

    return render(request, 'manage_addresses.html', {
        'addresses': addresses,
        'add_form': add_form
    })

# View to edit a delivery address
#@login_required
def edit_address(request, address_id):
    address_obj = get_object_or_404(DeliveryAddress, id=address_id, user=request.user)
    if request.method == 'POST':
        form = EditDeliveryAddressForm(request.POST, instance=address_obj)
        if form.is_valid():
            form.save()
            messages.success(request, "Address updated successfully!")
            return redirect('manage_addresses')
    else:
        form = EditDeliveryAddressForm(instance=address_obj)
    return render(request, 'edit_address.html', {'form': form})

# View to delete a delivery address
#@login_required
def delete_address(request, address_id):
    address_obj = get_object_or_404(DeliveryAddress, id=address_id, user=request.user)
    if request.method == 'POST':
        address_obj.delete()
        messages.success(request, "Address deleted successfully!")
        return redirect('manage_addresses')
    return render(request, 'delete_address.html', {'address': address_obj})

#@login_required
def sponsor_home(request):
    sponsor = request.user.sponsor_profile
    return render(request, 'sponsor_home.html', {'sponsor': sponsor})


#@login_required
def sponsor_profile(request):
    """Render the Sponsor Profile Page"""
    try:
        sponsor = request.user.sponsor_profile
    except SponsorProfile.DoesNotExist:
        messages.error(request, "Sponsor profile not found.")
        return redirect('sponsor_home')

    return render(request, 'sponsor_profile.html', {'sponsor': sponsor})

#@login_required
def sponsor_drivers(request):
    """Render a page showing all drivers associated with the logged-in sponsor"""
    try:
        sponsor = request.user.sponsor_profile
    except SponsorProfile.DoesNotExist:
        messages.error(request, "Sponsor profile not found.")
        return redirect('sponsor_home')

    # Get all drivers whose profile.sponsor is this sponsor
    drivers = Profile.objects.filter(sponsor=sponsor)

    return render(request, 'sponsor_drivers.html', {
        'sponsor': sponsor,
        'drivers': drivers
    })

