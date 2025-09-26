from .models import Profile
from django import forms
from django.shortcuts import render, redirect  # Add redirect import
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.db import connection
from django.conf import settings
import time
import sys

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

# def database_status(request):
#     """View to display database connection status"""
    
#     # Initialize status data
#     status_data = {
#         'connection_status': 'Unknown',
#         'database_info': {},
#         'table_info': {},
#         'performance_metrics': {},
#         'errors': [],
#         'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
#     }
    
#     try:
#         # Test 1: Basic connection
#         cursor = connection.cursor()
#         status_data['connection_status'] = 'Connected'
        
#         # Test 2: Database configuration
#         db_config = settings.DATABASES['default']
#         status_data['database_info'] = {
#             'engine': db_config.get('ENGINE', 'Unknown'),
#             'name': db_config.get('NAME', 'Unknown'),
#             'host': db_config.get('HOST', 'Unknown'),
#             'port': db_config.get('PORT', 'Unknown'),
#             'user': db_config.get('USER', 'Unknown')
#         }
        
#         # Test 3: Get database version and info
#         try:
#             start_time = time.time()
#             cursor.execute("SELECT VERSION() as version")
#             version_result = cursor.fetchone()
#             query_time = round((time.time() - start_time) * 1000, 2)
            
#             cursor.execute("SELECT DATABASE() as db_name")
#             db_result = cursor.fetchone()
            
#             status_data['database_info'].update({
#                 'version': version_result[0] if version_result else 'Unknown',
#                 'current_database': db_result[0] if db_result else 'Unknown',
#                 'query_response_time': f"{query_time} ms"
#             })
            
#         except Exception as e:
#             status_data['errors'].append(f"Database info error: {str(e)}")
        
#         # Test 4: Check tables
#         try:
#             cursor.execute("""
#                 SELECT table_name, table_rows 
#                 FROM information_schema.tables 
#                 WHERE table_schema = %s 
#                 ORDER BY table_name
#             """, [db_config['NAME']])
            
#             tables = cursor.fetchall()
#             status_data['table_info'] = {
#                 'total_tables': len(tables),
#                 'tables': [{'name': table[0], 'rows': table[1] or 0} for table in tables]
#             }
            
#             # Check specifically for users table
#             users_table_exists = any(table[0] == 'users' for table in tables)
#             status_data['table_info']['users_table_exists'] = users_table_exists
            
#             if users_table_exists:
#                 cursor.execute("SELECT COUNT(*) FROM users")
#                 user_count = cursor.fetchone()[0]
#                 status_data['table_info']['users_count'] = user_count
            
#         except Exception as e:
#             status_data['errors'].append(f"Table info error: {str(e)}")
        
#         # Test 5: Performance metrics
#         try:
#             start_time = time.time()
#             cursor.execute("SELECT 1")
#             cursor.fetchone()
#             ping_time = round((time.time() - start_time) * 1000, 2)
            
#             cursor.execute("SHOW STATUS LIKE 'Connections'")
#             connections_result = cursor.fetchone()
            
#             cursor.execute("SHOW STATUS LIKE 'Uptime'")
#             uptime_result = cursor.fetchone()
            
#             status_data['performance_metrics'] = {
#                 'ping_time': f"{ping_time} ms",
#                 'total_connections': connections_result[1] if connections_result else 'Unknown',
#                 'server_uptime': f"{int(uptime_result[1]) // 3600} hours" if uptime_result else 'Unknown'
#             }
            
#         except Exception as e:
#             status_data['errors'].append(f"Performance metrics error: {str(e)}")
            
#         # Test 6: Write test
#         try:
#             cursor.execute("""
#                 CREATE TEMPORARY TABLE connection_test (
#                     id INT PRIMARY KEY,
#                     test_value VARCHAR(50),
#                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#                 )
#             """)
            
#             cursor.execute("""
#                 INSERT INTO connection_test (id, test_value) 
#                 VALUES (1, 'write_test_success')
#             """)
            
#             cursor.execute("SELECT test_value FROM connection_test WHERE id = 1")
#             write_test = cursor.fetchone()
            
#             status_data['write_test'] = 'Success' if write_test and write_test[0] == 'write_test_success' else 'Failed'
            
#             cursor.execute("DROP TEMPORARY TABLE connection_test")
            
#         except Exception as e:
#             status_data['write_test'] = 'Failed'
#             status_data['errors'].append(f"Write test error: {str(e)}")
        
#         cursor.close()
        
#     except Exception as e:
#         status_data['connection_status'] = 'Failed'
#         status_data['errors'].append(f"Connection error: {str(e)}")
    
#     # Change 'status_data' to 'status' to match template expectations
#     return render(request, 'database_status.html', {'status': status_data})
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