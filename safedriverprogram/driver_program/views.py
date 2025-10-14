import hashlib
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import connection
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse

# Database authentication helper functions
class DatabaseUser:
    """Custom user authentication with MySQL database"""
    
    @staticmethod
    def authenticate(username, password):
        """Authenticate user against database"""
        cursor = connection.cursor()
        try:
            # Hash the password using SHA256 (matching your database)
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Query to find user with matching username and password
            cursor.execute("""
                SELECT userID, username, email, first_name, last_name, 
                       phone_number, address, account_type, is_active, created_at
                FROM users 
                WHERE username = %s AND password_hash = %s AND is_active = TRUE
            """, [username, password_hash])
            
            user_data = cursor.fetchone()
            
            if user_data:
                return {
                    'userID': user_data[0],
                    'username': user_data[1],
                    'email': user_data[2],
                    'first_name': user_data[3],
                    'last_name': user_data[4],
                    'phone_number': user_data[5],
                    'address': user_data[6],
                    'account_type': user_data[7],
                    'is_active': user_data[8],
                    'created_at': user_data[9]
                }
            else:
                return None
                
        except Exception as e:
            print(f"Database authentication error: {e}")
            return None
        finally:
            cursor.close()

    @staticmethod
    def create_user(username, email, password, first_name, last_name, 
                   phone_number='', address='', account_type='driver'):
        """Create a new user in the database"""
        cursor = connection.cursor()
        try:
            # Check if username or email already exists
            cursor.execute("""
                SELECT userID FROM users 
                WHERE username = %s OR email = %s
            """, [username, email])
            
            if cursor.fetchone():
                return None, "Username or email already exists"
            
            # Hash the password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Insert new user
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, first_name, last_name,
                                 phone_number, address, account_type, is_active, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, NOW())
            """, [username, email, password_hash, first_name, last_name,
                  phone_number, address, account_type])
            
            user_id = cursor.lastrowid
            
            # Return the created user data
            return {
                'userID': user_id,
                'username': username,
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'phone_number': phone_number,
                'address': address,
                'account_type': account_type,
                'is_active': True
            }, "User created successfully"
            
        except Exception as e:
            print(f"User creation error: {e}")
            return None, f"Database error: {str(e)}"
        finally:
            cursor.close()

# Custom decorators
def db_login_required(view_func):
    """Custom decorator to check if user is authenticated via database"""
    def wrapper(request, *args, **kwargs):
        if not request.session.get('is_authenticated'):
            messages.error(request, "You must be logged in to access this page.")
            return redirect('login_page')
        return view_func(request, *args, **kwargs)
    return wrapper

def admin_required(view_func):
    """Custom decorator to check if user is authenticated and is admin"""
    def wrapper(request, *args, **kwargs):
        if not request.session.get('is_authenticated'):
            messages.error(request, "You must be logged in to access this page.")
            return redirect('login_page')
        
        if request.session.get('account_type') != 'admin':
            messages.error(request, "Access denied. Administrator privileges required.")
            return redirect('account_page')
            
        return view_func(request, *args, **kwargs)
    return wrapper

# Basic Views
def homepage(request):
    """Display homepage"""
    return render(request, 'homepage.html')

@csrf_protect
@csrf_protect
def login_page(request):
    """Handle user login"""
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        
        if not username or not password:
            messages.error(request, "Please enter both username and password.")
            return render(request, 'login.html')
        
        # Use the DatabaseUser.authenticate method you already have
        user = DatabaseUser.authenticate(username, password)
        
        if user:
            # Update last login
            cursor = connection.cursor()
            try:
                cursor.execute("""
                    UPDATE users 
                    SET last_login_at = NOW() 
                    WHERE userID = %s
                """, [user['userID']])
            except Exception as e:
                print(f"Error updating last login: {e}")
            finally:
                cursor.close()
            
            # Set session data
            request.session['is_authenticated'] = True
            request.session['user_id'] = user['userID']
            request.session['username'] = user['username']
            request.session['email'] = user['email']
            request.session['first_name'] = user['first_name'] or ''
            request.session['last_name'] = user['last_name'] or ''
            request.session['phone_number'] = user['phone_number'] or ''
            request.session['address'] = user['address'] or ''
            request.session['account_type'] = user['account_type']
            
            first_name = user['first_name'] or user['username']
            messages.success(request, f"Welcome back, {first_name}!")
            return redirect('account_page')
        else:
            messages.error(request, "Invalid username or password.")
    
    return render(request, 'login.html')

def logout_view(request):
    """Handle user logout"""
    if request.session.get('is_authenticated'):
        username = request.session.get('first_name', 'User')
        
        # Clear all session data
        request.session.clear()
        
        messages.success(request, f"Goodbye {username}! You have been logged out successfully.")
    
    return redirect('homepage')

@admin_required
def signup_page(request):
    """Handle user registration - ADMIN ONLY"""
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        address = request.POST.get('address', '').strip()
        account_type = request.POST.get('account_type', 'driver')
        
        # Validation
        if not all([username, email, password, first_name, last_name]):
            messages.error(request, "Please fill in all required fields.")
            return render(request, 'signup.html')
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html')
        
        if len(password) < 6:
            messages.error(request, "Password must be at least 6 characters long.")
            return render(request, 'signup.html')
        
        # Create user in database
        user, message = DatabaseUser.create_user(
            username, email, password, first_name, last_name, 
            phone_number, address, account_type
        )
        
        if user:
            messages.success(request, f"Account created successfully for {username}!")
            return redirect('signup_page')  # Stay on page to create more accounts
        else:
            messages.error(request, f"Registration failed: {message}")
    
    admin_name = request.session.get('first_name', 'Admin')
    
    return render(request, 'signup.html', {'admin_name': admin_name})

# Account Management Views
@db_login_required
def edit_account(request):
    """Allow users to edit their account information"""
    user_id = request.session.get('user_id')
    
    if request.method == 'POST':
        # Get form data
        email = request.POST.get('email', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        address = request.POST.get('address', '').strip()
        
        # Validation
        if not all([email, first_name, last_name]):
            messages.error(request, "Please fill in all required fields.")
            return render(request, 'edit_account.html')
        
        # Update user in database
        cursor = connection.cursor()
        try:
            cursor.execute("""
                UPDATE users 
                SET email = %s, first_name = %s, last_name = %s, 
                    phone_number = %s, address = %s, updated_at = NOW()
                WHERE userID = %s
            """, [email, first_name, last_name, phone_number, address, user_id])
            
            # Update session data
            request.session['email'] = email
            request.session['first_name'] = first_name
            request.session['last_name'] = last_name
            request.session['phone_number'] = phone_number
            request.session['address'] = address
            
            messages.success(request, "Your account has been updated successfully!")
            return redirect('account_page')
            
        except Exception as e:
            messages.error(request, f"Error updating account: {str(e)}")
        finally:
            cursor.close()
    
    # Get current user data for the form using correct column names
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT email, first_name, last_name, phone_number, address
            FROM users WHERE userID = %s
        """, [user_id])
        
        user_data_result = cursor.fetchone()
        
        user_data = {
            'email': user_data_result[0] if user_data_result else '',
            'first_name': user_data_result[1] if user_data_result else '',
            'last_name': user_data_result[2] if user_data_result else '',
            'phone_number': user_data_result[3] if user_data_result else '',
            'address': user_data_result[4] if user_data_result else '',
        }
        
        return render(request, 'edit_account.html', {'user_data': user_data})
        
    except Exception as e:
        messages.error(request, f"Error loading account data: {str(e)}")
        return redirect('account_page')
    finally:
        cursor.close()

@db_login_required
def change_password(request):
    """Allow users to change their password"""
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '')
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        # Validation
        if not all([current_password, new_password, confirm_password]):
            messages.error(request, "Please fill in all password fields.")
            return render(request, 'change_password.html')
        
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return render(request, 'change_password.html')
        
        if len(new_password) < 6:
            messages.error(request, "New password must be at least 6 characters long.")
            return render(request, 'change_password.html')
        
        # Verify current password
        user_id = request.session.get('user_id')
        cursor = connection.cursor()
        
        try:
            # Check current password
            current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
            cursor.execute("""
                SELECT userID FROM users 
                WHERE userID = %s AND password_hash = %s
            """, [user_id, current_password_hash])
            
            if not cursor.fetchone():
                messages.error(request, "Current password is incorrect.")
                return render(request, 'change_password.html')
            
            # Update to new password
            new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s, updated_at = NOW()
                WHERE userID = %s
            """, [new_password_hash, user_id])
            
            messages.success(request, "Your password has been changed successfully!")
            return redirect('account_page')
            
        except Exception as e:
            messages.error(request, f"Error changing password: {str(e)}")
        finally:
            cursor.close()
    
    return render(request, 'change_password.html')

@db_login_required
def delete_account(request):
    """Delete the logged-in user's account from the database.

    - GET: show confirmation page (template: delete_account.html)
    - POST: attempt to delete user's records and the users row, or anonymize as a fallback.
    After successful deletion/anonymization the user's session is cleared and a success
    page is rendered informing the user their account has been deleted.
    Works for any account type.
    """
    # Ensure the user is logged in
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to delete your account.")
        return redirect('login_page')

    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "Session problem: cannot determine user. Please log in again.")
        return redirect('login_page')

    # Show confirmation page on GET
    if request.method != 'POST':
        return render(request, 'delete_account.html')

    # POST -> perform deletion
    cursor = connection.cursor()
    try:
        # Attempt to remove rows in related tables first to avoid constraint errors.
        try:
            cursor.execute("DELETE FROM delivery_addresses WHERE user_id = %s", [user_id])
        except Exception:
            pass

        try:
            cursor.execute("DELETE FROM sponsor_driver_relationships WHERE driver_user_id = %s OR sponsor_user_id = %s", [user_id, user_id])
        except Exception:
            pass

        try:
            cursor.execute("DELETE FROM driver_applications WHERE driver_user_id = %s OR sponsor_user_id = %s", [user_id, user_id])
        except Exception:
            pass

        try:
            cursor.execute("DELETE FROM sponsor_applications WHERE email = (SELECT email FROM users WHERE userID = %s)", [user_id])
        except Exception:
            pass

        # Finally attempt to delete the user row
        try:
            cursor.execute("DELETE FROM users WHERE userID = %s", [user_id])
        except Exception as e:
            # If delete fails (FK constraints), fall back to anonymizing the account
            try:
                print(f"Delete failed, anonymizing user {user_id}: {e}")
                anonymized_username = f"deleted_user_{user_id}"
                anonymized_email = f"deleted+{user_id}@example.invalid"
                cursor.execute(
                    """
                    UPDATE users SET username = %s, email = %s, password_hash = NULL,
                                    first_name = NULL, last_name = NULL, phone_number = NULL,
                                    address = NULL, is_active = 0, updated_at = NOW()
                    WHERE userID = %s
                    """,
                    [anonymized_username, anonymized_email, user_id]
                )
            except Exception as e2:
                print(f"Anonymize failed for user {user_id}: {e2}")
                # If anonymization also fails, surface an error to the user
                messages.error(request, "Failed to delete or anonymize your account. Please contact support.")
                return redirect('account_page')

        # Commit changes (cursor may auto-commit depending on DBAPI; ensure commit if needed)
        try:
            connection.commit()
        except Exception:
            pass

        # Clear session and inform the user
        username = request.session.get('first_name') or request.session.get('username') or 'User'
        request.session.clear()

        # Render a success page with a friendly message
        return render(request, 'application_success.html', {
            'message': f"{username}, your account and related data have been removed from our system. We're sorry to see you go.",
            'title': 'Account Deleted'
        })

    finally:
        try:
            cursor.close()
        except Exception:
            pass
        
def to_organization_page(request):
    """Redirect to organization page"""
    return redirect('organization_page')

# Address Management Views
@db_login_required
def manage_addresses(request):
    """Manage delivery addresses using database authentication"""
    user_id = request.session.get('user_id')
    
    # Create delivery address table if it doesn't exist
    cursor = connection.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS delivery_addresses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                address TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id)
            )
        """)
    except Exception as e:
        print(f"Error creating table: {e}")
    
    addresses = []
    
    try:
        # Get existing addresses for this user
        cursor.execute("""
            SELECT id, address, created_at 
            FROM delivery_addresses 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, [user_id])
        
        addresses_raw = cursor.fetchall()
        
        # Convert to list of dictionaries for template
        for addr in addresses_raw:
            addresses.append({
                'id': addr[0],
                'address': addr[1],
                'created_at': addr[2]
            })
        
    except Exception as e:
        print(f"Error fetching addresses: {e}")
        addresses = []
    
    if request.method == 'POST' and 'add_address' in request.POST:
        new_address = request.POST.get('address', '').strip()
        if new_address:
            try:
                cursor.execute("""
                    INSERT INTO delivery_addresses (user_id, address, created_at)
                    VALUES (%s, %s, NOW())
                """, [user_id, new_address])
                
                messages.success(request, "New delivery address added!")
                cursor.close()
                return redirect('manage_addresses')
                
            except Exception as e:
                messages.error(request, f"Failed to add address: {str(e)}")
    
    cursor.close()
    
    return render(request, 'manage_addresses.html', {
        'addresses': addresses,
    })

@db_login_required
def edit_address(request, address_id):
    """Edit delivery address using database"""
    user_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    # Get the address
    try:
        cursor.execute("""
            SELECT id, address 
            FROM delivery_addresses 
            WHERE id = %s AND user_id = %s
        """, [address_id, user_id])
        
        address_data = cursor.fetchone()
        if not address_data:
            messages.error(request, "Address not found.")
            cursor.close()
            return redirect('manage_addresses')
            
    except Exception as e:
        messages.error(request, f"Error fetching address: {str(e)}")
        cursor.close()
        return redirect('manage_addresses')
    
    if request.method == 'POST':
        new_address = request.POST.get('address', '').strip()
        if new_address:
            try:
                cursor.execute("""
                    UPDATE delivery_addresses 
                    SET address = %s 
                    WHERE id = %s AND user_id = %s
                """, [new_address, address_id, user_id])
                
                messages.success(request, "Address updated successfully!")
                cursor.close()
                return redirect('manage_addresses')
                
            except Exception as e:
                messages.error(request, f"Failed to update address: {str(e)}")
    
    cursor.close()
    
    return render(request, 'edit_address.html', {
        'address': {
            'id': address_data[0],
            'address': address_data[1]
        }
    })

@db_login_required
def delete_address(request, address_id):
    """Delete delivery address using database"""
    user_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    # Get the address first
    try:
        cursor.execute("""
            SELECT id, address 
            FROM delivery_addresses 
            WHERE id = %s AND user_id = %s
        """, [address_id, user_id])
        
        address_data = cursor.fetchone()
        if not address_data:
            messages.error(request, "Address not found.")
            cursor.close()
            return redirect('manage_addresses')
            
    except Exception as e:
        messages.error(request, f"Error fetching address: {str(e)}")
        cursor.close()
        return redirect('manage_addresses')
    
    if request.method == 'POST':
        try:
            cursor.execute("""
                DELETE FROM delivery_addresses 
                WHERE id = %s AND user_id = %s
            """, [address_id, user_id])
            
            messages.success(request, "Address deleted successfully!")
            cursor.close()
            return redirect('manage_addresses')
            
        except Exception as e:
            messages.error(request, f"Failed to delete address: {str(e)}")
    
    cursor.close()
    
    return render(request, 'delete_address.html', {
        'address': {
            'id': address_data[0],
            'address': address_data[1]
        }
    })
# ...existing code...

# Application Views
def sponsor_application(request):
    """Handle sponsor application page"""
    if request.method == 'POST':
        # Handle form submission
        company_name = request.POST.get('company_name', '').strip()
        contact_name = request.POST.get('contact_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        company_address = request.POST.get('company_address', '').strip()
        message = request.POST.get('message', '').strip()
        
        if not all([company_name, contact_name, email, phone]):
            messages.error(request, "Please fill in all required fields.")
            return render(request, 'sponsor_application.html')
        
        # Basic email validation
        if '@' not in email or '.' not in email:
            messages.error(request, "Please enter a valid email address.")
            return render(request, 'sponsor_application.html')
        
        # Store in database (create table if it doesn't exist)
        cursor = connection.cursor()
        try:
            # Create sponsor applications table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sponsor_applications (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    company_name VARCHAR(255) NOT NULL,
                    contact_name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    phone VARCHAR(50) NOT NULL,
                    company_address TEXT,
                    message TEXT,
                    application_status VARCHAR(50) DEFAULT 'pending',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            
            # Insert the application
            cursor.execute("""
                INSERT INTO sponsor_applications 
                (company_name, contact_name, email, phone, company_address, message, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """, [company_name, contact_name, email, phone, company_address, message])
            
            messages.success(request, f"Thank you {contact_name}! Your sponsor application for {company_name} has been submitted successfully. We will review your application and contact you soon.")
            return redirect('application_success')
            
        except Exception as e:
            messages.error(request, f"Sorry, there was an error submitting your application: {str(e)}")
            print(f"Database error in sponsor application: {e}")
        finally:
            cursor.close()
    
    return render(request, 'sponsor_application.html')

def application_success(request):
    """Show application success page"""
    return render(request, 'application_success.html')

# ...rest of your existing code...
# Application Views
def database_status(request):
    """Show database connection status with detailed information including ping"""
    from django.conf import settings
    import time
    
    cursor = connection.cursor()
    
    try:
        # Test multiple pings for better accuracy
        ping_times = []
        
        # Run 5 ping tests
        for i in range(5):
            ping_start = time.perf_counter()  # More precise timer
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            ping_end = time.perf_counter()
            
            if result:  # Ensure query was successful
                ping_time_ms = (ping_end - ping_start) * 1000
                ping_times.append(ping_time_ms)
        
        # Calculate ping statistics
        if ping_times:
            current_ping = round(ping_times[-1], 2)  # Last ping
            avg_ping = round(sum(ping_times) / len(ping_times), 2)
            min_ping = round(min(ping_times), 2)
            max_ping = round(max(ping_times), 2)
        else:
            current_ping = avg_ping = min_ping = max_ping = 0
        
        # Get user count with timing
        query_start = time.perf_counter()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        query_end = time.perf_counter()
        query_time = round((query_end - query_start) * 1000, 2)
        
        # Get database version
        cursor.execute("SELECT VERSION()")
        db_version = cursor.fetchone()[0]
        
        # Get database configuration from settings
        db_config = settings.DATABASES['default']
        
        # Determine ping status
        if avg_ping < 50:
            ping_status = 'excellent'
        elif avg_ping < 150:
            ping_status = 'good'
        else:
            ping_status = 'slow'
        
        status = {
            'connected': True,
            'user_count': user_count,
            'db_version': db_version,
            'message': 'Database connection successful',
            'engine': db_config.get('ENGINE', '').replace('django.db.backends.', '').upper(),
            'database_name': db_config.get('NAME', ''),
            'host': db_config.get('HOST', ''),
            'port': str(db_config.get('PORT', '')),
            'user': db_config.get('USER', ''),
            'error': None,
            # Ping/Performance metrics
            'ping_ms': current_ping,
            'avg_ping': avg_ping,
            'min_ping': min_ping,
            'max_ping': max_ping,
            'query_time': query_time,
            'ping_status': ping_status,
            'ping_tests_count': len(ping_times)
        }
        
        # Additional statistics
        try:
            # Get table information
            cursor.execute("""
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_schema = %s
            """, [db_config.get('NAME')])
            table_result = cursor.fetchone()
            table_count = table_result[0] if table_result else 0
            status['table_count'] = table_count
            
            # Get database size
            cursor.execute("""
                SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as 'DB Size in MB'
                FROM information_schema.tables 
                WHERE table_schema = %s
            """, [db_config.get('NAME')])
            db_size_result = cursor.fetchone()
            db_size = db_size_result[0] if db_size_result and db_size_result[0] else 0
            status['db_size'] = db_size
            
        except Exception as e:
            print(f"Error getting additional stats: {e}")
            status['table_count'] = 0
            status['db_size'] = 0
            
    except Exception as e:
        print(f"Database connection error: {e}")
        status = {
            'connected': False,
            'error': str(e),
            'message': 'Database connection failed',
            'user_count': 0,
            'db_version': 'Unknown',
            'engine': 'Unknown',
            'database_name': 'Unknown',
            'host': 'Unknown',
            'port': 'Unknown',
            'user': 'Unknown',
            'table_count': 0,
            'db_size': 0,
            'ping_ms': 0,
            'avg_ping': 0,
            'min_ping': 0,
            'max_ping': 0,
            'query_time': 0,
            'ping_status': 'failed',
            'ping_tests_count': 0
        }
    finally:
        try:
            cursor.close()
        except:
            pass
    
    # Add debug flag
    context = {
        'status': status,
        'debug': settings.DEBUG
    }
    
    return render(request, 'database_status.html', context)

# Account management views
def account_page(request):
    """Display user account information"""
    
    # Check if user is logged in
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access your account.")
        return redirect('login_page')
    
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "Session error. Please log in again.")
        return redirect('login_page')
    
    cursor = connection.cursor()
    
    try:
        # Fetch user information from database using correct column names from your schema
        cursor.execute("""
            SELECT userID, username, email, first_name, last_name, 
                   phone_number, address, account_type, DOB,
                   is_active, is_email_verified, last_login_at, 
                   created_at, updated_at, avatar_image
            FROM users 
            WHERE userID = %s
        """, [user_id])
        
        user_data = cursor.fetchone()
        
        if not user_data:
            messages.error(request, "User account not found.")
            return redirect('login_page')
        
        # Create user dictionary matching your actual database schema
        user = {
            'user_id': user_data[0],
            'username': user_data[1],
            'email': user_data[2],
            'first_name': user_data[3],
            'last_name': user_data[4],
            'phone_number': user_data[5],
            'address': user_data[6],
            'account_type': user_data[7],
            'date_of_birth': user_data[8],  # This is DOB in your schema
            'is_active': user_data[9],
            'email_verified': user_data[10],  # This is is_email_verified in your schema
            'last_login': user_data[11],      # This is last_login_at in your schema
            'created_at': user_data[12],
            'updated_at': user_data[13],
            'avatar_image': user_data[14],
            'delivery_address': None  # This column doesn't exist in your schema
        }
        
        # Get delivery addresses count
        cursor.execute("""
            SELECT COUNT(*) FROM delivery_addresses 
            WHERE user_id = %s
        """, [user_id])
        
        address_count_result = cursor.fetchone()
        address_count = address_count_result[0] if address_count_result else 0
        
        context = {
            'user': user,
            'has_delivery_addresses': address_count > 0,
            'address_count': address_count
        }
        
        return render(request, 'account_page.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading account information: {str(e)}")
        print(f"Account page error: {e}")
        return redirect('homepage')
        
    finally:
        cursor.close()
# Add this to your existing views.py file

@db_login_required
def sponsor_change_request(request):
    """Allow drivers to request a sponsor change"""
    
    # Only drivers can make sponsor change requests
    if request.session.get('account_type') != 'driver':
        messages.error(request, "Only drivers can submit sponsor change requests.")
        return redirect('homepage')
    
    user_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Check if driver has an active relationship
        cursor.execute("""
            SELECT sdr.relationship_id, sdr.sponsor_user_id, sdr.relationship_start_date,
                   u.username as sponsor_username, u.first_name, u.last_name,
                   sdr.relationship_status
            FROM sponsor_driver_relationships sdr
            JOIN users u ON sdr.sponsor_user_id = u.userID
            WHERE sdr.driver_user_id = %s 
            AND sdr.relationship_status = 'active'
        """, [user_id])
        
        current_relationship = cursor.fetchone()
        
        if not current_relationship:
            messages.error(request, "You must have an active sponsor relationship before requesting a change.")
            return redirect('account_page')
        
        # Check if there's already a pending change request
        cursor.execute("""
            SELECT COUNT(*) FROM driver_applications 
            WHERE driver_user_id = %s 
            AND application_status IN ('pending', 'under_review')
            AND application_date > DATE_SUB(NOW(), INTERVAL 30 DAY)
        """, [user_id])
        
        pending_requests = cursor.fetchone()[0]
        
        if pending_requests > 0:
            messages.warning(request, "You already have a pending sponsor change request. Please wait for it to be processed.")
            return redirect('account_page')
        
        # Get available sponsors
        cursor.execute("""
            SELECT u.userID, u.username, u.first_name, u.last_name, u.email,
                   COUNT(sdr.relationship_id) as current_drivers
            FROM users u
            LEFT JOIN sponsor_driver_relationships sdr ON u.userID = sdr.sponsor_user_id 
                AND sdr.relationship_status = 'active'
            WHERE u.account_type = 'sponsor' 
            AND u.is_active = 1
            AND u.userID != %s
            GROUP BY u.userID, u.username, u.first_name, u.last_name, u.email
            ORDER BY current_drivers ASC, u.first_name ASC
        """, [current_relationship[1]])  # Exclude current sponsor
        
        available_sponsors = cursor.fetchall()
        
        if request.method == 'POST':
            # Process the sponsor change request
            new_sponsor_id = request.POST.get('new_sponsor_id')
            reason_for_change = request.POST.get('reason_for_change', '').strip()
            additional_notes = request.POST.get('additional_notes', '').strip()
            
            if not new_sponsor_id or not reason_for_change:
                messages.error(request, "Please select a new sponsor and provide a reason for the change.")
                return render(request, 'sponsor_change_request.html', {
                    'current_relationship': current_relationship,
                    'available_sponsors': available_sponsors
                })
            
            # Verify the selected sponsor exists and is active
            cursor.execute("""
                SELECT userID, username, first_name, last_name 
                FROM users 
                WHERE userID = %s AND account_type = 'sponsor' AND is_active = 1
            """, [new_sponsor_id])
            
            selected_sponsor = cursor.fetchone()
            
            if not selected_sponsor:
                messages.error(request, "Selected sponsor is not valid.")
                return render(request, 'sponsor_change_request.html', {
                    'current_relationship': current_relationship,
                    'available_sponsors': available_sponsors
                })
            
            # Create a new driver application for sponsor change
            try:
                # First, let's check what columns actually exist in driver_applications table
                cursor.execute("DESCRIBE driver_applications")
                columns = [col[0] for col in cursor.fetchall()]
                print(f"Available columns in driver_applications: {columns}")
                
                # Create the change request with only the columns that exist
                # Build the insert query dynamically based on available columns
                base_columns = ['driver_user_id', 'sponsor_user_id', 'application_status', 'application_date']
                base_values = [user_id, new_sponsor_id, 'pending', 'NOW()']
                
                # Add optional columns if they exist
                optional_columns = {}
                if 'created_at' in columns:
                    optional_columns['created_at'] = 'NOW()'
                if 'updated_at' in columns:
                    optional_columns['updated_at'] = 'NOW()'
                if 'motivation_essay' in columns:
                    # Fix the string escaping issue
                    escaped_reason = reason_for_change.replace("'", "''")  # SQL escape single quotes
                    optional_columns['motivation_essay'] = f"SPONSOR CHANGE REQUEST: {escaped_reason}"
                if 'goals_description' in columns:
                    escaped_notes = additional_notes.replace("'", "''") if additional_notes else "Sponsor change request"
                    optional_columns['goals_description'] = f"Additional Notes: {escaped_notes}"
                if 'admin_notes' in columns:
                    escaped_reason_admin = reason_for_change.replace("'", "''")
                    sponsor_name = f"{current_relationship[3]} {current_relationship[4]} {current_relationship[5]}"
                    requested_name = f"{selected_sponsor[2]} {selected_sponsor[3]}"
                    admin_note = f"SPONSOR CHANGE REQUEST - Current Sponsor: {sponsor_name} (ID: {current_relationship[1]}) | Requested Sponsor: {requested_name} (ID: {selected_sponsor[0]}) | Reason: {escaped_reason_admin}"
                    optional_columns['admin_notes'] = admin_note

                for col, val in optional_columns.items():
                    base_columns.append(col)
                    if val == 'NOW()':
                        base_values.append('NOW()')
                    else:
                        base_values.append(val)                
                # Build and execute the query
                columns_str = ', '.join(base_columns)
                placeholders = []
                actual_values = []
                
                for i, val in enumerate(base_values):
                    if val in ['NOW()', 'NOW()']:
                        placeholders.append('NOW()')
                    elif val.startswith("'") and val.endswith("'"):
                        placeholders.append('%s')
                        actual_values.append(val[1:-1])  # Remove quotes
                    else:
                        placeholders.append('%s')
                        actual_values.append(val)
                
                placeholders_str = ', '.join(placeholders)
                
                query = f"""
                    INSERT INTO driver_applications ({columns_str})
                    VALUES ({placeholders_str})
                """
                
                print(f"Executing query: {query}")
                print(f"With values: {actual_values}")
                
                cursor.execute(query, actual_values)
                application_id = cursor.lastrowid
                
                messages.success(request, f"Your sponsor change request has been submitted successfully! You've requested to change from {current_relationship[3]} {current_relationship[4]} to {selected_sponsor[2]} {selected_sponsor[3]}. An administrator will review your request.")
                return redirect('account_page')
                
            except Exception as e:
                messages.error(request, f"Error submitting sponsor change request: {str(e)}")
                print(f"Sponsor change request error: {e}")
                
                # Let's also print the table structure for debugging
                try:
                    cursor.execute("DESCRIBE driver_applications")
                    table_structure = cursor.fetchall()
                    print("driver_applications table structure:")
                    for col in table_structure:
                        print(f"  {col[0]} - {col[1]} - Null: {col[2]} - Key: {col[3]} - Default: {col[4]}")
                except:
                    print("Could not describe table structure")
        
        # Prepare current relationship data for template
        relationship_data = {
            'relationship_id': current_relationship[0],
            'sponsor_id': current_relationship[1],
            'start_date': current_relationship[2],
            'sponsor_username': current_relationship[3],
            'sponsor_first_name': current_relationship[4],
            'sponsor_last_name': current_relationship[5],
            'status': current_relationship[6] if len(current_relationship) > 6 else 'active'
        }
        
        # Format available sponsors for template
        sponsors_list = []
        for sponsor in available_sponsors:
            sponsors_list.append({
                'user_id': sponsor[0],
                'username': sponsor[1],
                'first_name': sponsor[2],
                'last_name': sponsor[3],
                'email': sponsor[4],
                'current_drivers': sponsor[5]
            })
        
        return render(request, 'sponsor_change_request.html', {
            'current_relationship': relationship_data,
            'available_sponsors': sponsors_list
        })
        
    except Exception as e:
        messages.error(request, f"Error loading sponsor change request page: {str(e)}")
        print(f"Sponsor change request page error: {e}")
        return redirect('account_page')
    finally:
        cursor.close()

@db_login_required
def view_sponsor_requests(request):
    """View sponsor change request history for the logged-in driver"""
    
    if request.session.get('account_type') != 'driver':
        messages.error(request, "Access denied.")
        return redirect('homepage')
    
    user_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Get all applications/requests for this driver
        cursor.execute("""
            SELECT da.application_id, da.application_status, da.application_date,
                   da.review_date, da.approval_date, da.motivation_essay,
                   da.admin_notes, da.rejection_reason,
                   u_sponsor.first_name as sponsor_first_name,
                   u_sponsor.last_name as sponsor_last_name,
                   u_reviewer.first_name as reviewer_first_name,
                   u_reviewer.last_name as reviewer_last_name
            FROM driver_applications da
            LEFT JOIN users u_sponsor ON da.sponsor_user_id = u_sponsor.userID
            LEFT JOIN users u_reviewer ON da.reviewed_by_admin_id = u_reviewer.userID
            WHERE da.driver_user_id = %s
            ORDER BY da.application_date DESC
        """, [user_id])
        
        requests = cursor.fetchall()
        
        requests_list = []
        for req in requests:
            is_change_request = req[6] and 'SPONSOR CHANGE REQUEST' in req[6]
            requests_list.append({
                'application_id': req[0],
                'status': req[1],
                'application_date': req[2],
                'review_date': req[3],
                'approval_date': req[4],
                'motivation_essay': req[5],
                'admin_notes': req[6],
                'rejection_reason': req[7],
                'sponsor_first_name': req[8],
                'sponsor_last_name': req[9],
                'reviewer_first_name': req[10],
                'reviewer_last_name': req[11],
                'is_change_request': is_change_request
            })
        
        return render(request, 'view_sponsor_requests.html', {
            'requests': requests_list
        })
        
    except Exception as e:
        messages.error(request, f"Error loading requests: {str(e)}")
        return redirect('account_page')
    finally:
        cursor.close()
# Add these missing view functions to your views.py file

@db_login_required
def sponsor_home(request):
    """Sponsor dashboard/home page"""
    
    # Only sponsors can access this page
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can view this page.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Get sponsor's basic information
        cursor.execute("""
            SELECT first_name, last_name, email, username
            FROM users 
            WHERE userID = %s
        """, [sponsor_id])
        
        sponsor_info = cursor.fetchone()
        
        # Get sponsor's active drivers
        cursor.execute("""
            SELECT COUNT(*) 
            FROM sponsor_driver_relationships 
            WHERE sponsor_user_id = %s AND relationship_status = 'active'
        """, [sponsor_id])
        
        active_drivers_count = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        # Get pending applications
        cursor.execute("""
            SELECT COUNT(*) 
            FROM driver_applications 
            WHERE sponsor_user_id = %s AND application_status = 'pending'
        """, [sponsor_id])
        
        pending_applications = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        # Get recent driver activity (if tables exist)
        try:
            cursor.execute("""
                SELECT u.first_name, u.last_name, sdr.safe_driving_streak_days, sdr.total_trips_logged
                FROM sponsor_driver_relationships sdr
                JOIN users u ON sdr.driver_user_id = u.userID
                WHERE sdr.sponsor_user_id = %s AND sdr.relationship_status = 'active'
                ORDER BY sdr.relationship_start_date DESC
                LIMIT 5
            """, [sponsor_id])
            
            recent_drivers = cursor.fetchall()
        except:
            recent_drivers = []
        
        context = {
            'sponsor_info': {
                'first_name': sponsor_info[0] if sponsor_info else '',
                'last_name': sponsor_info[1] if sponsor_info else '',
                'email': sponsor_info[2] if sponsor_info else '',
                'username': sponsor_info[3] if sponsor_info else '',
            },
            'active_drivers_count': active_drivers_count,
            'pending_applications': pending_applications,
            'recent_drivers': recent_drivers
        }
        
        return render(request, 'sponsor_home.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading sponsor dashboard: {str(e)}")
        return redirect('account_page')
    finally:
        cursor.close()

@db_login_required
def sponsor_profile(request):
    """Sponsor profile management page"""
    
    # Only sponsors can access this page
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can view this page.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    if request.method == 'POST':
        # Handle profile update
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        address = request.POST.get('address', '').strip()
        
        if not all([first_name, last_name, email]):
            messages.error(request, "Please fill in all required fields.")
        else:
            try:
                cursor.execute("""
                    UPDATE users 
                    SET first_name = %s, last_name = %s, email = %s, 
                        phone_number = %s, address = %s, updated_at = NOW()
                    WHERE userID = %s
                """, [first_name, last_name, email, phone_number, address, sponsor_id])
                
                # Update session data
                request.session['first_name'] = first_name
                request.session['last_name'] = last_name
                request.session['email'] = email
                
                messages.success(request, "Profile updated successfully!")
                return redirect('sponsor_profile')
                
            except Exception as e:
                messages.error(request, f"Error updating profile: {str(e)}")
    
    # Get current profile data
    try:
        cursor.execute("""
            SELECT first_name, last_name, email, phone_number, address, username, created_at
            FROM users 
            WHERE userID = %s
        """, [sponsor_id])
        
        profile_data = cursor.fetchone()
        
        if profile_data:
            context = {
                'profile': {
                    'first_name': profile_data[0],
                    'last_name': profile_data[1],
                    'email': profile_data[2],
                    'phone_number': profile_data[3],
                    'address': profile_data[4],
                    'username': profile_data[5],
                    'created_at': profile_data[6]
                }
            }
        else:
            context = {'profile': {}}
        
        return render(request, 'sponsor_profile.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading profile: {str(e)}")
        return redirect('sponsor_home')
    finally:
        cursor.close()

@db_login_required
def sponsor_drivers(request):
    """View and manage sponsored drivers"""
    
    # Only sponsors can access this page
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can view this page.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Get all drivers sponsored by this sponsor
        cursor.execute("""
            SELECT 
                u.userID, u.username, u.first_name, u.last_name, u.email, u.phone_number,
                sdr.relationship_id, sdr.relationship_status, sdr.relationship_start_date,
                sdr.safe_driving_streak_days, sdr.total_trips_logged
            FROM sponsor_driver_relationships sdr
            JOIN users u ON sdr.driver_user_id = u.userID
            WHERE sdr.sponsor_user_id = %s
            ORDER BY sdr.relationship_start_date DESC
        """, [sponsor_id])
        
        sponsored_drivers = cursor.fetchall()
        
        # Get pending applications for this sponsor
        cursor.execute("""
            SELECT 
                da.application_id, da.application_date, da.application_status,
                u.userID, u.username, u.first_name, u.last_name, u.email,
                da.motivation_essay, da.goals_description
            FROM driver_applications da
            JOIN users u ON da.driver_user_id = u.userID
            WHERE da.sponsor_user_id = %s AND da.application_status IN ('pending', 'under_review')
            ORDER BY da.application_date DESC
        """, [sponsor_id])
        
        pending_applications = cursor.fetchall()
        
        # Format data for template
        drivers_list = []
        for driver in sponsored_drivers:
            drivers_list.append({
                'user_id': driver[0],
                'username': driver[1],
                'first_name': driver[2],
                'last_name': driver[3],
                'email': driver[4],
                'phone_number': driver[5],
                'relationship_id': driver[6],
                'relationship_status': driver[7],
                'relationship_start_date': driver[8],
                'safe_driving_streak_days': driver[9] or 0,
                'total_trips_logged': driver[10] or 0
            })
        
        applications_list = []
        for app in pending_applications:
            applications_list.append({
                'application_id': app[0],
                'application_date': app[1],
                'application_status': app[2],
                'driver_id': app[3],
                'driver_username': app[4],
                'driver_first_name': app[5],
                'driver_last_name': app[6],
                'driver_email': app[7],
                'motivation_essay': app[8],
                'goals_description': app[9]
            })
        
        context = {
            'sponsored_drivers': drivers_list,
            'pending_applications': applications_list,
            'total_drivers': len(drivers_list),
            'active_drivers': len([d for d in drivers_list if d['relationship_status'] == 'active'])
        }
        
        return render(request, 'sponsor_drivers.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading sponsored drivers: {str(e)}")
        return redirect('sponsor_home')
    finally:
        cursor.close()