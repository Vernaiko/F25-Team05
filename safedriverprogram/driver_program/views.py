import hashlib
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db import connection
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.conf import settings
import os
import requests
from django.core.files.storage import default_storage
from django.contrib.auth.models import User
from django.contrib.auth.decorators import user_passes_test, login_required  # <-- added login_required
from datetime import datetime
from driver_program.decorators import admin_required
from django.contrib.auth.decorators import login_required
import textwrap
from django.db import connection
from .forms import AddressForm




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
    wishlist_display = []
    if request.session.get('is_authenticated'):
        user_id = request.session.get('user_id')
        try:
            cursor = connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_wishlist (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    product_id INT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_user_product (user_id, product_id),
                    INDEX idx_user_id (user_id)
                )
            """)
            cursor.execute("SELECT product_id FROM user_wishlist WHERE user_id = %s ORDER BY created_at DESC", [user_id])
            rows = cursor.fetchall()
            wishlist_ids = [r[0] for r in rows]

            # Fetch product titles for up to 5 items
            import requests
            for pid in wishlist_ids[:5]:
                try:
                    resp = requests.get(f'https://fakestoreapi.com/products/{pid}', timeout=3)
                    if resp.status_code == 200:
                        data = resp.json()
                        wishlist_display.append({'id': data.get('id'), 'title': data.get('title')})
                    else:
                        wishlist_display.append({'id': pid, 'title': f'Product #{pid}'})
                except Exception:
                    wishlist_display.append({'id': pid, 'title': f'Product #{pid}'})
        except Exception:
            wishlist_display = []
        finally:
            try:
                cursor.close()
            except:
                pass

    return render(request, 'homepage.html', {'wishlist': wishlist_display})

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
            # Log failed login attempt
            log_failed_login_attempt(request, username, "Invalid username or password")
            messages.error(request, "Invalid username or password.")
    
    return render(request, 'login.html')


def log_failed_login_attempt(request, username, reason):
    """Log a failed login attempt to the database"""
    cursor = connection.cursor()
    try:
        # Get IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]  # Limit length
        
        # Try to determine account type from username
        cursor.execute("SELECT account_type FROM users WHERE username = %s", [username])
        result = cursor.fetchone()
        account_type = result[0] if result else 'unknown'
        
        # Ensure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS failed_login_attempts (
                attempt_id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(150) NOT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                user_agent TEXT,
                failure_reason VARCHAR(255),
                account_type VARCHAR(50),
                INDEX idx_username (username),
                INDEX idx_attempted_at (attempted_at),
                INDEX idx_ip_address (ip_address)
            )
        """)
        
        # Insert the failed attempt
        cursor.execute("""
            INSERT INTO failed_login_attempts 
            (username, ip_address, user_agent, failure_reason, account_type)
            VALUES (%s, %s, %s, %s, %s)
        """, [username, ip_address, user_agent, reason, account_type])
        
        connection.commit()
        
    except Exception as e:
        print(f"Error logging failed login attempt: {e}")
    finally:
        cursor.close()

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
        
        # Handle uploaded avatar (optional)
        avatar_filename = None
        if request.FILES.get('avatar'):
            avatar = request.FILES['avatar']
            avatars_dir = settings.MEDIA_ROOT / 'avatars'
            os.makedirs(avatars_dir, exist_ok=True)
            avatar_filename = os.path.join('avatars', avatar.name)
            full_path = settings.MEDIA_ROOT / avatar_filename
            with open(full_path, 'wb+') as dest:
                for chunk in avatar.chunks():
                    dest.write(chunk)

        # Create user in database
        user, message = DatabaseUser.create_user(
            username, email, password, first_name, last_name, 
            phone_number, address, account_type
        )

        # If created and avatar uploaded, update avatar_image column
        if user and avatar_filename:
            cursor = connection.cursor()
            try:
                cursor.execute("""
                    UPDATE users SET avatar_image = %s WHERE userID = %s
                """, [avatar_filename, user['userID']])
            except Exception as e:
                print(f"Error saving avatar path to DB: {e}")
            finally:
                cursor.close()
        
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
        # Handle avatar upload
        avatar_filename = None
        if request.FILES.get('avatar'):
            avatar = request.FILES['avatar']
            avatars_dir = settings.MEDIA_ROOT / 'avatars'
            os.makedirs(avatars_dir, exist_ok=True)
            avatar_filename = os.path.join('avatars', avatar.name)
            full_path = settings.MEDIA_ROOT / avatar_filename
            with open(full_path, 'wb+') as dest:
                for chunk in avatar.chunks():
                    dest.write(chunk)
        
        # If required fields are missing (e.g., user submitted only an avatar),
        # fetch current values from DB and use them so avatar-only updates are allowed.
        if not all([email, first_name, last_name]):
            cursor_prefill = connection.cursor()
            try:
                cursor_prefill.execute("""
                    SELECT email, first_name, last_name, phone_number, address
                    FROM users WHERE userID = %s
                """, [user_id])
                existing = cursor_prefill.fetchone()
                if existing:
                    if not email:
                        email = existing[0] or ''
                    if not first_name:
                        first_name = existing[1] or ''
                    if not last_name:
                        last_name = existing[2] or ''
                    if not phone_number:
                        phone_number = existing[3] or ''
                    if not address:
                        address = existing[4] or ''
            except Exception as e:
                print(f"Error pre-filling account data: {e}")
            finally:
                try:
                    cursor_prefill.close()
                except:
                    pass

        # Validation (re-check after prefill)
        if not all([email, first_name, last_name]):
            # Provide current user data to the template so the form stays populated
            cursor = connection.cursor()
            try:
                cursor.execute("""
                    SELECT email, first_name, last_name, phone_number, address
                    FROM users WHERE userID = %s
                """, [user_id])
                row = cursor.fetchone()
                user_data = {
                    'email': row[0] if row else '',
                    'first_name': row[1] if row else '',
                    'last_name': row[2] if row else '',
                    'phone_number': row[3] if row else '',
                    'address': row[4] if row else '',
                }
            except Exception:
                user_data = {'email': email, 'first_name': first_name, 'last_name': last_name, 'phone_number': phone_number, 'address': address}
            finally:
                try:
                    cursor.close()
                except:
                    pass

            messages.error(request, "Please fill in all required fields.")
            return render(request, 'edit_account.html', {'user_data': user_data})
        
        # Update user in database
        cursor = connection.cursor()
        try:
            cursor.execute("""
                UPDATE users 
                SET email = %s, first_name = %s, last_name = %s, 
                    phone_number = %s, address = %s, updated_at = NOW()
                WHERE userID = %s
            """, [email, first_name, last_name, phone_number, address, user_id])

            # Save avatar filename to DB if uploaded
            if avatar_filename:
                try:
                    cursor.execute("""
                        UPDATE users SET avatar_image = %s WHERE userID = %s
                    """, [avatar_filename, user_id])
                except Exception as e:
                    print(f"Error updating avatar in DB: {e}")
            
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


def get_user_wishlist(user_id):
    """Return a list of product_ids in the user's wishlist."""
    cursor = connection.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_wishlist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_product (user_id, product_id),
                INDEX idx_user_id (user_id)
            )
        """)

        cursor.execute("""SELECT product_id FROM user_wishlist WHERE user_id = %s ORDER BY created_at DESC""", [user_id])
        rows = cursor.fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []
    finally:
        try:
            cursor.close()
        except:
            pass


@db_login_required
def add_to_wishlist(request, product_id=None):
    """Add a product to the logged-in user's wishlist.

    Accepts product_id either as a POST form field or as a URL parameter (optional).
    """
    if request.method != 'POST' and product_id is None:
        messages.error(request, "Invalid request method")
        return redirect('view_products')

    # Prefer POST product_id, fall back to URL param
    if request.method == 'POST':
        product_id = request.POST.get('product_id') or product_id

    if not product_id:
        messages.error(request, "No product specified")
        return redirect('view_products')

    # session keys were inconsistent across the codebase; accept either
    user_id = request.session.get('user_id') or request.session.get('userID')
    if not user_id:
        messages.error(request, "You must be logged in to add items to wishlist.")
        return redirect('login_page')

    cursor = connection.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_wishlist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_product (user_id, product_id),
                INDEX idx_user_id (user_id)
            )
        """)

        try:
            cursor.execute("INSERT INTO user_wishlist (user_id, product_id) VALUES (%s, %s)", [user_id, int(product_id)])
            connection.commit()
            messages.success(request, "Added to your wishlist")
        except Exception as ex:
            # Likely duplicate insertion or constraint error; report info
            messages.info(request, f"Product already in wishlist or could not be added: {ex}")

    except Exception as e:
        messages.error(request, f"Error adding to wishlist: {str(e)}")
    finally:
        try:
            cursor.close()
        except:
            pass

    # Redirect back to product detail if referrer is product page
    ref = request.META.get('HTTP_REFERER')
    if ref:
        return redirect(ref)
    return redirect('view_products')

@login_required
def manage_addresses(request):
    """
    Show all addresses for the logged-in user, allow adding a new one.
    New address can optionally be set as default (and will unset others).
    """
    addresses = Address.objects.filter(user=request.user).order_by('-is_default', '-created_at')

    if request.method == 'POST':
        form = AddressForm(request.POST)
        if form.is_valid():
            addr = form.save(commit=False)
            addr.user = request.user
            addr.save()

            # If this was marked default, unset all others
            if addr.is_default:
                Address.objects.filter(user=request.user).exclude(id=addr.id).update(is_default=False)

            messages.success(request, "Address saved successfully.")
            return redirect('manage_addresses')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = AddressForm()

    return render(request, 'manage_addresses.html', {
        'addresses': addresses,
        'add_form': form,
    })


@login_required
def delete_address(request, address_id):
    """
    Delete an address; if it was default and another exists, leave none default
    (user can set a new default explicitly).
    """
    address = get_object_or_404(Address, id=address_id, user=request.user)

    if request.method == 'POST':
        was_default = address.is_default
        address.delete()

        # Optionally: auto-pick a new default if any remain
        # (Uncomment if you want this behavior)
        # if was_default:
        #     first = Address.objects.filter(user=request.user).order_by('-created_at').first()
        #     if first:
        #         first.is_default = True
        #         first.save()

        messages.success(request, "Address deleted successfully.")
        return redirect('manage_addresses')

    # If someone GETs this URL, just redirect back
    return redirect('manage_addresses')

@login_required
def set_default_address(request, address_id):
    """
    Explicitly set an address as default for the logged-in user.
    """
    if request.method != 'POST':
        return redirect('manage_addresses')

    address = get_object_or_404(Address, id=address_id, user=request.user)
    Address.objects.filter(user=request.user, is_default=True).update(is_default=False)
    address.is_default = True
    address.save()
    messages.success(request, "Default address updated.")
    return redirect('manage_addresses')

@login_required
def edit_address(request, address_id):
    """
    Edit an existing address belonging to the logged-in user.
    """
    address = get_object_or_404(Address, id=address_id, user=request.user)

    if request.method == 'POST':
        form = AddressForm(request.POST, instance=address)
        if form.is_valid():
            addr = form.save()

            # If marked default, unset others
            if addr.is_default:
                Address.objects.filter(user=request.user).exclude(id=addr.id).update(is_default=False)

            messages.success(request, "Address updated successfully.")
            return redirect('manage_addresses')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = AddressForm(instance=address)

    return render(request, 'edit_address.html', {'form': form})

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
@db_login_required
def account_page(request):
    """Display user account information and management options"""
    
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access your account.")
        return redirect('login_page')
    
    user_id = request.session.get('user_id')
    account_type = request.session.get('account_type')
    
    cursor = connection.cursor()
    
    try:
        # Get user information from database
        cursor.execute("""
            SELECT userID, username, first_name, last_name, email, 
                   phone_number, address, avatar_image, account_type, is_active, created_at
            FROM users 
            WHERE userID = %s
        """, [user_id])
        
        user_data = cursor.fetchone()
        
        if not user_data:
            messages.error(request, "User account not found.")
            return redirect('login_page')
        
        # Format user information
        user_info = {
            'userID': user_data[0],
            'username': user_data[1],
            'first_name': user_data[2],
            'last_name': user_data[3],
            'email': user_data[4],
            'phone_number': user_data[5],
            'address': user_data[6],
            'avatar_image': user_data[7],
            'account_type': user_data[8],
            'is_active': user_data[9],
            'created_at': user_data[10]
        }

        # Fetch latest delivery address if available
        try:
            cursor.execute(
                "SELECT address FROM delivery_addresses WHERE user_id = %s ORDER BY created_at DESC LIMIT 1",
                [user_info['userID']]
            )
            da = cursor.fetchone()
            user_info['delivery_address'] = da[0] if da else None
        except Exception:
            user_info['delivery_address'] = None
        
        # Get additional statistics based on account type
        statistics = {}
        
        if account_type == 'sponsor':
            # Get sponsor statistics
            cursor.execute("""
                SELECT COUNT(*) 
                FROM sponsor_driver_relationships 
                WHERE sponsor_user_id = %s AND relationship_status = 'active'
            """, [user_id])
            
            active_drivers_result = cursor.fetchone()
            statistics['active_drivers'] = active_drivers_result[0] if active_drivers_result else 0
            
            cursor.execute("""
                SELECT COUNT(*) 
                FROM driver_applications 
                WHERE sponsor_user_id = %s AND application_status = 'pending'
            """, [user_id])
            
            pending_apps_result = cursor.fetchone()
            statistics['pending_applications'] = pending_apps_result[0] if pending_apps_result else 0
            
        elif account_type == 'driver':
            # Get driver statistics
            cursor.execute("""
                SELECT COUNT(*) 
                FROM driver_applications 
                WHERE driver_user_id = %s
            """, [user_id])
            
            total_apps_result = cursor.fetchone()
            statistics['total_applications'] = total_apps_result[0] if total_apps_result else 0
            
            cursor.execute("""
                SELECT COUNT(*) 
                FROM sponsor_driver_relationships 
                WHERE driver_user_id = %s AND relationship_status = 'active'
            """, [user_id])
            
            active_sponsors_result = cursor.fetchone()
            statistics['active_sponsors'] = active_sponsors_result[0] if active_sponsors_result else 0
        
        context = {
            'user_info': user_info,
            'statistics': statistics
        }
        
        return render(request, 'account_page.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading account information: {str(e)}")
        print(f"Account page error: {e}")
        return redirect('homepage')
    finally:
        cursor.close()

@db_login_required
def sponsor_change_request(request):
    """Allow drivers to request a change of sponsor"""
    
    # Check if user is logged in and is a driver
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to submit a sponsor change request.")
        return redirect('login_page')
    
    if request.session.get('account_type') != 'driver':
        messages.error(request, "Only drivers can submit sponsor change requests.")
        return redirect('homepage')
    
    driver_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    if request.method == 'POST':
        try:
            # Get form data - FIXED: Use correct field names from the HTML form
            sponsor_user_id = request.POST.get('sponsor_user_id', '').strip()
            reason_for_change = request.POST.get('reason_for_change', '').strip()
            additional_notes = request.POST.get('additional_notes', '').strip()
            
            # Validation
            if not sponsor_user_id:
                messages.error(request, "Please select a sponsor.")
                return redirect('sponsor_change_request')
            
            # Convert sponsor_user_id to integer
            try:
                sponsor_user_id = int(sponsor_user_id)
            except (ValueError, TypeError):
                messages.error(request, "Invalid sponsor selection.")
                return redirect('sponsor_change_request')
            
            if not reason_for_change:
                messages.error(request, "Please provide your reason for the sponsor change.")
                return redirect('sponsor_change_request')
            
            # Check if driver has an active sponsor relationship
            cursor.execute("""
                SELECT sdr.sponsor_user_id, u.first_name, u.last_name
                FROM sponsor_driver_relationships sdr
                JOIN users u ON sdr.sponsor_user_id = u.userID
                WHERE sdr.driver_user_id = %s AND sdr.relationship_status = %s
            """, [driver_id, 'active'])
            
            current_sponsor = cursor.fetchone()
            
            if not current_sponsor:
                messages.error(request, "You must have an active sponsor before requesting a change.")
                return redirect('sponsor_application')
            
            current_sponsor_id = current_sponsor[0]
            current_sponsor_name = f"{current_sponsor[1]} {current_sponsor[2]}"
            
            # Check if trying to change to the same sponsor
            if current_sponsor_id == sponsor_user_id:
                messages.error(request, f"You are already sponsored by {current_sponsor_name}.")
                return redirect('sponsor_change_request')
            
            # Check if there's already a pending change request
            cursor.execute("""
                SELECT COUNT(*) 
                FROM driver_applications 
                WHERE driver_user_id = %s 
                AND application_status = %s
                AND admin_notes LIKE %s
            """, [driver_id, 'pending', '%SPONSOR CHANGE REQUEST%'])
            
            pending_count_result = cursor.fetchone()
            pending_count = pending_count_result[0] if pending_count_result else 0
            
            if pending_count > 0:
                messages.error(request, "You already have a pending sponsor change request. Please wait for it to be reviewed.")
                return redirect('view_sponsor_requests')
            
            # Get driver's existing information from previous applications
            cursor.execute("""
                SELECT driver_license_number, license_state, license_expiry_date,
                       years_of_experience, date_of_birth
                FROM driver_applications
                WHERE driver_user_id = %s
                ORDER BY application_date DESC
                LIMIT 1
            """, [driver_id])
            
            previous_data = cursor.fetchone()
            
            if previous_data:
                driver_license_number = previous_data[0]
                license_state = previous_data[1]
                license_expiry_date = previous_data[2]
                years_of_experience = previous_data[3]
                date_of_birth = previous_data[4]
            else:
                # If no previous application, use placeholder values
                driver_license_number = "PENDING"
                license_state = "PENDING"
                license_expiry_date = None
                years_of_experience = 0
                date_of_birth = None
            
            # Create the motivation essay from the form data
            motivation_essay = f"SPONSOR CHANGE REQUEST\n\nReason for change:\n{reason_for_change}"
            if additional_notes:
                motivation_essay += f"\n\nAdditional notes:\n{additional_notes}"
            
            # Create admin notes to track the change request
            admin_notes = f"SPONSOR CHANGE REQUEST - From Sponsor ID: {current_sponsor_id} ({current_sponsor_name}) to Sponsor ID: {sponsor_user_id}"
            
            # Insert the sponsor change request
            cursor.execute("""
                INSERT INTO driver_applications (
                    driver_user_id, sponsor_user_id, application_status,
                    application_date, driver_license_number, license_state,
                    license_expiry_date, years_of_experience, date_of_birth,
                    motivation_essay, goals_description, admin_notes,
                    created_at, updated_at
                ) VALUES (
                    %s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
                )
            """, [
                driver_id,
                sponsor_user_id,
                'pending',
                driver_license_number,
                license_state,
                license_expiry_date,
                years_of_experience,
                date_of_birth,
                motivation_essay,
                additional_notes or '',
                admin_notes
            ])
            
            application_id = cursor.lastrowid
            
            # Get new sponsor name for confirmation message
            cursor.execute("""
                SELECT first_name, last_name 
                FROM users 
                WHERE userID = %s
            """, [sponsor_user_id])
            
            new_sponsor = cursor.fetchone()
            new_sponsor_name = f"{new_sponsor[0]} {new_sponsor[1]}" if new_sponsor else "the selected sponsor"
            
            messages.success(request, 
                f"Sponsor change request submitted successfully! Your request to change from {current_sponsor_name} to {new_sponsor_name} is now pending review.")
            
            return redirect('application_success')
            
        except Exception as e:
            messages.error(request, f"Error submitting sponsor change request: {str(e)}")
            print(f"Sponsor change request error: {e}")
            import traceback
            traceback.print_exc()
            return redirect('sponsor_change_request')
        finally:
            cursor.close()
    
    # GET request - display the form
    try:
        # Get current sponsor information first
        cursor.execute("""
            SELECT u.userID, u.first_name, u.last_name, u.username, 
                   sdr.relationship_start_date, sdr.safe_driving_streak_days
            FROM sponsor_driver_relationships sdr
            JOIN users u ON sdr.sponsor_user_id = u.userID
            WHERE sdr.driver_user_id = %s AND sdr.relationship_status = %s
        """, [driver_id, 'active'])
        
        current_sponsor = cursor.fetchone()
        
        if not current_sponsor:
            messages.warning(request, "You must have an active sponsor before requesting a change.")
            return redirect('sponsor_application')
        
        current_relationship = {
            'sponsor_id': current_sponsor[0],
            'sponsor_first_name': current_sponsor[1],
            'sponsor_last_name': current_sponsor[2],
            'sponsor_username': current_sponsor[3],
            'start_date': current_sponsor[4],
            'streak_days': current_sponsor[5] or 0
        }
        
        # Get list of available sponsors (exclude current sponsor)
        cursor.execute("""
            SELECT u.userID, u.first_name, u.last_name, u.username,
                   (SELECT COUNT(*) 
                    FROM sponsor_driver_relationships sdr2 
                    WHERE sdr2.sponsor_user_id = u.userID 
                    AND sdr2.relationship_status = 'active') as current_drivers
            FROM users u
            WHERE u.account_type = %s 
            AND u.is_active = 1
            AND u.userID != %s
            ORDER BY u.last_name, u.first_name
        """, ['sponsor', current_sponsor[0]])
        
        available_sponsors = cursor.fetchall()
        
        context = {
            'available_sponsors': [
                {
                    'userID': sponsor[0],
                    'first_name': sponsor[1],
                    'last_name': sponsor[2],
                    'username': sponsor[3],
                    'current_drivers': sponsor[4]
                }
                for sponsor in available_sponsors
            ],
            'current_relationship': current_relationship
        }
        
        return render(request, 'sponsor_change_request.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading sponsor change request form: {str(e)}")
        print(f"Error loading form: {e}")
        import traceback
        traceback.print_exc()
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
        # Ensure sponsors_settings table exists so we can SELECT/INSERT safely
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sponsors_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sponsor_user_id INT NOT NULL UNIQUE,
                point_exchange_rate INT NOT NULL DEFAULT 100,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_sponsor_user_id (sponsor_user_id)
            )
        """)

        # Get sponsor's basic information
        cursor.execute("""
            SELECT first_name, last_name, email, username
            FROM users 
            WHERE userID = %s
        """, [sponsor_id])
        
        sponsor_info = cursor.fetchone()
        
        # Get sponsor's active drivers - FIX: Store result in variable first
        cursor.execute("""
            SELECT COUNT(*) 
            FROM sponsor_driver_relationships 
            WHERE sponsor_user_id = %s AND relationship_status = 'active'
        """, [sponsor_id])
        
        active_drivers_result = cursor.fetchone()
        active_drivers_count = active_drivers_result[0] if active_drivers_result else 0
        
        # Get pending applications - FIX: Store result in variable first
        cursor.execute("""
            SELECT COUNT(*) 
            FROM driver_applications 
            WHERE sponsor_user_id = %s AND application_status = 'pending'
        """, [sponsor_id])
        
        pending_applications_result = cursor.fetchone()
        pending_applications = pending_applications_result[0] if pending_applications_result else 0
        
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

        # Ensure transactions table exists for point adjustments
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS driver_points_transactions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    sponsor_user_id INT NOT NULL,
                    driver_user_id INT NOT NULL,
                    points INT NOT NULL,
                    message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_sponsor_driver (sponsor_user_id, driver_user_id)
                )
            """)
        except Exception as e:
            print(f"Error ensuring transactions table: {e}")

        # Attach points summary and recent transactions for each driver
        for d in drivers_list:
            try:
                cursor.execute(
                    "SELECT IFNULL(SUM(points), 0) FROM driver_points_transactions WHERE sponsor_user_id = %s AND driver_user_id = %s",
                    [sponsor_id, d['user_id']]
                )
                pts_row = cursor.fetchone()
                d['points'] = pts_row[0] if pts_row else 0

                cursor.execute(
                    "SELECT points, message, created_at FROM driver_points_transactions WHERE sponsor_user_id = %s AND driver_user_id = %s ORDER BY created_at DESC LIMIT 5",
                    [sponsor_id, d['user_id']]
                )
                tx_rows = cursor.fetchall()
                d['transactions'] = [
                    {'points': t[0], 'message': t[1], 'created_at': t[2]} for t in tx_rows
                ]
            except Exception as e:
                print(f"Error loading transactions for driver {d['user_id']}: {e}")
                d['points'] = 0
                d['transactions'] = []
        
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
        
        # Calculate total outstanding points
        total_outstanding_points = sum(d['points'] for d in drivers_list)
        
        context = {
            'sponsored_drivers': drivers_list,
            'pending_applications': applications_list,
            'total_drivers': len(drivers_list),
            'active_drivers': len([d for d in drivers_list if d['relationship_status'] == 'active']),
            'total_outstanding_points': total_outstanding_points
        }
        
        return render(request, 'sponsor_drivers.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading sponsored drivers: {str(e)}")
        return redirect('sponsor_home')
    finally:
        cursor.close()


def is_admin(user):
    return user.is_staff or user.is_superuser

@user_passes_test(is_admin)
def add_admin(request):
    """Allow existing admins to add a new admin."""
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
        else:
            new_admin = User.objects.create_user(username=username, email=email, password=password)
            new_admin.is_staff = True
            new_admin.save()
            messages.success(request, f"Admin '{username}' added successfully.")
            return redirect("admin_list")

    return render(request, "add_admin.html")

@user_passes_test(is_admin)
def admin_list(request):
    """Show all admins with option to delete."""
    admins = User.objects.filter(is_staff=True)
    return render(request, "admin_list.html", {"admins": admins})

@user_passes_test(is_admin)
def delete_admin(request, admin_id):
    """Delete a selected admin."""
    admin_user = get_object_or_404(User, id=admin_id, is_staff=True)

    if request.user == admin_user:
        messages.error(request, "You cannot delete your own account.")
    else:
        admin_user.delete()
        messages.success(request, "Admin deleted successfully.")

    return redirect("admin_list")

@user_passes_test(is_admin)
def driver_list(request):
    """Display all drivers and allow admin to update their active status."""
    drivers = User.objects.filter(is_staff=False)  # assuming drivers are non-admin users

    if request.method == "POST":
        driver_id = request.POST.get("driver_id")
        new_status = request.POST.get("status") == "True"
        driver = get_object_or_404(User, id=driver_id)
        driver.is_active = new_status
        driver.save()
        messages.success(request, f"Driver '{driver.username}' status updated.")
        return redirect("driver_list")

    return render(request, "driver_list.html", {"drivers": drivers})


@admin_required
def admin_driver_dashboard(request):
    """Admin dashboard: list all drivers with their points from all sponsors.

    This uses the same session-based admin check (`admin_required`) used elsewhere in the app
    so it works with your database-backed login/session system.
    """
    cursor = connection.cursor()
    try:
        # Get all drivers
        cursor.execute("""
            SELECT userID, username, first_name, last_name, email,
                   phone_number, account_type, is_active, created_at
            FROM users
            WHERE account_type = %s
            ORDER BY last_name, first_name
        """, ['driver'])

        rows = cursor.fetchall()
        drivers = []
        total_points_across_all_drivers = 0
        
        for r in rows:
            driver_data = {
                'user_id': r[0],
                'username': r[1],
                'first_name': r[2],
                'last_name': r[3],
                'email': r[4],
                'phone_number': r[5],
                'account_type': r[6],
                'is_active': bool(r[7]),
                'created_at': r[8],
                'total_points': 0,
                'sponsor_breakdown': []
            }
            
            # Get points from all sponsors for this driver
            try:
                cursor.execute("""
                    SELECT 
                        dpt.sponsor_user_id,
                        u.first_name AS sponsor_first_name,
                        u.last_name AS sponsor_last_name,
                        u.username AS sponsor_username,
                        SUM(dpt.points) AS total_points_from_sponsor,
                        COUNT(dpt.id) AS transaction_count
                    FROM driver_points_transactions dpt
                    JOIN users u ON dpt.sponsor_user_id = u.userID
                    WHERE dpt.driver_user_id = %s
                    GROUP BY dpt.sponsor_user_id, u.first_name, u.last_name, u.username
                    ORDER BY total_points_from_sponsor DESC
                """, [r[0]])
                
                sponsor_points = cursor.fetchall()
                driver_total = 0
                
                for sp in sponsor_points:
                    points_from_sponsor = sp[4] or 0
                    driver_total += points_from_sponsor
                    driver_data['sponsor_breakdown'].append({
                        'sponsor_id': sp[0],
                        'sponsor_name': f"{sp[1]} {sp[2]}",
                        'sponsor_username': sp[3],
                        'points': points_from_sponsor,
                        'transaction_count': sp[5]
                    })
                
                driver_data['total_points'] = driver_total
                total_points_across_all_drivers += driver_total
                
            except Exception as e:
                print(f"Error loading points for driver {r[0]}: {e}")
                driver_data['total_points'] = 0
                driver_data['sponsor_breakdown'] = []
            
            drivers.append(driver_data)

        return render(request, 'admin_driver_list.html', {
            'drivers': drivers,
            'total_drivers': len(drivers),
            'total_points_all_drivers': total_points_across_all_drivers
        })

    except Exception as e:
        messages.error(request, f"Error loading drivers: {str(e)}")
        return redirect('account_page')
    finally:
        try:
            cursor.close()
        except:
            pass


@admin_required
def admin_delete_driver(request, user_id):
    """Delete a driver and related records from the custom database tables.

    This removes related delivery addresses, sponsor relationships, driver applications,
    and the users table row. It's admin-only and uses POST for safety.
    """
    if request.method != 'POST':
        messages.error(request, "Invalid request method.")
        return redirect('admin_driver_dashboard')

    cursor = connection.cursor()
    try:
        # Remove related rows first to avoid FK issues
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

        # Finally delete the user row
        cursor.execute("DELETE FROM users WHERE userID = %s", [user_id])

        try:
            connection.commit()
        except Exception:
            pass

        messages.success(request, "Driver and related data deleted successfully.")
        return redirect('admin_driver_dashboard')

    except Exception as e:
        messages.error(request, f"Error deleting driver: {str(e)}")
        return redirect('admin_driver_dashboard')
    finally:
        try:
            cursor.close()
        except:
            pass

# Add these functions to your existing driver_program/views.py file


@admin_required
def admin_drivers_csv_export(request):
    """Export all drivers and their point transactions to CSV format."""
    import csv
    from django.http import HttpResponse
    from datetime import datetime
    
    cursor = connection.cursor()
    
    try:
        # Create the HTTP response with CSV content type
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="drivers_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        writer = csv.writer(response)
        
        # Write the header row
        writer.writerow([
            'Driver ID',
            'Username', 
            'First Name',
            'Last Name',
            'Email',
            'Phone',
            'Status',
            'Join Date',
            'Total Points',
            'Transaction Date',
            'Transaction Points',
            'Transaction Message',
            'Sponsor Name',
            'Sponsor Username'
        ])
        
        # Get all drivers
        cursor.execute("""
            SELECT userID, username, first_name, last_name, email,
                   phone_number, is_active, created_at
            FROM users
            WHERE account_type = %s
            ORDER BY last_name, first_name
        """, ['driver'])
        
        drivers = cursor.fetchall()
        
        for driver in drivers:
            driver_id = driver[0]
            username = driver[1]
            first_name = driver[2]
            last_name = driver[3]
            email = driver[4]
            phone = driver[5] or ''
            is_active = 'Active' if driver[6] else 'Inactive'
            join_date = driver[7].strftime('%Y-%m-%d') if driver[7] else ''
            
            # Get all transactions for this driver
            cursor.execute("""
                SELECT 
                    dpt.points,
                    dpt.message,
                    dpt.created_at,
                    u.first_name AS sponsor_first_name,
                    u.last_name AS sponsor_last_name,
                    u.username AS sponsor_username
                FROM driver_points_transactions dpt
                JOIN users u ON dpt.sponsor_user_id = u.userID
                WHERE dpt.driver_user_id = %s
                ORDER BY dpt.created_at DESC
            """, [driver_id])
            
            transactions = cursor.fetchall()
            
            # Calculate total points
            total_points = sum(t[0] for t in transactions) if transactions else 0
            
            if transactions:
                # Write one row per transaction
                for transaction in transactions:
                    transaction_points = transaction[0]
                    transaction_message = transaction[1] or ''
                    transaction_date = transaction[2].strftime('%Y-%m-%d %H:%M:%S') if transaction[2] else ''
                    sponsor_name = f"{transaction[3]} {transaction[4]}"
                    sponsor_username = transaction[5]
                    
                    writer.writerow([
                        driver_id,
                        username,
                        first_name,
                        last_name,
                        email,
                        phone,
                        is_active,
                        join_date,
                        total_points,
                        transaction_date,
                        transaction_points,
                        transaction_message,
                        sponsor_name,
                        sponsor_username
                    ])
            else:
                # Write one row for drivers with no transactions
                writer.writerow([
                    driver_id,
                    username,
                    first_name,
                    last_name,
                    email,
                    phone,
                    is_active,
                    join_date,
                    0,  # total_points
                    '',  # transaction_date
                    '',  # transaction_points
                    '',  # transaction_message
                    '',  # sponsor_name
                    ''   # sponsor_username
                ])
        
        return response
        
    except Exception as e:
        messages.error(request, f"Error generating CSV export: {str(e)}")
        return redirect('admin_driver_dashboard')
    finally:
        try:
            cursor.close()
        except:
            pass

@db_login_required
def sponsor_manage_applications(request):
    """Allow sponsors to view and manage driver applications"""
    
    # Check if user is logged in and is a sponsor
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can view this page.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Get all applications for this sponsor - FIXED: Remove driver info from users table
        cursor.execute("""
            SELECT 
                da.application_id, da.driver_user_id, da.sponsor_user_id,
                da.application_status, da.application_date, da.driver_license_number,
                da.license_state, da.license_expiry_date, da.years_of_experience,
                da.date_of_birth, da.motivation_essay, da.goals_description,
                da.admin_notes, da.review_date, da.reviewed_by_admin_id,
                da.rejection_reason, da.created_at, da.updated_at,
                u.username, u.first_name, u.last_name, u.email, u.phone_number,
                u.address, u.is_active, u.created_at as user_created
            FROM driver_applications da
            JOIN users u ON da.driver_user_id = u.userID
            WHERE da.sponsor_user_id = %s
            ORDER BY 
                CASE da.application_status 
                    WHEN 'pending' THEN 1 
                    WHEN 'under_review' THEN 2 
                    ELSE 3 
                END,
                da.application_date DESC
        """, [sponsor_id])
        
        applications = cursor.fetchall()
        
        # Format applications for template
        applications_list = []
        for app in applications:
            # Check if this is a sponsor change request based on admin_notes
            is_change_request = app[12] and 'SPONSOR CHANGE REQUEST' in str(app[12])
            
            applications_list.append({
                'application_id': app[0],
                'driver_user_id': app[1],
                'sponsor_user_id': app[2],
                'application_status': app[3],
                'application_date': app[4],
                'driver_license_number': app[5],  # From driver_applications table
                'license_state': app[6],
                'license_expiry_date': app[7],
                'years_of_experience': app[8],
                'date_of_birth': app[9],
                'motivation_essay': app[10],
                'goals_description': app[11],
                'admin_notes': app[12],
                'review_date': app[13],
                'reviewed_by_admin_id': app[14],
                'rejection_reason': app[15],
                'created_at': app[16],
                'updated_at': app[17],
                'driver_username': app[18],   # From users table
                'driver_first_name': app[19], # From users table
                'driver_last_name': app[20],  # From users table
                'driver_email': app[21],      # From users table
                'driver_phone': app[22],      # From users table
                'driver_address': app[23],    # From users table
                'driver_is_active': app[24],  # From users table
                'driver_created': app[25],    # From users table
                'is_change_request': is_change_request
            })
        
        # Get statistics
        pending_count = len([app for app in applications_list if app['application_status'] == 'pending'])
        approved_count = len([app for app in applications_list if app['application_status'] == 'approved'])
        rejected_count = len([app for app in applications_list if app['application_status'] == 'rejected'])
        
        context = {
            'applications': applications_list,
            'pending_count': pending_count,
            'approved_count': approved_count,
            'rejected_count': rejected_count,
            'total_count': len(applications_list)
        }
        
        return render(request, 'sponsor_manage_applications.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading applications: {str(e)}")
        print(f"Sponsor manage applications error: {e}")
        return redirect('sponsor_home')
    finally:
        cursor.close()

@csrf_protect
def sponsor_application_action(request, application_id):
    """Handle sponsor actions on driver applications (approve/reject)"""
    
    # Check if user is logged in and is a sponsor
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')
    
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can perform this action.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    
    if request.method == 'POST':
        action = request.POST.get('action')  # 'approve' or 'reject'
        admin_notes = request.POST.get('admin_notes', '').strip()
        rejection_reason = request.POST.get('rejection_reason', '').strip()
        
        if action not in ['approve', 'reject']:
            messages.error(request, "Invalid action.")
            return redirect('sponsor_manage_applications')
        
        cursor = connection.cursor()
        
        try:
            # First, verify this application belongs to this sponsor
            cursor.execute("""
                SELECT da.driver_user_id, da.application_status, da.admin_notes,
                       u.first_name, u.last_name
                FROM driver_applications da
                JOIN users u ON da.driver_user_id = u.userID
                WHERE da.application_id = %s AND da.sponsor_user_id = %s
            """, [application_id, sponsor_id])
            
            application_data = cursor.fetchone()
            
            if not application_data:
                messages.error(request, "Application not found or you don't have permission to modify it.")
                return redirect('sponsor_manage_applications')
            
            driver_id = application_data[0]
            current_status = application_data[1]
            existing_notes = application_data[2] or ''
            driver_name = f"{application_data[3]} {application_data[4]}"
            
            if current_status not in ['pending', 'under_review']:
                messages.error(request, "This application has already been processed.")
                return redirect('sponsor_manage_applications')
            
            # Check if this is a sponsor change request
            is_change_request = 'SPONSOR CHANGE REQUEST' in existing_notes
            
            if action == 'approve':
                # Update application status
                cursor.execute("""
                    UPDATE driver_applications 
                    SET application_status = 'approved', 
                        review_date = NOW(),
                        reviewed_by_admin_id = %s,
                        admin_notes = %s
                    WHERE application_id = %s
                """, [sponsor_id, admin_notes, application_id])
                
                if is_change_request:
                    # For sponsor change requests, end the current relationship and create new one
                    try:
                        # End current active relationship
                        cursor.execute("""
                            UPDATE sponsor_driver_relationships 
                            SET relationship_status = 'ended', 
                                relationship_end_date = NOW(),
                                updated_at = NOW()
                            WHERE driver_user_id = %s 
                            AND relationship_status = 'active'
                        """, [driver_id])
                        
                        # Create new relationship
                        cursor.execute("""
                            INSERT INTO sponsor_driver_relationships (
                                sponsor_user_id, driver_user_id, application_id,
                                relationship_status, relationship_start_date, 
                                created_at, updated_at
                            ) VALUES (%s, %s, %s, 'active', NOW(), NOW(), NOW())
                        """, [sponsor_id, driver_id, application_id])
                        
                        messages.success(request, f"Sponsor change request approved! {driver_name} is now your sponsored driver.")
                        
                    except Exception as rel_error:
                        print(f"Error creating new relationship: {rel_error}")
                        messages.warning(request, f"Application approved, but there was an issue creating the new sponsor relationship. Please contact an administrator.")
                else:
                    # For new applications, create the relationship
                    try:
                        cursor.execute("""
                            INSERT INTO sponsor_driver_relationships (
                                sponsor_user_id, driver_user_id, application_id,
                                relationship_status, relationship_start_date,
                                created_at, updated_at
                            ) VALUES (%s, %s, %s, 'active', NOW(), NOW(), NOW())
                        """, [sponsor_id, driver_id, application_id])
                        
                        messages.success(request, f"Application approved! {driver_name} is now your sponsored driver.")
                        
                    except Exception as rel_error:
                        print(f"Error creating relationship: {rel_error}")
                        messages.warning(request, f"Application approved, but there was an issue creating the sponsor relationship. Please contact an administrator.")
                
            elif action == 'reject':
                if not rejection_reason:
                    messages.error(request, "Please provide a reason for rejection.")
                    return redirect('sponsor_manage_applications')
                
                # Update application status
                cursor.execute("""
                    UPDATE driver_applications 
                    SET application_status = 'rejected', 
                        review_date = NOW(),
                        reviewed_by_admin_id = %s,
                        rejection_reason = %s,
                        admin_notes = %s
                    WHERE application_id = %s
                """, [sponsor_id, rejection_reason, admin_notes, application_id])
                
                action_type = "change request" if is_change_request else "application"
                messages.success(request, f"Driver {action_type} rejected. {driver_name} has been notified.")
            
        except Exception as e:
            messages.error(request, f"Error processing application: {str(e)}")
            print(f"Application action error: {e}")
        finally:
            cursor.close()
    
    return redirect('sponsor_manage_applications')

@db_login_required
def sponsor_view_application(request, application_id):
    """View detailed information about a specific driver application"""
    
    # Check if user is logged in and is a sponsor
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can view this page.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Get application details - FIXED: Correct column references
        cursor.execute("""
            SELECT 
                da.application_id, da.driver_user_id, da.sponsor_user_id,
                da.application_status, da.application_date, da.driver_license_number,
                da.license_state, da.license_expiry_date, da.years_of_experience,
                da.date_of_birth, da.motivation_essay, da.goals_description,
                da.admin_notes, da.review_date, da.reviewed_by_admin_id,
                da.rejection_reason, da.created_at, da.updated_at,
                u.username, u.first_name, u.last_name, u.email, u.phone_number,
                u.address, u.is_active, u.created_at as user_created
            FROM driver_applications da
            JOIN users u ON da.driver_user_id = u.userID
            WHERE da.application_id = %s AND da.sponsor_user_id = %s
        """, [application_id, sponsor_id])
        
        application_data = cursor.fetchone()
        
        if not application_data:
            messages.error(request, "Application not found or you don't have permission to view it.")
            return redirect('sponsor_manage_applications')
        
        # Check if this is a sponsor change request
        is_change_request = application_data[12] and 'SPONSOR CHANGE REQUEST' in str(application_data[12])
        
        # Get current sponsor info if this is a change request
        current_sponsor_info = None
        if is_change_request:
            cursor.execute("""
                SELECT u.first_name, u.last_name, u.username, sdr.relationship_start_date
                FROM sponsor_driver_relationships sdr
                JOIN users u ON sdr.sponsor_user_id = u.userID
                WHERE sdr.driver_user_id = %s AND sdr.relationship_status = %s
            """, [application_data[1], 'active'])
            
            current_sponsor = cursor.fetchone()
            if current_sponsor:
                current_sponsor_info = {
                    'name': f"{current_sponsor[0]} {current_sponsor[1]}",
                    'username': current_sponsor[2],
                    'relationship_start': current_sponsor[3]
                }
        
        # REMOVED: Problematic status history query
        # Instead, create a simple status timeline from the application data itself
        status_history = []
        
        # Create basic status history from available application data
        if application_data[4]:  # application_date
            status_history.append({
                'previous_status': None,
                'new_status': 'submitted',
                'change_date': application_data[4],  # application_date
                'change_reason': 'Application submitted',
                'changed_by': 'Driver'
            })
        
        # Add review entry if review_date exists
        if application_data[13] and application_data[3] in ['approved', 'rejected']:  # review_date and current status
            status_history.append({
                'previous_status': 'pending',
                'new_status': application_data[3],
                'change_date': application_data[13],  # review_date
                'change_reason': f'Application {application_data[3]} by sponsor',
                'changed_by': 'Sponsor'
            })
        
        application = {
            'application_id': application_data[0],
            'driver_user_id': application_data[1],
            'sponsor_user_id': application_data[2],
            'application_status': application_data[3],
            'application_date': application_data[4],
            'driver_license_number': application_data[5],  # From driver_applications table
            'license_state': application_data[6],
            'license_expiry_date': application_data[7],
            'years_of_experience': application_data[8],
            'date_of_birth': application_data[9],
            'motivation_essay': application_data[10],
            'goals_description': application_data[11],
            'admin_notes': application_data[12],
            'review_date': application_data[13],
            'reviewed_by_admin_id': application_data[14],
            'rejection_reason': application_data[15],
            'created_at': application_data[16],
            'updated_at': application_data[17],
            'driver_username': application_data[18],   # From users table
            'driver_first_name': application_data[19], # From users table
            'driver_last_name': application_data[20],  # From users table
            'driver_email': application_data[21],      # From users table
            'driver_phone': application_data[22],      # From users table
            'driver_address': application_data[23],    # From users table
            'driver_is_active': application_data[24],  # From users table
            'driver_created': application_data[25],    # From users table
            'is_change_request': is_change_request,
            'current_sponsor': current_sponsor_info,
            'status_history': status_history
        }
        
        context = {
            'application': application
        }
        
        return render(request, 'sponsor_view_application.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading application details: {str(e)}")
        print(f"View application error: {e}")
        return redirect('sponsor_manage_applications')
    finally:
        cursor.close()
        
def adjust_catalogue(request):
    """Allow a sponsor to select which catalogue categories should be displayed.

    Stores selections in a simple DB table `sponsor_catalogue_preferences` as a
    comma-separated list in `categories`.
    """
    # Auth checks
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')

    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can perform this action.")
        return redirect('homepage')

    sponsor_id = request.session.get('user_id') or request.session.get('id')
    cursor = connection.cursor()

    try:
        # Create preferences table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sponsor_catalogue_preferences (
                sponsor_user_id INT PRIMARY KEY,
                categories TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)

        if request.method == 'POST':
            # Expect multiple checkbox values under 'categories'
            selected = request.POST.getlist('categories')
            categories_str = ','.join([c.strip() for c in selected if c.strip()])

            # Upsert preferences — REPLACE is portable for simple upsert here
            cursor.execute(
                "REPLACE INTO sponsor_catalogue_preferences (sponsor_user_id, categories) VALUES (%s, %s)",
                [sponsor_id, categories_str]
            )
            connection.commit()
            messages.success(request, "Catalogue preferences updated.")
            return redirect('sponsor_adjust_catalogue')

        # GET -> build form: preferred categories + available categories from API
        try:
            resp = requests.get('https://fakestoreapi.com/products/categories', timeout=5)
            resp.raise_for_status()
            all_categories = resp.json()
        except Exception:
            # Fallback: fetch products and derive categories
            try:
                resp = requests.get('https://fakestoreapi.com/products', timeout=5)
                resp.raise_for_status()
                products = resp.json()
                all_categories = sorted(list({p.get('category') for p in products if p.get('category')}))
            except Exception:
                all_categories = []

        # Load current selection
        cursor.execute("SELECT categories FROM sponsor_catalogue_preferences WHERE sponsor_user_id = %s", [sponsor_id])
        row = cursor.fetchone()
        selected = [c for c in (row[0].split(',') if row and row[0] else []) if c]

        return render(request, 'sponsor_adjust_catalogue.html', {
            'categories': all_categories,
            'selected': selected
        })

    except Exception as e:
        messages.error(request, f"Error loading catalogue preferences: {str(e)}")
        return redirect('sponsor_home')
    finally:
        cursor.close()
        
def sponsor_adjust_point_exchange_rate(request):
    """Allow sponsors to adjust their point exchange rate."""
    
    # Check if user is logged in and is a sponsor
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')
    
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can perform this action.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('id')
    cursor = connection.cursor()
    
    try:
        if request.method == 'POST':
            new_rate = request.POST.get('point_exchange_rate')
            try:
                new_rate = float(new_rate)
                if new_rate <= 0:
                    raise ValueError("Exchange rate must be positive.")
                
                # Update the sponsor's point exchange rate
                cursor.execute("""
                    UPDATE sponsors_settings
                    SET point_exchange_rate = %s, updated_at = NOW()
                    WHERE id = %s
                """, [new_rate, sponsor_id])
                
                messages.success(request, "Point exchange rate updated successfully.")
                return redirect('sponsor_home')
                
            except ValueError as ve:
                messages.error(request, f"Invalid exchange rate: {str(ve)}")
        
        # Fetch current exchange rate for display
        cursor.execute("""
            SELECT point_exchange_rate
            FROM sponsors_settings
            WHERE id = %s
        """, [sponsor_id])
        
        row = cursor.fetchone()
        current_rate = row[0] if row else None
        
        return render(request, 'sponsor_adjust_point_exchange_rate.html', {
            'current_rate': current_rate
        })
        
    except Exception as e:
        messages.error(request, f"Error updating exchange rate: {str(e)}")
        return redirect('sponsor_home')
    finally:
        cursor.close()
    

# ADMIN DASHBOARD: REVIEW USER ACCOUNT STATUSES
def is_admin(user):
    return user.is_staff or user.is_superuser


@user_passes_test(is_admin)
def review_admin_status(request):
    """View all admins and their account status."""
    admins = User.objects.filter(is_staff=True)

    if request.method == "POST":
        admin_id = request.POST.get("admin_id")
        new_status = request.POST.get("status") == "True"
        admin_user = get_object_or_404(User, id=admin_id)
        admin_user.is_active = new_status
        admin_user.save()
        messages.success(request, f"Admin '{admin_user.username}' status updated.")
        return redirect("review_admin_status")

    return render(request, "admin_status.html", {"admins": admins})


@user_passes_test(is_admin)
def review_sponsor_status(request):
    """View all sponsors and their account status."""
    sponsors = User.objects.filter(groups__name='Sponsor')

    if request.method == "POST":
        sponsor_id = request.POST.get("sponsor_id")
        new_status = request.POST.get("status") == "True"
        sponsor_user = get_object_or_404(User, id=sponsor_id)
        sponsor_user.is_active = new_status
        sponsor_user.save()
        messages.success(request, f"Sponsor '{sponsor_user.username}' status updated.")
        return redirect("review_sponsor_status")

    return render(request, "sponsor_status.html", {"sponsors": sponsors})


@user_passes_test(is_admin)
def review_driver_status(request):
    """View all drivers and their account status."""
    drivers = User.objects.filter(groups__name='Driver')

    if request.method == "POST":
        driver_id = request.POST.get("driver_id")
        new_status = request.POST.get("status") == "True"
        driver_user = get_object_or_404(User, id=driver_id)
        driver_user.is_active = new_status
        driver_user.save()
        messages.success(request, f"Driver '{driver_user.username}' status updated.")
        return redirect("review_driver_status")

    return render(request, "driver_status.html", {"drivers": drivers})

def view_products(request):
    """Display products from Fake Store API with optional sorting and search"""
    import requests

    sort_order = request.GET.get('sort', '')  # Get sort parameter from query string
    search_query = request.GET.get('search', '').strip()

    try:
        # Fetch products from the Fake Store API
        response = requests.get('https://fakestoreapi.com/products')
        response.raise_for_status()
        products = response.json()
        
        # Sort products if requested
        if sort_order == 'price_asc':
            products.sort(key=lambda x: float(x['price']))
        elif sort_order == 'price_desc':
            products.sort(key=lambda x: float(x['price']), reverse=True)
        
        # Filter products based on search query
        if search_query:
            search_lower = search_query.lower()
            products = [
                product for product in products
                if (search_lower in product.get('title', '').lower() or
                    search_lower in product.get('description', '').lower() or
                    search_lower in product.get('category', '').lower())
            ]

        # If the current user is a sponsor, apply their catalogue category preferences (if any)
        try:
            if request.session.get('is_authenticated') and request.session.get('account_type') == 'sponsor':
                sponsor_id = request.session.get('user_id') or request.session.get('id')
                if sponsor_id:
                    cur = connection.cursor()
                    try:
                        cur.execute("SELECT categories FROM sponsor_catalogue_preferences WHERE sponsor_user_id = %s", [sponsor_id])
                        r = cur.fetchone()
                        if r and r[0]:
                            prefs = [c.strip() for c in r[0].split(',') if c.strip()]
                            if prefs:
                                products = [p for p in products if p.get('category') in prefs]
                    finally:
                        try:
                            cur.close()
                        except Exception:
                            pass
        except Exception:
            # Don't fail the whole page if preferences lookup or filtering fails
            pass

        # Render template with products
        return render(request, 'products.html', {
            'products': products,
            'current_sort': sort_order,
            'search_query': search_query,
            'total_products': len(products)
        })

    except requests.RequestException as e:
        return render(request, 'products.html', {
            'error_message': f"Failed to fetch products: {str(e)}",
            'products': [],
            'search_query': search_query,
            'total_products': 0
        })


@db_login_required
def view_product(request, product_id):
    """Display a single product's details from Fake Store API"""

    try:
        response = requests.get(f'https://fakestoreapi.com/products/{product_id}')
        response.raise_for_status()
        product = response.json()

        wishlist = []
        if request.session.get('is_authenticated'):
            try:
                wishlist = get_user_wishlist(request.session.get('user_id'))
            except Exception:
                wishlist = []

        return render(request, 'product_detail.html', {
            'product': product,
            'wishlist': wishlist
        })
    except requests.RequestException as e:
        messages.error(request, f"Failed to fetch product details: {str(e)}")
        return redirect('view_products')
      
      
@db_login_required
def admin_sponsor_list(request):
    """Admin page to view and manage all sponsors"""
    
    # Check if user is logged in and is an admin
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')
    
    if request.session.get('account_type') != 'admin':
        messages.error(request, "Access denied. Only administrators can view this page.")
        return redirect('homepage')
    
    cursor = connection.cursor()
    
    try:
        # Get all sponsors with their statistics
        cursor.execute("""
            SELECT 
                u.userID, u.username, u.first_name, u.last_name, u.email,
                u.phone_number, u.address, u.is_active, u.created_at,
                (SELECT COUNT(*) 
                 FROM sponsor_driver_relationships sdr 
                 WHERE sdr.sponsor_user_id = u.userID 
                 AND sdr.relationship_status = 'active') as active_drivers,
                (SELECT COUNT(*) 
                 FROM driver_applications da 
                 WHERE da.sponsor_user_id = u.userID 
                 AND da.application_status = 'pending') as pending_applications,
                (SELECT COUNT(*) 
                 FROM driver_applications da 
                 WHERE da.sponsor_user_id = u.userID 
                 AND da.application_status = 'approved') as total_approved
            FROM users u
            WHERE u.account_type = 'sponsor'
            ORDER BY u.created_at DESC
        """)
        
        sponsors_data = cursor.fetchall()
        
        sponsors_list = []
        for sponsor in sponsors_data:
            sponsors_list.append({
                'userID': sponsor[0],
                'username': sponsor[1],
                'first_name': sponsor[2],
                'last_name': sponsor[3],
                'email': sponsor[4],
                'phone_number': sponsor[5],
                'address': sponsor[6],
                'is_active': sponsor[7],
                'created_at': sponsor[8],
                'active_drivers': sponsor[9],
                'pending_applications': sponsor[10],
                'total_approved': sponsor[11]
            })
        
        # Get statistics
        total_sponsors = len(sponsors_list)
        active_sponsors = len([s for s in sponsors_list if s['is_active']])
        inactive_sponsors = total_sponsors - active_sponsors
        
        context = {
            'sponsors': sponsors_list,
            'total_sponsors': total_sponsors,
            'active_sponsors': active_sponsors,
            'inactive_sponsors': inactive_sponsors
        }
        
        return render(request, 'admin_sponsor_list.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading sponsors: {str(e)}")
        print(f"Admin sponsor list error: {e}")
        return redirect('account_page')
    finally:
        cursor.close()


@db_login_required
def admin_update_sponsor_status(request, sponsor_id):
    """Toggle sponsor active/inactive status"""

    # Check if user is logged in and is an admin
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')

    if request.session.get('account_type') != 'admin':
        messages.error(request, "Access denied. Only administrators can perform this action.")
        return redirect('homepage')

    if request.method == 'POST':
        cursor = connection.cursor()

        try:
            # Get current sponsor status
            cursor.execute("""
                SELECT username, first_name, last_name, is_active, account_type
                FROM users
                WHERE userID = %s
            """, [sponsor_id])

            sponsor_data = cursor.fetchone()

            if not sponsor_data:
                messages.error(request, "Sponsor not found.")
                return redirect('admin_sponsor_list')

            if sponsor_data[4] != 'sponsor':
                messages.error(request, "This user is not a sponsor.")
                return redirect('admin_sponsor_list')

            username = sponsor_data[0]
            full_name = f"{sponsor_data[1]} {sponsor_data[2]}"
            current_status = sponsor_data[3]

            # Toggle status
            new_status = 0 if current_status else 1

            cursor.execute("""
                UPDATE users
                SET is_active = %s
                WHERE userID = %s
            """, [new_status, sponsor_id])

            status_text = "activated" if new_status else "deactivated"
            messages.success(request, f"Sponsor {full_name} (@{username}) has been {status_text}.")

        except Exception as e:
            messages.error(request, f"Error updating sponsor status: {str(e)}")
            print(f"Update sponsor status error: {e}")
        finally:
            cursor.close()

    return redirect('admin_sponsor_list')

@db_login_required
def admin_sponsor_details(request, sponsor_id):
    """View detailed information about a specific sponsor"""
    
    # Check if user is logged in and is an admin
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')
    
    if request.session.get('account_type') != 'admin':
        messages.error(request, "Access denied. Only administrators can view this page.")
        return redirect('homepage')
    
    cursor = connection.cursor()
    
    try:
        # Get sponsor information
        cursor.execute("""
            SELECT userID, username, first_name, last_name, email,
                   phone_number, address, organization, is_active, created_at, account_type
            FROM users
            WHERE userID = %s
        """, [sponsor_id])
        
        sponsor_data = cursor.fetchone()
        
        if not sponsor_data or sponsor_data[10] != 'sponsor':
            messages.error(request, "Sponsor not found.")
            return redirect('admin_sponsor_list')
        
        sponsor_info = {
            'userID': sponsor_data[0],
            'username': sponsor_data[1],
            'first_name': sponsor_data[2],
            'last_name': sponsor_data[3],
            'email': sponsor_data[4],
            'phone_number': sponsor_data[5],
            'address': sponsor_data[6],
            'organization': sponsor_data[7],
            'is_active': sponsor_data[8],
            'created_at': sponsor_data[9]
        }
        
        # Get active drivers
        cursor.execute("""
            SELECT u.userID, u.username, u.first_name, u.last_name,
                   sdr.relationship_start_date, sdr.safe_driving_streak_days,
                   sdr.total_trips_logged
            FROM sponsor_driver_relationships sdr
            JOIN users u ON sdr.driver_user_id = u.userID
            WHERE sdr.sponsor_user_id = %s AND sdr.relationship_status = 'active'
            ORDER BY sdr.relationship_start_date DESC
        """, [sponsor_id])
        
        active_drivers = cursor.fetchall()
        
        # Get pending applications
        cursor.execute("""
            SELECT da.application_id, da.driver_user_id, da.application_date,
                   u.username, u.first_name, u.last_name
            FROM driver_applications da
            JOIN users u ON da.driver_user_id = u.userID
            WHERE da.sponsor_user_id = %s AND da.application_status = 'pending'
            ORDER BY da.application_date DESC
        """, [sponsor_id])
        
        pending_applications = cursor.fetchall()
        
        # Get relationship history
        cursor.execute("""
            SELECT u.userID, u.username, u.first_name, u.last_name,
                   sdr.relationship_start_date, sdr.relationship_end_date,
                   sdr.relationship_status
            FROM sponsor_driver_relationships sdr
            JOIN users u ON sdr.driver_user_id = u.userID
            WHERE sdr.sponsor_user_id = %s
            ORDER BY sdr.relationship_start_date DESC
        """, [sponsor_id])
        
        relationship_history = cursor.fetchall()
        
        context = {
            'sponsor': sponsor_info,
            'active_drivers': [
                {
                    'userID': driver[0],
                    'username': driver[1],
                    'first_name': driver[2],
                    'last_name': driver[3],
                    'relationship_start_date': driver[4],
                    'streak_days': driver[5] or 0,
                    'total_trips': driver[6] or 0
                }
                for driver in active_drivers
            ],
            'pending_applications': [
                {
                    'application_id': app[0],
                    'driver_user_id': app[1],
                    'application_date': app[2],
                    'driver_username': app[3],
                    'driver_first_name': app[4],
                    'driver_last_name': app[5]
                }
                for app in pending_applications
            ],
            'relationship_history': [
                {
                    'driver_user_id': rel[0],
                    'driver_username': rel[1],
                    'driver_first_name': rel[2],
                    'driver_last_name': rel[3],
                    'start_date': rel[4],
                    'end_date': rel[5],
                    'status': rel[6]
                }
                for rel in relationship_history
            ]
        }
        
        return render(request, 'admin_sponsor_details.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading sponsor details: {str(e)}")
        print(f"Sponsor details error: {e}")
        import traceback
        traceback.print_exc()
        return redirect('admin_sponsor_list')
    finally:
        cursor.close()

@db_login_required
def admin_delete_sponsor(request, sponsor_id):
    """Delete a sponsor account"""
    
    # Check if user is logged in and is an admin
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')
    
    if request.session.get('account_type') != 'admin':
        messages.error(request, "Access denied. Only administrators can perform this action.")
        return redirect('homepage')
    
    if request.method == 'POST':
        cursor = connection.cursor()
        
        try:
            # Get sponsor information
            cursor.execute("""
                SELECT username, first_name, last_name, account_type
                FROM users
                WHERE userID = %s
            """, [sponsor_id])
            
            sponsor_data = cursor.fetchone()
            
            if not sponsor_data:
                messages.error(request, "Sponsor not found.")
                # Get referer URL to preserve filters
                referer = request.META.get('HTTP_REFERER', '')
                if 'useradmin/sponsors' in referer:
                    return redirect(referer)
                return redirect('admin_sponsor_list')
            
            if sponsor_data[3] != 'sponsor':
                messages.error(request, "This user is not a sponsor.")
                referer = request.META.get('HTTP_REFERER', '')
                if 'useradmin/sponsors' in referer:
                    return redirect(referer)
                return redirect('admin_sponsor_list')
            
            username = sponsor_data[0]
            full_name = f"{sponsor_data[1]} {sponsor_data[2]}"
            
            # Check if sponsor has active relationships
            cursor.execute("""
                SELECT COUNT(*)
                FROM sponsor_driver_relationships
                WHERE sponsor_user_id = %s AND relationship_status = 'active'
            """, [sponsor_id])
            
            active_relationships_result = cursor.fetchone()
            active_relationships = active_relationships_result[0] if active_relationships_result else 0
            
            if active_relationships > 0:
                messages.error(request, 
                    f"Cannot delete sponsor {full_name}. They have {active_relationships} active driver relationship(s). "
                    f"Please end all relationships before deleting.")
                referer = request.META.get('HTTP_REFERER', '')
                if 'useradmin/sponsors' in referer:
                    return redirect(referer)
                return redirect('admin_sponsor_list')
            
            # End any non-active relationships
            cursor.execute("""
                UPDATE sponsor_driver_relationships
                SET relationship_status = 'ended',
                    relationship_end_date = NOW(),
                    updated_at = NOW()
                WHERE sponsor_user_id = %s 
                AND relationship_status != 'ended'
            """, [sponsor_id])
            
            # Update applications to show sponsor deleted
            cursor.execute("""
                UPDATE driver_applications
                SET admin_notes = CONCAT(COALESCE(admin_notes, ''), '\n[Sponsor account deleted by admin]'),
                    updated_at = NOW()
                WHERE sponsor_user_id = %s
            """, [sponsor_id])
            
            # Delete the sponsor account
            cursor.execute("""
                DELETE FROM users
                WHERE userID = %s
            """, [sponsor_id])
            
            messages.success(request, f"Sponsor {full_name} (@{username}) has been deleted successfully.")
            
            # Get referer URL to preserve filters
            referer = request.META.get('HTTP_REFERER', '')
            if 'useradmin/sponsors' in referer:
                return redirect(referer)
            
        except Exception as e:
            messages.error(request, f"Error deleting sponsor: {str(e)}")
            print(f"Delete sponsor error: {e}")
        finally:
            cursor.close()
    
    return redirect('admin_sponsor_list')


@db_login_required
def admin_sponsor_list(request):
    """Admin page to view and manage all sponsors with bulk operations"""
    
    # Check if user is logged in and is an admin
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to access this page.")
        return redirect('login_page')
    
    if request.session.get('account_type') != 'admin':
        messages.error(request, "Access denied. Only administrators can view this page.")
        return redirect('homepage')
    
    cursor = connection.cursor()
    
    # Get filter parameters from GET request
    organization_filter = request.GET.get('organization', '')
    status_filter = request.GET.get('status', '')
    
    # Handle bulk actions
    if request.method == 'POST':
        action = request.POST.get('bulk_action')
        selected_sponsors = request.POST.getlist('selected_sponsors')
        organization_bulk = request.POST.get('organization_filter', '').strip()
        
        if action and (selected_sponsors or organization_bulk):
            try:
                if action == 'delete_selected':
                    # Delete selected sponsors
                    if selected_sponsors:
                        deleted_count = 0
                        skipped_count = 0
                        
                        for sponsor_id in selected_sponsors:
                            # Check for active relationships
                            cursor.execute("""
                                SELECT COUNT(*) FROM sponsor_driver_relationships
                                WHERE sponsor_user_id = %s AND relationship_status = 'active'
                            """, [sponsor_id])
                            result = cursor.fetchone()
                            active_rels = result[0] if result else 0
                            
                            if active_rels > 0:
                                skipped_count += 1
                                continue
                            
                            # End non-active relationships
                            cursor.execute("""
                                UPDATE sponsor_driver_relationships
                                SET relationship_status = 'ended',
                                    relationship_end_date = NOW(),
                                    updated_at = NOW()
                                WHERE sponsor_user_id = %s AND relationship_status != 'ended'
                            """, [sponsor_id])
                            
                            # Update applications
                            cursor.execute("""
                                UPDATE driver_applications
                                SET admin_notes = CONCAT(COALESCE(admin_notes, ''), '\n[Sponsor account deleted by admin]'),
                                    updated_at = NOW()
                                WHERE sponsor_user_id = %s
                            """, [sponsor_id])
                            
                            # Delete sponsor
                            cursor.execute("DELETE FROM users WHERE userID = %s", [sponsor_id])
                            deleted_count += 1
                        
                        if deleted_count > 0:
                            messages.success(request, f"Successfully deleted {deleted_count} sponsor(s).")
                        if skipped_count > 0:
                            messages.warning(request, f"Skipped {skipped_count} sponsor(s) with active relationships.")
                
                elif action == 'delete_by_organization':
                    # Delete all sponsors from specific organization
                    if organization_bulk:
                        # Get sponsors from organization
                        cursor.execute("""
                            SELECT userID FROM users 
                            WHERE account_type = 'sponsor' AND organization = %s
                        """, [organization_bulk])
                        
                        org_sponsors = cursor.fetchall()
                        deleted_count = 0
                        skipped_count = 0
                        
                        for (sponsor_id,) in org_sponsors:
                            # Check for active relationships
                            cursor.execute("""
                                SELECT COUNT(*) FROM sponsor_driver_relationships
                                WHERE sponsor_user_id = %s AND relationship_status = 'active'
                            """, [sponsor_id])
                            result = cursor.fetchone()
                            active_rels = result[0] if result else 0
                            
                            if active_rels > 0:
                                skipped_count += 1
                                continue
                            
                            # End non-active relationships
                            cursor.execute("""
                                UPDATE sponsor_driver_relationships
                                SET relationship_status = 'ended',
                                    relationship_end_date = NOW(),
                                    updated_at = NOW()
                                WHERE sponsor_user_id = %s AND relationship_status != 'ended'
                            """, [sponsor_id])
                            
                            # Update applications
                            cursor.execute("""
                                UPDATE driver_applications
                                SET admin_notes = CONCAT(COALESCE(admin_notes, ''), '\n[Sponsor account deleted by admin - Organization cleanup]'),
                                    updated_at = NOW()
                                WHERE sponsor_user_id = %s
                            """, [sponsor_id])
                            
                            # Delete sponsor
                            cursor.execute("DELETE FROM users WHERE userID = %s", [sponsor_id])
                            deleted_count += 1
                        
                        if deleted_count > 0:
                            messages.success(request, f"Successfully deleted {deleted_count} sponsor(s) from organization '{organization_bulk}'.")
                        if skipped_count > 0:
                            messages.warning(request, f"Skipped {skipped_count} sponsor(s) with active relationships.")
                
                elif action == 'activate_selected':
                    # Activate selected sponsors
                    if selected_sponsors:
                        placeholders = ','.join(['%s'] * len(selected_sponsors))
                        cursor.execute(f"""
                            UPDATE users SET is_active = 1 
                            WHERE userID IN ({placeholders})
                        """, selected_sponsors)
                        messages.success(request, f"Successfully activated {len(selected_sponsors)} sponsor(s).")
                
                elif action == 'deactivate_selected':
                    # Deactivate selected sponsors
                    if selected_sponsors:
                        placeholders = ','.join(['%s'] * len(selected_sponsors))
                        cursor.execute(f"""
                            UPDATE users SET is_active = 0 
                            WHERE userID IN ({placeholders})
                        """, selected_sponsors)
                        messages.success(request, f"Successfully deactivated {len(selected_sponsors)} sponsor(s).")
                
                elif action == 'activate_by_organization':
                    # Activate all sponsors from organization
                    if organization_bulk:
                        cursor.execute("""
                            UPDATE users SET is_active = 1 
                            WHERE account_type = 'sponsor' AND organization = %s
                        """, [organization_bulk])
                        affected = cursor.rowcount
                        messages.success(request, f"Successfully activated {affected} sponsor(s) from organization '{organization_bulk}'.")
                
                elif action == 'deactivate_by_organization':
                    # Deactivate all sponsors from organization
                    if organization_bulk:
                        cursor.execute("""
                            UPDATE users SET is_active = 0 
                            WHERE account_type = 'sponsor' AND organization = %s
                        """, [organization_bulk])
                        affected = cursor.rowcount
                        messages.success(request, f"Successfully deactivated {affected} sponsor(s) from organization '{organization_bulk}'.")
                
                # Redirect back with filters preserved
                redirect_url = f"{request.path}?"
                if organization_filter:
                    redirect_url += f"organization={organization_filter}&"
                if status_filter:
                    redirect_url += f"status={status_filter}&"
                return redirect(redirect_url.rstrip('&?'))
                
            except Exception as e:
                messages.error(request, f"Error performing bulk action: {str(e)}")
                print(f"Bulk action error: {e}")
                import traceback
                traceback.print_exc()
    
    try:
        # Build query with filters
        query = """
            SELECT 
                u.userID, u.username, u.first_name, u.last_name, u.email,
                u.phone_number, u.address, u.organization, u.is_active, u.created_at,
                (SELECT COUNT(*) 
                 FROM sponsor_driver_relationships sdr 
                 WHERE sdr.sponsor_user_id = u.userID 
                 AND sdr.relationship_status = 'active') as active_drivers,
                (SELECT COUNT(*) 
                 FROM driver_applications da 
                 WHERE da.sponsor_user_id = u.userID 
                 AND da.application_status = 'pending') as pending_applications,
                (SELECT COUNT(*) 
                 FROM driver_applications da 
                 WHERE da.sponsor_user_id = u.userID 
                 AND da.application_status = 'approved') as total_approved
            FROM users u
            WHERE u.account_type = 'sponsor'
        """
        
        params = []
        
        if organization_filter:
            query += " AND u.organization = %s"
            params.append(organization_filter)
        
        if status_filter:
            if status_filter == 'active':
                query += " AND u.is_active = 1"
            elif status_filter == 'inactive':
                query += " AND u.is_active = 0"
        
        query += " ORDER BY u.created_at DESC"
        
        cursor.execute(query, params)
        sponsors_data = cursor.fetchall()
        
        sponsors_list = []
        for sponsor in sponsors_data:
            sponsors_list.append({
                'userID': sponsor[0],
                'username': sponsor[1],
                'first_name': sponsor[2],
                'last_name': sponsor[3],
                'email': sponsor[4],
                'phone_number': sponsor[5],
                'address': sponsor[6],
                'organization': sponsor[7],
                'is_active': sponsor[8],
                'created_at': sponsor[9],
                'active_drivers': sponsor[10],
                'pending_applications': sponsor[11],
                'total_approved': sponsor[12]
            })
        
        # Get list of all organizations
        cursor.execute("""
            SELECT DISTINCT organization 
            FROM users 
            WHERE account_type = 'sponsor' AND organization IS NOT NULL AND organization != ''
            ORDER BY organization
        """)
        organizations = [org[0] for org in cursor.fetchall()]
        
        # Get statistics (for filtered results)
        total_sponsors = len(sponsors_list)
        active_sponsors = len([s for s in sponsors_list if s['is_active']])
        inactive_sponsors = total_sponsors - active_sponsors
        
        context = {
            'sponsors': sponsors_list,
            'organizations': organizations,
            'total_sponsors': total_sponsors,
            'active_sponsors': active_sponsors,
            'inactive_sponsors': inactive_sponsors,
            'current_organization_filter': organization_filter,
            'current_status_filter': status_filter
        }
        
        return render(request, 'admin_sponsor_list.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading sponsors: {str(e)}")
        print(f"Admin sponsor list error: {e}")
        import traceback
        traceback.print_exc()
        return redirect('account_page')
    finally:
        cursor.close()


@db_login_required
def sponsor_adjust_points(request):
    """Allow sponsors to add/remove points for their drivers and store the transactions."""
    if request.method != 'POST':
        messages.error(request, "Invalid request method.")
        return redirect('sponsor_drivers')

    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied.")
        return redirect('homepage')

    sponsor_id = request.session.get('user_id')
    driver_user_id = request.POST.get('driver_user_id')
    try:
        points = int(request.POST.get('points', '0'))
    except ValueError:
        messages.error(request, "Points must be an integer.")
        return redirect('sponsor_drivers')

    message_text = request.POST.get('message', '').strip()

    cursor = connection.cursor()
    try:
        # Ensure driver exists and is sponsored by this sponsor
        cursor.execute("SELECT COUNT(*) FROM sponsor_driver_relationships WHERE sponsor_user_id = %s AND driver_user_id = %s AND relationship_status = 'active'", [sponsor_id, driver_user_id])
        rel_exists = cursor.fetchone()[0]
        if not rel_exists:
            messages.error(request, "Driver not found or not sponsored by you.")
            return redirect('sponsor_drivers')

        # Insert transaction
        cursor.execute("""
            INSERT INTO driver_points_transactions (sponsor_user_id, driver_user_id, points, message, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """, [sponsor_id, driver_user_id, points, message_text])

        # Optionally update any aggregate counters in sponsor_driver_relationships (e.g., total points)
        try:
            cursor.execute("""
                UPDATE sponsor_driver_relationships
                SET total_points = IFNULL(total_points, 0) + %s, updated_at = NOW()
                WHERE sponsor_user_id = %s AND driver_user_id = %s
            """, [points, sponsor_id, driver_user_id])
        except Exception:
            # Table might not have total_points column; ignore silently
            pass

        try:
            connection.commit()
        except Exception:
            pass

        messages.success(request, "Points recorded successfully.")
        return redirect('sponsor_drivers')

    except Exception as e:
        messages.error(request, f"Error recording points: {str(e)}")
        return redirect('sponsor_drivers')
    finally:
        try:
            cursor.close()
        except Exception:
            pass

@db_login_required
def wishlist_page(request):
    """Display the user's wishlist"""
    # Accept either session key name used elsewhere ('user_id' or 'userID')
    user_id = request.session.get('user_id') or request.session.get('userID')
    cursor = connection.cursor()
    
    try:
        # For testing, let's add a sample product
        # Get all product IDs from the user's wishlist
        cursor.execute("""
            SELECT product_id FROM user_wishlist WHERE user_id = %s
        """, [user_id])
        product_ids = [row[0] for row in cursor.fetchall()]
        # Fetch product details from Fake Store API
        wishlist_items = []
        for product_id in product_ids:
            try:
                response = requests.get(f'https://fakestoreapi.com/products/{product_id}')
                if response.status_code == 200:
                    product_data = response.json()
                    wishlist_items.append(product_data)
            except Exception as e:
                # Skip product on error but log to console
                print(f"Error fetching product {product_id}: {str(e)}")
        
        # Optional: add info message when wishlist is empty
        if not wishlist_items:
            messages.info(request, "Your wishlist is empty.")

        return render(request, 'wishlist.html', {'wishlist_items': wishlist_items})
    
    except Exception as e:
        messages.error(request, f"Error fetching wishlist: {str(e)}")
        return redirect('homepage')
    finally:
        cursor.close()
        
@db_login_required
def delete_from_wishlist(request, product_id):
    """Remove a product from the logged-in user's wishlist.

    Only accepts POST requests. Redirects back to the wishlist page after
    attempting removal. Uses `user_wishlist` table which is created elsewhere
    (and created on-demand in other code paths as well).
    """
    # Ensure this is a POST to avoid accidental deletions via GET
    if request.method != 'POST':
        return redirect('wishlist')

    user_id = request.session.get('user_id') or request.session.get('userID') or request.session.get('id')
    if not user_id:
        messages.error(request, "Please log in to modify your wishlist.")
        return redirect('login_page')

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM user_wishlist WHERE user_id = %s AND product_id = %s", [user_id, product_id])
        try:
            connection.commit()
        except Exception:
            # If commit fails (e.g., autocommit enabled), ignore
            pass

        messages.success(request, "Product removed from wishlist.")
    except Exception as e:
        messages.error(request, f"Error removing product from wishlist: {str(e)}")
    finally:
        try:
            cursor.close()
        except Exception:
            pass

    return redirect('wishlist')
        
# --- Helper and Decorator ---
def is_admin(user):
    return user.is_staff or user.is_superuser


def admin_required(view_func):
    return user_passes_test(is_admin, login_url='/login/')(view_func)


# --- Review Admin Accounts ---
@admin_required
def review_admin_status(request):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT userID, first_name, last_name, username, email, is_active 
            FROM users
            WHERE account_type = 'admin'
        """)
        admins = cursor.fetchall()
    finally:
        cursor.close()

    context = {'users': admins, 'account_type': 'Admin'}
    return render(request, 'review_status.html', context)


# --- Review Driver Accounts ---
@admin_required
def review_driver_status(request):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT userID, first_name, last_name, username, email, is_active 
            FROM users
            WHERE account_type = 'driver'
        """)
        drivers = cursor.fetchall()
    finally:
        cursor.close()

    context = {'users': drivers, 'account_type': 'Driver'}
    return render(request, 'review_status.html', context)


# --- Review Sponsor Accounts ---
@admin_required
def review_sponsor_status(request):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT userID, first_name, last_name, username, email, is_active 
            FROM users
            WHERE account_type = 'sponsor'
        """)
        sponsors = cursor.fetchall()
    finally:
        cursor.close()

    context = {'users': sponsors, 'account_type': 'Sponsor'}
    return render(request, 'review_status.html', context)

@login_required
def generate_driver_point_report(request):
    sponsor_id = request.session.get('user_id')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    report_data = []

    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")

            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT d.first_name, d.last_name, p.points, p.date_awarded
                    FROM driver_points p
                    JOIN users d ON p.driver_id = d.userID
                    WHERE p.sponsor_id = %s AND p.date_awarded BETWEEN %s AND %s
                    ORDER BY p.date_awarded DESC
                """, [sponsor_id, start, end])
                report_data = cursor.fetchall()

        except Exception as e:
            print("Error generating report:", e)

    context = {
        'report_data': report_data,
        'start_date': start_date,
        'end_date': end_date,
    }
    return render(request, 'generate_driver_point_report.html', context)


@login_required
def driver_order_history(request):
    user_id = request.user.id  # Get logged-in driver's ID
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT order_id, product_name, order_date, points_used, status
            FROM orders
            WHERE driver_id = %s
            ORDER BY order_date DESC
        """, [user_id])
        orders = cursor.fetchall()

        order_list = [
            {
                'order_id': row[0],
                'product_name': row[1],
                'order_date': row[2],
                'points_used': row[3],
                'status': row[4],
            }
            for row in orders
        ]

        return render(request, 'driver_order_history.html', {'orders': order_list})
    finally:
        cursor.close()

@admin_required
def review_all_accounts(request):
    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT userID, first_name, last_name, username, email, account_type, is_active
            FROM users
        """)
        users = cursor.fetchall()
        user_list = [
            {
                'userID': row[0],
                'first_name': row[1],
                'last_name': row[2],
                'username': row[3],
                'email': row[4],
                'account_type': row[5],
                'is_active': row[6],
            }
            for row in users
        ]
        return render(request, 'review_all_accounts.html', {'users': user_list})
    finally:
        cursor.close()


# Placeholder functions for missing views
@login_required
def sponsor_wallet_history(request, driver_id=None):
    """Placeholder for sponsor wallet history view."""
    from django.http import HttpResponse
    return HttpResponse("Sponsor wallet history feature is not yet implemented.")

@login_required  
def admin_wallet_history(request, driver_id=None):
    """Placeholder for admin wallet history view."""
    from django.http import HttpResponse
    return HttpResponse("Admin wallet history feature is not yet implemented.")

@login_required
def admin_failed_login_log(request):
    """Placeholder for admin failed login log view."""
    from django.http import HttpResponse
    return HttpResponse("Admin failed login log feature is not yet implemented.")

@login_required
def admin_update_admin_status(request, admin_id):
    """Placeholder for admin update admin status view."""
    from django.http import HttpResponse
    return HttpResponse("Admin update admin status feature is not yet implemented.")

@login_required
def review_driver_points(request):
    """Placeholder for review driver points view."""
    from django.http import HttpResponse
    return HttpResponse("Review driver points feature is not yet implemented.")
@db_login_required
def view_cart(request):
    """Display the logged-in driver's shopping cart."""
    # Check login and driver role
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to view your cart.")
        return redirect('login_page')
    if request.session.get('account_type') != 'driver':
        messages.error(request, "Only drivers can access the cart.")
        return redirect('homepage')

    user_id = request.session.get('user_id')
    cursor = connection.cursor()

    try:
        # Create table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_cart (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_product (user_id, product_id),
                INDEX idx_user_id (user_id)
            )
        """)

        # Fetch all cart items
        cursor.execute("""
            SELECT product_id, quantity FROM user_cart WHERE user_id = %s
        """, [user_id])
        rows = cursor.fetchall()

        cart_items = []
        total = 0

        # Fetch live product info from API for each item
        import requests
        for product_id, qty in rows:
            try:
                response = requests.get(f"https://fakestoreapi.com/products/{product_id}", timeout=5)
                if response.status_code == 200:
                    product = response.json()
                    product['quantity'] = qty
                    product['subtotal'] = product['price'] * qty
                    total += product['subtotal']
                    cart_items.append(product)
            except Exception as e:
                print(f"Error fetching product {product_id}: {e}")

        if not cart_items:
            messages.info(request, "Your cart is empty.")

        context = {
            'cart_items': cart_items,
            'total': round(total, 2),
        }
        return render(request, 'cart.html', context)

    except Exception as e:
        messages.error(request, f"Error loading your cart: {str(e)}")
        return redirect('homepage')
    finally:
        try:
            cursor.close()
        except:
            pass

@db_login_required
def add_to_cart(request, product_id):
    """Add a product to the logged-in driver’s cart."""
    if not request.session.get('is_authenticated'):
        messages.error(request, "Please log in to add items to your cart.")
        return redirect('login_page')
    if request.session.get('account_type') != 'driver':
        messages.error(request, "Only drivers can add products to the cart.")
        return redirect('homepage')

    user_id = request.session.get('user_id')
    cursor = connection.cursor()

    try:
        # Make sure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_cart (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_product (user_id, product_id)
            )
        """)

        # Try inserting; if already there, increment quantity
        cursor.execute("""
            INSERT INTO user_cart (user_id, product_id, quantity)
            VALUES (%s, %s, 1)
            ON DUPLICATE KEY UPDATE quantity = quantity + 1
        """, [user_id, product_id])

        messages.success(request, "Product added to your cart!")
        return redirect('view_cart')

    except Exception as e:
        messages.error(request, f"Error adding to cart: {e}")
        return redirect('view_products')
    finally:
              cursor.close()

@db_login_required
def remove_from_cart(request, product_id):
    """Remove a product from the logged-in driver's cart."""
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "Please log in to modify your cart.")
        return redirect('login_page')

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM user_cart WHERE user_id = %s AND product_id = %s", [user_id, product_id])
        try:
            connection.commit()
        except Exception:
            pass
        messages.success(request, "Item removed from your cart.")
    except Exception as e:
        messages.error(request, f"Error removing product: {e}")
    finally:
        try:
            cursor.close()
        except:
            pass

    return redirect('view_cart')

@admin_required
def admin_change_user_type(request):
    """Admin page to change any user's account type"""
    
    cursor = connection.cursor()
    
    # Get filter parameters
    account_type_filter = request.GET.get('account_type', '')
    search_query = request.GET.get('search', '').strip()
    
    # Handle POST request for changing account type
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        new_account_type = request.POST.get('new_account_type')
        
        if user_id and new_account_type in ['admin', 'driver', 'sponsor']:
            try:
                # Get current user info
                cursor.execute("""
                    SELECT username, first_name, last_name, account_type
                    FROM users
                    WHERE userID = %s
                """, [user_id])
                
                user_data = cursor.fetchone()
                
                if user_data:
                    old_account_type = user_data[3]
                    full_name = f"{user_data[1]} {user_data[2]}"
                    username = user_data[0]
                    
                    # Prevent admin from changing their own account type away from admin
                    current_admin_id = request.session.get('user_id')
                    if int(user_id) == current_admin_id and new_account_type != 'admin':
                        messages.error(request, "You cannot change your own account type away from admin.")
                        return redirect('admin_change_user_type')
                    
                    # Update account type
                    cursor.execute("""
                        UPDATE users
                        SET account_type = %s, updated_at = NOW()
                        WHERE userID = %s
                    """, [new_account_type, user_id])
                    
                    # Handle account type specific cleanup/setup
                    if old_account_type != new_account_type:
                        # If changing FROM sponsor, end all active relationships
                        if old_account_type == 'sponsor':
                            cursor.execute("""
                                UPDATE sponsor_driver_relationships
                                SET relationship_status = 'ended',
                                    relationship_end_date = NOW(),
                                    updated_at = NOW()
                                WHERE sponsor_user_id = %s AND relationship_status = 'active'
                            """, [user_id])
                        
                        # If changing FROM driver, end all active relationships
                        if old_account_type == 'driver':
                            cursor.execute("""
                                UPDATE sponsor_driver_relationships
                                SET relationship_status = 'ended',
                                    relationship_end_date = NOW(),
                                    updated_at = NOW()
                                WHERE driver_user_id = %s AND relationship_status = 'active'
                            """, [user_id])
                        
                        # If changing TO driver, create wallet if it doesn't exist
                        if new_account_type == 'driver':
                            cursor.execute("""
                                INSERT IGNORE INTO driver_wallets (driver_id, points_balance, is_active)
                                VALUES (%s, 0, TRUE)
                            """, [user_id])
                    
                    messages.success(request, 
                        f"Successfully changed {full_name} (@{username}) from {old_account_type} to {new_account_type}.")
                else:
                    messages.error(request, "User not found.")
                    
            except Exception as e:
                messages.error(request, f"Error changing account type: {str(e)}")
                print(f"Change account type error: {e}")
        else:
            messages.error(request, "Invalid user ID or account type.")
    
    try:
        # Build query with filters
        query = """
            SELECT userID, username, first_name, last_name, email,
                   phone_number, account_type, is_active, created_at,
                   (SELECT COUNT(*) FROM sponsor_driver_relationships sdr 
                    WHERE (sdr.sponsor_user_id = u.userID OR sdr.driver_user_id = u.userID) 
                    AND sdr.relationship_status = 'active') as active_relationships
            FROM users u
            WHERE 1=1
        """
        
        params = []
        
        if account_type_filter:
            query += " AND u.account_type = %s"
            params.append(account_type_filter)
        
        if search_query:
            query += " AND (u.username LIKE %s OR u.first_name LIKE %s OR u.last_name LIKE %s OR u.email LIKE %s)"
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param, search_param, search_param])
        
        query += " ORDER BY u.created_at DESC LIMIT 100"
        
        cursor.execute(query, params)
        users_data = cursor.fetchall()
        
        users_list = []
        for user in users_data:
            users_list.append({
                'userID': user[0],
                'username': user[1],
                'first_name': user[2],
                'last_name': user[3],
                'email': user[4],
                'phone_number': user[5],
                'account_type': user[6],
                'is_active': user[7],
                'created_at': user[8],
                'active_relationships': user[9]
            })
        
        # Get statistics
        cursor.execute("""
            SELECT 
                account_type,
                COUNT(*) as count
            FROM users
            GROUP BY account_type
        """)
        
        account_stats = cursor.fetchall()
        stats = {}
        for stat in account_stats:
            stats[stat[0]] = stat[1]
        
        context = {
            'users': users_list,
            'account_stats': stats,
            'current_account_type_filter': account_type_filter,
            'current_search': search_query,
            'current_admin_id': request.session.get('user_id')
        }
        
        return render(request, 'admin_change_user_type.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading users: {str(e)}")
        print(f"Admin change user type error: {e}")
        return redirect('account_page')
    finally:
        cursor.close()

@db_login_required
def sponsor_create_user(request):
    """Sponsor page to create new sponsor users for their organization"""
    
    # Verify user is a sponsor
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can create organization users.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    # Handle POST request for creating new sponsor user
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        # Validation
        if not all([username, email, first_name, last_name, password, confirm_password]):
            messages.error(request, "All fields are required.")
            return render(request, 'sponsor_create_user.html')
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'sponsor_create_user.html')
        
        if len(password) < 6:
            messages.error(request, "Password must be at least 6 characters long.")
            return render(request, 'sponsor_create_user.html')
        
        try:
            # Check if username or email already exists
            cursor.execute("""
                SELECT username, email FROM users 
                WHERE username = %s OR email = %s
            """, [username, email])
            
            existing_user = cursor.fetchone()
            if existing_user:
                if existing_user[0] == username:
                    messages.error(request, f"Username '{username}' is already taken.")
                else:
                    messages.error(request, f"Email '{email}' is already registered.")
                return render(request, 'sponsor_create_user.html')
            
            # Get the creating sponsor's organization info
            cursor.execute("""
                SELECT organization, first_name, last_name
                FROM users 
                WHERE userID = %s
            """, [sponsor_id])
            
            sponsor_info = cursor.fetchone()
            sponsor_organization = sponsor_info[0] if sponsor_info else None
            
            # Hash password
            import hashlib
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # Create new sponsor user with SAME organization as creator
            cursor.execute("""
                INSERT INTO users 
                (username, email, password_hash, first_name, last_name, phone_number, 
                 account_type, organization, is_active, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'sponsor', %s, TRUE, NOW(), NOW())
            """, [username, email, hashed_password, first_name, last_name, phone_number, sponsor_organization])
            
            new_user_id = cursor.lastrowid
            
            # Create a dummy driver application for the relationship tracking
            cursor.execute("""
                INSERT INTO driver_applications 
                (driver_user_id, sponsor_user_id, application_status, application_date, 
                  approval_date, driver_license_number, license_state, years_of_experience,
                 motivation_essay, created_at, updated_at)
                VALUES (%s, %s, 'approved', NOW(), NOW(), 'ORG_MEMBER', 'N/A', 0,
                        'Organization member created by sponsor', NOW(), NOW())
            """, [new_user_id, sponsor_id])
            
            application_id = cursor.lastrowid
            
            # Create organization relationship in sponsor_driver_relationships
            cursor.execute("""
                INSERT INTO sponsor_driver_relationships 
                (sponsor_user_id, driver_user_id, application_id, relationship_status, 
                 relationship_start_date, relationship_notes, created_at, updated_at)
                VALUES (%s, %s, %s, 'active', NOW(), 
                        'Organization member relationship', NOW(), NOW())
            """, [sponsor_id, new_user_id, application_id])
            
            messages.success(request, 
                f"Successfully created sponsor account for {first_name} {last_name} (@{username}) in organization: {sponsor_organization or 'Default'}.")
            
            return redirect('sponsor_create_user')
            
        except Exception as e:
            messages.error(request, f"Error creating user: {str(e)}")
            print(f"Sponsor create user error: {e}")
    
    try:
        # Get current sponsor's info and organization
        cursor.execute("""
            SELECT username, first_name, last_name, email, organization
            FROM users
            WHERE userID = %s
        """, [sponsor_id])
        
        sponsor_info = cursor.fetchone()
        current_organization = sponsor_info[4] if sponsor_info else None
        
        # Get organization members (sponsors in the same organization)
        cursor.execute("""
            SELECT u.userID, u.username, u.first_name, u.last_name, u.email,
                   u.phone_number, u.is_active, u.created_at, u.organization,
                   sdr.relationship_start_date,
                   sdr.relationship_status
            FROM users u
            LEFT JOIN sponsor_driver_relationships sdr ON (
                u.userID = sdr.driver_user_id 
                AND sdr.sponsor_user_id = %s 
                AND sdr.relationship_notes = 'Organization member relationship'
            )
            WHERE u.account_type = 'sponsor'
                AND u.organization = %s
                AND u.userID != %s
            ORDER BY u.created_at DESC
        """, [sponsor_id, current_organization, sponsor_id])
        
        organization_members = cursor.fetchall()
        
        members_list = []
        for member in organization_members:
            members_list.append({
                'userID': member[0],
                'username': member[1],
                'first_name': member[2],
                'last_name': member[3],
                'email': member[4],
                'phone_number': member[5],
                'is_active': member[6],
                'created_at': member[7],
                'organization': member[8],
                'joined_organization': member[9] or member[7],  # Use relationship start or created date
                'relationship_status': member[10] or ('active' if member[6] else 'inactive')
            })
        
        context = {
            'organization_members': members_list,
            'total_members': len(members_list),
            'sponsor_username': sponsor_info[0] if sponsor_info else '',
            'sponsor_name': f"{sponsor_info[1]} {sponsor_info[2]}" if sponsor_info else '',
            'sponsor_email': sponsor_info[3] if sponsor_info else '',
            'current_organization': current_organization or 'Default Organization'
        }
        
        return render(request, 'sponsor_create_user.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading organization data: {str(e)}")
        print(f"Sponsor create user page error: {e}")
        return redirect('sponsor_home')
    finally:
        cursor.close()


@db_login_required
def sponsor_deactivate_organization_member(request, member_id):
    """Deactivate an organization member created by this sponsor"""
    
    if request.method != 'POST':
        messages.error(request, "Invalid request method.")
        return redirect('sponsor_create_user')
    
    # Verify user is a sponsor
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can manage organization members.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Verify this sponsor created this member
        cursor.execute("""
            SELECT u.username, u.first_name, u.last_name
            FROM users u
            JOIN sponsor_driver_relationships sdr ON u.userID = sdr.driver_user_id
            WHERE sdr.sponsor_user_id = %s 
                AND sdr.driver_user_id = %s
                AND sdr.relationship_notes = 'Organization member relationship'
                AND sdr.relationship_status = 'active'
        """, [sponsor_id, member_id])
        
        member_info = cursor.fetchone()
        
        if not member_info:
            messages.error(request, "You don't have permission to manage this user.")
            return redirect('sponsor_create_user')
        
        # Deactivate the member
        cursor.execute("""
            UPDATE users
            SET is_active = FALSE, updated_at = NOW()
            WHERE userID = %s
        """, [member_id])
        
        # Update relationship status using correct column names
        cursor.execute("""
            UPDATE sponsor_driver_relationships
            SET relationship_status = 'terminated', 
                relationship_end_date = NOW(),
                updated_at = NOW(),
                terminated_by_user_id = %s,
                termination_reason = 'Deactivated by organization creator'
            WHERE sponsor_user_id = %s AND driver_user_id = %s 
                AND relationship_notes = 'Organization member relationship'
        """, [sponsor_id, sponsor_id, member_id])
        
        full_name = f"{member_info[1]} {member_info[2]}"
        username = member_info[0]
        
        messages.success(request, f"Successfully deactivated {full_name} (@{username}).")
        
    except Exception as e:
        messages.error(request, f"Error deactivating member: {str(e)}")
        print(f"Deactivate member error: {e}")
    finally:
        cursor.close()

    return redirect('sponsor_create_user')
    try:
        cursor.close()
    except:
        pass


# Delete Sponsor Drivers
@db_login_required 
def sponsor_delete_driver(request, driver_id):
    """Remove a driver from the currently logged-in sponsor's organization.

    Deletes the sponsor<->driver relationship (and, optionally, that pair's
    point transactions). It does NOT delete the user's global account.
    """
    # Only sponsors can do this
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can perform this action.")
        return redirect('homepage')

    if request.method != 'POST':
        messages.error(request, "Invalid request method.")
        return redirect('sponsor_drivers')

    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    try:
        # Remove the relationship for this sponsor and driver
        cursor.execute("""
            DELETE FROM sponsor_driver_relationships
            WHERE sponsor_user_id = %s AND driver_user_id = %s
        """, [sponsor_id, driver_id])

        # (Optional) also remove point transactions between this sponsor & driver
        try:
            cursor.execute("""
                DELETE FROM driver_points_transactions
                WHERE sponsor_user_id = %s AND driver_user_id = %s
            """, [sponsor_id, driver_id])
        except Exception:
            # safe to ignore if table doesn't exist yet
            pass

        try:
            connection.commit()
        except Exception:
            pass

        messages.success(request, "Driver removed from your organization.")
    except Exception as e:
        messages.error(request, f"Could not remove driver: {e}")
    finally:
        try:
            cursor.close()
        except Exception:
            pass

    return redirect('sponsor_drivers')


@db_login_required
def sponsor_organization_management(request):
    """View for sponsors to manage other sponsors in their organization."""
    
    # Only sponsors can access this page
    if request.session.get('account_type') != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can view this page.")
        return redirect('homepage')
    
    sponsor_id = request.session.get('user_id')
    cursor = connection.cursor()
    
    try:
        # Get current sponsor's organization
        cursor.execute("""
            SELECT organization, first_name, last_name
            FROM users 
            WHERE userID = %s AND account_type = 'sponsor'
        """, [sponsor_id])
        
        sponsor_info = cursor.fetchone()
        if not sponsor_info or not sponsor_info[0]:
            messages.error(request, "You must be part of an organization to manage members.")
            return redirect('account_page')
        
        current_organization = sponsor_info[0]
        sponsor_name = f"{sponsor_info[1]} {sponsor_info[2]}"
        
        # Handle member removal
        if request.method == 'POST':
            member_id = request.POST.get('member_id')
            action = request.POST.get('action')
            
            if action == 'remove_member' and member_id:
                try:
                    # Don't allow sponsors to remove themselves
                    if int(member_id) == sponsor_id:
                        messages.error(request, "You cannot remove yourself from the organization.")
                    else:
                        # Remove the member by setting their organization to NULL
                        cursor.execute("""
                            UPDATE users 
                            SET organization = NULL 
                            WHERE userID = %s AND account_type = 'sponsor' AND organization = %s
                        """, [member_id, current_organization])
                        
                        if cursor.rowcount > 0:
                            # Get the removed member's name for the message
                            cursor.execute("""
                                SELECT first_name, last_name 
                                FROM users 
                                WHERE userID = %s
                            """, [member_id])
                            removed_member = cursor.fetchone()
                            member_name = f"{removed_member[0]} {removed_member[1]}" if removed_member else "Member"
                            
                            connection.commit()
                            messages.success(request, f"Successfully removed {member_name} from the organization.")
                        else:
                            messages.error(request, "Member not found or could not be removed.")
                            
                except Exception as e:
                    messages.error(request, f"Error removing member: {str(e)}")
                    
                return redirect('sponsor_organization_management')
        
        # Get all sponsors in the same organization
        cursor.execute("""
            SELECT userID, username, first_name, last_name, email, phone_number, is_active, created_at
            FROM users 
            WHERE account_type = 'sponsor' AND organization = %s
            ORDER BY first_name, last_name
        """, [current_organization])
        
        organization_members = cursor.fetchall()
        
        # Format the data
        members_list = []
        for member in organization_members:
            members_list.append({
                'user_id': member[0],
                'username': member[1],
                'first_name': member[2],
                'last_name': member[3],
                'email': member[4],
                'phone_number': member[5],
                'is_active': bool(member[6]),
                'created_at': member[7],
                'is_current_user': member[0] == sponsor_id
            })
        
        context = {
            'organization_members': members_list,
            'current_organization': current_organization,
            'sponsor_name': sponsor_name,
            'total_members': len(members_list)
        }
        
        return render(request, 'sponsor_organization_management.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading organization members: {str(e)}")
        return redirect('account_page')
    finally:
        try:
            cursor.close()
        except:
            pass

#Admin Reset Driver Password ... Testing
@admin_required
def admin_reset_driver_password(request, user_id):
    """
    Admin action: reset a driver's password to a temporary value.

    - Only accepts POST
    - Uses same SHA-256 hashing convention as change_password
    - Puts the temp password in a flash message so the admin can share it
    """
    if request.method != 'POST':
        messages.error(request, "Invalid request.")
        return redirect('admin_driver_dashboard')

    cursor = connection.cursor()
    try:
        # Ensure this is a driver account and exists
        cursor.execute("""
            SELECT userID, username, account_type, email
            FROM users WHERE userID = %s
        """, [user_id])
        row = cursor.fetchone()
        if not row:
            messages.error(request, "Driver not found.")
            return redirect('admin_driver_dashboard')
        if row[2] != 'driver':
            messages.error(request, "Password reset is only allowed for driver accounts.")
            return redirect('admin_driver_dashboard')

        username = row[1]

        # Generate a temp password (12 chars: URL-safe, no punctuation confusion)
        alphabet = string.ascii_letters + string.digits
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(12))

        # Hash exactly like your change_password view (SHA-256 hex)
        temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()

        # Update DB
        cursor.execute("""
            UPDATE users
            SET password_hash = %s, updated_at = NOW()
            WHERE userID = %s
        """, [temp_hash, user_id])

        try:
            connection.commit()
        except Exception:
            pass

        messages.success(
            request,
            f"Password for @{username} has been reset. Temporary password: {temp_password}"
        )
    except Exception as e:
        messages.error(request, f"Error resetting password: {e}")
    finally:
        try:
            cursor.close()
        except Exception:
            pass

    return redirect('admin_driver_dashboard')

# Sponsor Add Driver Notes
@db_login_required
def sponsor_add_driver_note(request, driver_id):
    """
    Sponsors can add private notes about individual drivers.
    In addition to saving in sponsor_driver_notes, we also write a 0-point
    transaction row so the note is visible immediately in the 'Recent Transactions'
    column without changing the sponsor_drivers view.
    """
    # Access control
    acct = (request.session.get('account_type') or '').lower()
    if acct != 'sponsor':
        messages.error(request, "Access denied. Only sponsors can perform this action.")
        return redirect('homepage')

    if request.method != 'POST':
        messages.error(request, "Invalid request.")
        return redirect('sponsor_drivers')

    # Robust sponsor_id retrieval
    sponsor_id = (
        request.session.get('user_id')
        or request.session.get('id')
        or request.session.get('userID')
    )
    if not sponsor_id:
        messages.error(request, "Session error: could not identify sponsor user.")
        return redirect('sponsor_drivers')

    note_text = (request.POST.get('note_text') or '').strip()
    if not note_text:
        messages.error(request, "Please enter a note before saving.")
        return redirect('sponsor_drivers')
    if len(note_text) > 4000:
        messages.error(request, "Note is too long (max 4000 characters).")
        return redirect('sponsor_drivers')

    cursor = connection.cursor()
    try:
        engine = settings.DATABASES['default']['ENGINE']

        # Create notes table if needed (engine-aware)
        if 'sqlite' in engine:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sponsor_driver_notes (
                    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sponsor_user_id INTEGER NOT NULL,
                    driver_user_id INTEGER NOT NULL,
                    note_text TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
        elif 'postgresql' in engine:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sponsor_driver_notes (
                    note_id SERIAL PRIMARY KEY,
                    sponsor_user_id INT NOT NULL,
                    driver_user_id INT NOT NULL,
                    note_text TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
            """)
        else:
            # MySQL / MariaDB
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sponsor_driver_notes (
                    note_id INT AUTO_INCREMENT PRIMARY KEY,
                    sponsor_user_id INT NOT NULL,
                    driver_user_id INT NOT NULL,
                    note_text TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX (sponsor_user_id),
                    INDEX (driver_user_id)
                )
            """)

        # Validate sponsor<->driver relationship
        cursor.execute("""
            SELECT 1
            FROM sponsor_driver_relationships
            WHERE sponsor_user_id = %s AND driver_user_id = %s
            LIMIT 1
        """, [sponsor_id, driver_id])
        if not cursor.fetchone():
            messages.error(request, "You can only add notes for your own drivers.")
            return redirect('sponsor_drivers')

        # 1) Save the note to the notes table
        cursor.execute("""
            INSERT INTO sponsor_driver_notes (sponsor_user_id, driver_user_id, note_text)
            VALUES (%s, %s, %s)
        """, [sponsor_id, driver_id, note_text])

        # 2) ALSO write a zero-point "NOTE" transaction so it shows up under Recent Transactions
        #    Your sponsor_drivers page already queries driver_points_transactions and renders message/created_at.
        #    If your table has additional required columns, adjust this insert accordingly.
        try:
            cursor.execute("""
                INSERT INTO driver_points_transactions (sponsor_user_id, driver_user_id, points, message)
                VALUES (%s, %s, %s, %s)
            """, [sponsor_id, driver_id, 0, f"NOTE: {note_text}"])
        except Exception as tx_e:
            # If schema differs (extra columns), don't block note saving—just log it.
            print("Warning: could not insert 0-point NOTE transaction:", tx_e)
            traceback.print_exc()

        try:
            connection.commit()
        except Exception:
            pass

        messages.success(request, "Note saved successfully.")
    except Exception as e:
        print("sponsor_add_driver_note error:", e)
        traceback.print_exc()
        messages.error(request, "Could not save note due to an internal error.")
    finally:
        try:
            cursor.close()
        except Exception:
            pass

    return redirect('sponsor_drivers')