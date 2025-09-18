# Example in Django views.py
from django.db import connection

def login_user(request):
    cursor = connection.cursor()
    cursor.execute("""
        SELECT userID, username, email, password_hash, account_type 
        FROM users 
        WHERE username = %s AND is_active = true
    """, [username])
    user_data = cursor.fetchone()