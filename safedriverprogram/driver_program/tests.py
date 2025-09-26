from django.db import connection, connections
from django.conf import settings
import unittest
import hashlib
import time
from datetime import date, datetime

#to run these tests: execute in terminal:
# # Run all test methods in the class
# python manage.py test driver_program.tests.Team05DatabaseInsertTestCase
# note you can also run individual test methods by appending the method name after the class name
# it will ask you if you want to clean up the test data after running in the database.
class Team05DatabaseInsertTestCase(unittest.TestCase):
        """Test cases for inserting data into Team05_DB schema ONLY"""
        
        @classmethod
        def setUpClass(cls):
                """Force connection to actual Team05_DB"""
                super().setUpClass()
                
                # Override the database connection to use actual Team05_DB
                db_settings = connections.databases['default']
                db_settings['NAME'] = 'Team05_DB'
                
                # Close any existing connections to force reconnection
                connections.close_all()
                
        def setUp(self):
                """Set up test environment"""
                # Ensure we're connected to the right database
                self.cursor = connection.cursor()
                
                # Verify we're connected to the actual database
                self.cursor.execute("SELECT DATABASE() as current_db")
                current_db = self.cursor.fetchone()[0]
                
                if current_db != 'Team05_DB':
                        # Force connection to actual database
                        connection.close()
                        connection.settings_dict['NAME'] = 'Team05_DB'
                        self.cursor = connection.cursor()
                        
                        # Re-verify connection
                        self.cursor.execute("SELECT DATABASE() as current_db")
                        current_db = self.cursor.fetchone()[0]
                        
                # Store test user IDs for cleanup
                self.test_user_ids = []
                print(f"\n*** Connected to database: {current_db} ***")
                
        def tearDown(self):
                """Clean up test data only if user confirms"""
                if not self.test_user_ids:
                        self.cursor.close()
                        return
                        
                print(f"\nTest completed. Created {len(self.test_user_ids)} test users with IDs: {self.test_user_ids}")
                
                # Ask user if they want to clean up
                cleanup_response = input("Do you want to clean up the test data now? (yes/no): ").lower()
                
                if cleanup_response == 'yes':
                        # Clean up test users
                        for user_id in self.test_user_ids:
                                try:
                                        self.cursor.execute("DELETE FROM users WHERE userID = %s", [user_id])
                                        print(f"Cleaned up test user ID: {user_id}")
                                except Exception as e:
                                        print(f"Cleanup error for user {user_id}: {e}")
                        
                        # Clean up any remaining test data
                        try:
                                self.cursor.execute("DELETE FROM users WHERE username LIKE 'djangotest_%'")
                                deleted_count = self.cursor.rowcount
                                if deleted_count > 0:
                                        print(f"Cleaned up {deleted_count} additional test users")
                        except Exception as e:
                                print(f"Bulk cleanup error: {e}")
                        
                        print("✓ Test data cleanup completed")
                else:
                        print("Test data preserved in database for manual inspection")
                        print(f"To clean up later, delete users with IDs: {self.test_user_ids}")
                        
                self.cursor.close()

        def test_database_connection_and_info(self):
                """Test database connection and retrieve basic info"""
                print("\n=== Testing Database Connection and Info ===")
                
                try:
                        # Test basic connection
                        self.cursor.execute("SELECT 1 as connection_test")
                        connection_result = self.cursor.fetchone()
                        self.assertEqual(connection_result[0], 1, "Basic connection should work")
                        
                        # Test database version
                        self.cursor.execute("SELECT VERSION() as version")
                        version_result = self.cursor.fetchone()
                        self.assertIsNotNone(version_result[0], "Should get database version")
                        
                        # STRICT CHECK: Must be connected to Team05_DB ONLY
                        self.cursor.execute("SELECT DATABASE() as current_db")
                        db_result = self.cursor.fetchone()
                        current_db = db_result[0]
                        
                        # FAIL if not connected to actual Team05_DB
                        self.assertEqual(current_db, 'Team05_DB', 
                                                   f"MUST be connected to Team05_DB, got: {current_db}")
                        
                        # Test table existence
                        self.cursor.execute("""
                                SELECT COUNT(*) as table_count
                                FROM information_schema.tables 
                                WHERE table_schema = 'Team05_DB' AND table_name = 'users'
                        """)
                        table_result = self.cursor.fetchone()
                        
                        self.assertGreaterEqual(table_result[0], 1, "Users table must exist in Team05_DB")
                        
                        print(f"✓ Database connection verified - Connected to: {current_db}")
                        
                except Exception as e:
                        self.fail(f"Database connection test failed: {e}")

        def test_insert_user_with_hashed_password(self):
                """Test inserting a user with SHA2-256 hashed password"""
                print("\n=== Testing User Insert with Hashed Password ===")
                
                # Verify database connection first
                self.cursor.execute("SELECT DATABASE() as current_db")
                current_db = self.cursor.fetchone()[0]
                self.assertEqual(current_db, 'Team05_DB', f"Must be Team05_DB, got: {current_db}")
                
                # Test user data with shorter username
                timestamp_suffix = str(int(time.time()))[-6:]  # Last 6 digits only
                username = f"test_user_{timestamp_suffix}"  # Max ~16 characters
                email = f"test{timestamp_suffix}@test.com"
                password = "test_password_123"
                first_name = "Test"
                last_name = "User"
                phone = "1234567890"
                address = "123 Test St, Test City, SC 29634"
                account_type = "driver"
                dob = "1990-01-01"
                
                print(f"Creating user: {username} (length: {len(username)})")
                
                try:
                        # Insert user with hashed password
                        insert_query = """
                        INSERT INTO users (username, email, password_hash, first_name, last_name, 
                                        phone_number, address, account_type, DOB, is_active, is_email_verified)
                        VALUES (%s, %s, SHA2(%s, 256), %s, %s, %s, %s, %s, %s, true, false)
                        """
                        
                        self.cursor.execute(insert_query, [
                        username, email, password, first_name, last_name,
                        phone, address, account_type, dob
                        ])
                        
                        # Rest of the test remains the same...
                        user_id = self.cursor.lastrowid
                        self.test_user_ids.append(user_id)
                        
                        # Verify insertion by selecting the user
                        select_query = """
                        SELECT userID, username, email, first_name, last_name, phone_number, 
                        address, account_type, DOB, is_active, is_email_verified
                        FROM users WHERE userID = %s
                        """
                        
                        self.cursor.execute(select_query, [user_id])
                        result = self.cursor.fetchone()
                        
                        # Assertions
                        self.assertIsNotNone(result, "User should be inserted successfully")
                        self.assertEqual(result[1], username, "Username should match")
                        self.assertEqual(result[2], email, "Email should match")
                        self.assertEqual(result[3], first_name, "First name should match")
                        self.assertEqual(result[4], last_name, "Last name should match")
                        self.assertEqual(result[5], phone, "Phone should match")
                        self.assertEqual(result[6], address, "Address should match")
                        self.assertEqual(result[7], account_type, "Account type should match")
                        self.assertEqual(str(result[8]), dob, "DOB should match")
                        self.assertTrue(result[9], "User should be active")
                        self.assertFalse(result[10], "Email should not be verified initially")
                        
                        print(f"✓ User inserted successfully in Team05_DB with ID: {user_id}")
                        
                except Exception as e:
                        self.fail(f"User insertion failed: {e}")

        def test_verify_password_hash(self):
                """Test that password is properly hashed and can be verified"""
                print("\n=== Testing Password Hash Verification ===")
                
                # Verify database connection
                self.cursor.execute("SELECT DATABASE() as current_db")
                current_db = self.cursor.fetchone()[0]
                self.assertEqual(current_db, 'Team05_DB', f"Must be Team05_DB, got: {current_db}")
                
                # Use shorter usernames
                timestamp_suffix = str(int(time.time()))[-6:]
                username = f"hash_{timestamp_suffix}"  # Max ~12 characters
                email = f"hash{timestamp_suffix}@test.com"
                password = "secure_password_456"
                
                print(f"Creating user: {username} (length: {len(username)})")
                
                try:
                        # Rest of the test remains the same...
                        insert_query = """
                        INSERT INTO users (username, email, password_hash, first_name, last_name, account_type)
                        VALUES (%s, %s, SHA2(%s, 256), 'Hash', 'Test', 'driver')
                        """
                        
                        self.cursor.execute(insert_query, [username, email, password])
                        user_id = self.cursor.lastrowid
                        self.test_user_ids.append(user_id)
                        
                        # Verify password by attempting login query
                        login_query = """
                        SELECT userID, username, email, first_name, last_name
                        FROM users 
                        WHERE username = %s AND password_hash = SHA2(%s, 256) AND is_active = true
                        """
                        
                        self.cursor.execute(login_query, [username, password])
                        login_result = self.cursor.fetchone()
                        
                        self.assertIsNotNone(login_result, "Password verification should succeed")
                        self.assertEqual(login_result[1], username, "Login should return correct user")
                        
                        # Test with wrong password
                        self.cursor.execute(login_query, [username, "wrong_password"])
                        wrong_password_result = self.cursor.fetchone()
                        
                        self.assertIsNone(wrong_password_result, "Wrong password should fail verification")
                        
                        print(f"✓ Password hash verification successful in Team05_DB for user ID: {user_id}")
                        
                except Exception as e:
                        self.fail(f"Password hash verification failed: {e}")

        def test_database_write_operations(self):
                """Test comprehensive write operations on Team05_DB"""
                print("\n=== Testing Database Write Operations ===")
                
                # Verify database connection
                self.cursor.execute("SELECT DATABASE() as current_db")
                current_db = self.cursor.fetchone()[0]
                self.assertEqual(current_db, 'Team05_DB', f"Must be Team05_DB, got: {current_db}")
                
                try:
                        # Test multiple user insertions with shorter names
                        users_to_create = [
                                ('drv', 'driver1@test.com', 'driver'),
                                ('spo', 'sponsor1@test.com', 'sponsor'),
                                ('adm', 'admin1@test.com', 'admin')
                        ]
                        
                        created_users = []
                        
                        for username, email, account_type in users_to_create:
                                # Create shorter unique usernames to fit database constraints
                                # Use last 6 digits of timestamp to keep it short
                                timestamp_suffix = str(int(time.time()))[-6:]  # Last 6 digits
                                unique_username = f"test_{username}_{timestamp_suffix}"  # Max ~17 characters
                                unique_email = f"{timestamp_suffix}_{email}"
                                
                                # Ensure username doesn't exceed database limit (assuming 30 chars max)
                                if len(unique_username) > 30:
                                        unique_username = unique_username[:30]
                                
                                print(f"Creating user: {unique_username} (length: {len(unique_username)})")
                                
                                insert_query = """
                                INSERT INTO users (username, email, password_hash, first_name, last_name, 
                                                account_type, is_active)
                                VALUES (%s, %s, SHA2(%s, 256), %s, 'TestUser', %s, true)
                                """
                                
                                self.cursor.execute(insert_query, [
                                        unique_username, unique_email, 'test_password', 
                                        account_type.title(), account_type
                                ])
                                
                                user_id = self.cursor.lastrowid
                                self.test_user_ids.append(user_id)
                                created_users.append((user_id, unique_username, account_type))
                        
                        # Verify all users were created
                        self.assertEqual(len(created_users), 3, "Should create 3 test users")
                        
                        # Test update operations
                        for user_id, username, account_type in created_users:
                                update_query = """
                                UPDATE users 
                                SET last_name = %s, updated_at = CURRENT_TIMESTAMP 
                                WHERE userID = %s
                                """
                        
                                self.cursor.execute(update_query, [f"Updated_{account_type}", user_id])
                                self.assertEqual(self.cursor.rowcount, 1, "Should update one row")
                        
                        print(f"✓ Successfully performed write operations on Team05_DB")
                        print(f"  - Created {len(created_users)} users")
                        print(f"  - Updated {len(created_users)} user records")
                        
                except Exception as e:
                        self.fail(f"Database write operations failed: {e}")

# Function to manually clean up test data
def cleanup_test_data():
        """Manual cleanup function for test data"""
        print("Manual cleanup of test data...")
        
        cursor = connection.cursor()
        
        try:
                # Show test users that exist
                cursor.execute("SELECT userID, username, email FROM users WHERE username LIKE 'test_%'")
                test_users = cursor.fetchall()
                
                if not test_users:
                        print("No test users found to clean up.")
                        return
                
                print(f"Found {len(test_users)} test users:")
                for user_id, username, email in test_users:
                        print(f"  ID: {user_id}, Username: {username}, Email: {email}")
                
                response = input(f"\nDelete all {len(test_users)} test users? (yes/no): ")
                if response.lower() == 'yes':
                        cursor.execute("DELETE FROM users WHERE username LIKE 'test_%'")
                        deleted_count = cursor.rowcount
                        print(f"✓ Deleted {deleted_count} test users")
                else:
                        print("Cleanup cancelled.")
        finally:
                cursor.close()

if __name__ == '__main__':
        run_production_database_tests()
