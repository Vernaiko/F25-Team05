# Failed Login Attempts - Security Monitoring System

## Overview
This system tracks and logs all failed login attempts across the Safe Driver Program application, providing administrators with comprehensive security monitoring and threat detection capabilities.

## Features Implemented

### 1. **Database Table** (`failed_login_attempts`)
Stores all failed login attempt data:
- `attempt_id` - Unique identifier
- `username` - Username that was attempted
- `attempted_at` - Timestamp of the attempt
- `ip_address` - IP address of the attacker
- `user_agent` - Browser/device information
- `failure_reason` - Why the login failed
- `account_type` - Type of account being targeted

### 2. **Automatic Logging**
Every failed login attempt is automatically logged with:
- Username attempted
- IP address of the attempt
- User agent (browser/device info)
- Timestamp
- Failure reason
- Account type (if username exists in system)

### 3. **Admin Security Dashboard**
Comprehensive security monitoring page at `/useradmin/failed-login-log/`

**Features:**
- View all failed login attempts
- Filter by username, account type, and time range
- Statistics dashboard showing:
  - Total failed attempts
  - Unique usernames targeted
  - Unique IP addresses
  - Days with failed attempts
  - Account type breakdown

**Top Offenders Section:**
- Shows usernames with most failed attempts
- Displays attempt count and unique IPs
- Quick filter to view all attempts for specific user

**IP Address Analysis:**
- Identifies IP addresses with multiple failed attempts
- Shows unique usernames tried from each IP
- Helps identify potential brute force attacks

**Detailed Log Table:**
- All failed attempts with complete metadata
- Sortable and filterable
- Shows up to 500 most recent records

### 4. **Filtering System**
Advanced filtering options:
- **Username**: Search for specific usernames
- **Account Type**: Filter by admin, sponsor, driver, or unknown
- **Time Range**: 
  - Last hour
  - Last 24 hours
  - Last 7 days
  - Last 30 days
  - All time

### 5. **Security Insights**
The system helps identify:
- **Brute Force Attacks**: Multiple attempts from same IP
- **Credential Stuffing**: Multiple usernames from same IP
- **Targeted Attacks**: Repeated attempts on specific accounts
- **Suspicious Patterns**: Unusual activity patterns

## Access

### URL Routes
- **Admin Security Log**: `/useradmin/failed-login-log/`
- **Login Page** (where logging occurs): `/login/`

### Permissions
- Only users with `account_type == 'admin'` can access the security log
- Protected by `@admin_required` decorator

## Usage

### For Administrators

1. **Access the Security Log:**
   - Go to your Account page at `/account/`
   - Click "Security Log" button in Administrator Dashboard
   - Or navigate directly to `/useradmin/failed-login-log/`

2. **Monitor Recent Activity:**
   - Default view shows last 24 hours
   - Check "Overall Statistics" for quick overview
   - Review "Top Failed Login Attempts" for concerning patterns

3. **Investigate Specific Users:**
   - Use username filter to see all attempts for a user
   - Check if attempts are from multiple IPs (distributed attack)
   - Review failure reasons

4. **Identify Threats:**
   - Look for IP addresses with many attempts
   - Check for multiple different usernames from same IP
   - Review timing patterns for automated attacks

5. **Take Action:**
   - Consider blocking IPs with excessive attempts
   - Reset passwords for targeted accounts
   - Enable additional security measures if needed

## Database Schema

```sql
CREATE TABLE failed_login_attempts (
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
);
```

## Files Modified/Created

### Created:
1. `Database/DDL/failed_login_attempts.sql` - Database table definition
2. `driver_program/templates/admin_failed_login_log.html` - Admin security dashboard
3. `FAILED_LOGIN_SECURITY.md` - This documentation

### Modified:
1. `driver_program/views.py`:
   - Added `log_failed_login_attempt()` function
   - Modified `login_page()` to call logging function
   - Added `admin_failed_login_log()` view
   
2. `driver_program/urls.py`:
   - Added route: `path('useradmin/failed-login-log/', views.admin_failed_login_log, name='admin_failed_login_log')`

3. `driver_program/templates/account_page.html`:
   - Added "Security Log" button to Admin Dashboard

## Implementation Details

### How Logging Works

1. User attempts to login at `/login/`
2. `DatabaseUser.authenticate()` is called
3. If authentication fails:
   - `log_failed_login_attempt()` is called
   - Function extracts:
     - IP address from request headers
     - User agent from request META
     - Looks up account type from database
   - Creates table if it doesn't exist
   - Inserts failed attempt record
4. Error message shown to user
5. User sees generic "Invalid username or password" message

### Security Considerations

**What is Logged:**
- ✅ Username attempted (for security monitoring)
- ✅ IP address (to identify attackers)
- ✅ Timestamp (to detect patterns)
- ✅ User agent (to identify bots)
- ✅ Account type (if username exists)

**What is NOT Logged:**
- ❌ Passwords (never logged - security best practice)
- ❌ Session data
- ❌ Personal information beyond username

**Privacy Notes:**
- Failed login data is security-critical
- Should be retained according to security policy
- Access restricted to administrators only
- Consider data retention policies (e.g., purge after 90 days)

## Performance Considerations

### Optimizations:
1. **Indexes** on frequently queried columns:
   - `username` - for filtering by user
   - `attempted_at` - for time-based queries
   - `ip_address` - for IP analysis

2. **Limits**:
   - Main log shows max 500 most recent records
   - Top offenders limited to 10 entries
   - IP stats limited to 10 entries

3. **Query Efficiency**:
   - Uses parameterized queries (SQL injection protection)
   - Aggregation done at database level
   - Minimal data transferred to application

## Maintenance

### Recommended Actions:

1. **Regular Monitoring:**
   - Check daily for unusual patterns
   - Review top offenders weekly
   - Investigate spikes in failed attempts

2. **Data Retention:**
   - Consider purging old records (e.g., >90 days)
   - Archive historical data if needed
   - Example purge query:
   ```sql
   DELETE FROM failed_login_attempts 
   WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
   ```

3. **Performance:**
   - Monitor table size
   - Add additional indexes if queries slow down
   - Consider partitioning for very large datasets

4. **Security Response:**
   - Block IPs with excessive attempts
   - Implement rate limiting if needed
   - Enable CAPTCHA for repeated failures
   - Consider two-factor authentication

## Future Enhancements

### Potential Additions:
1. **Email Alerts**: Notify admins of suspicious activity
2. **Automatic IP Blocking**: Block IPs after X failed attempts
3. **Geographic Analysis**: Map IP addresses to locations
4. **Export Functionality**: Download logs as CSV/PDF
5. **Real-time Dashboard**: Live updates with WebSockets
6. **Account Lockout**: Temporarily lock accounts after failures
7. **CAPTCHA Integration**: Add after X failed attempts
8. **Detailed Analytics**: Graphs and charts of patterns
9. **Integration with SIEM**: Send logs to security systems
10. **Successful Login Tracking**: Compare with failed attempts

## Troubleshooting

### Common Issues:

**Table doesn't exist:**
- Solution: The table is created automatically on first failed login
- Or manually run: `Database/DDL/failed_login_attempts.sql`

**No data showing:**
- Check that failed login attempts have occurred
- Verify time range filter isn't too restrictive
- Ensure database connection is working

**Permission errors:**
- Verify user has `account_type = 'admin'`
- Check session is properly authenticated
- Review `@admin_required` decorator

**Performance slow:**
- Check database indexes exist
- Reduce time range or add more specific filters
- Consider archiving old records

## Security Best Practices

1. ✅ **Never log passwords** - This implementation follows this rule
2. ✅ **Generic error messages** - Users see same message for any failure
3. ✅ **Rate limiting** - Consider adding after reviewing logs
4. ✅ **IP blocking** - Use logs to identify IPs to block
5. ✅ **Regular monitoring** - Review logs frequently
6. ✅ **Secure access** - Admin-only access to logs
7. ✅ **Data retention** - Plan for log rotation/archival

## Support

For issues or questions:
1. Check Django server logs for errors
2. Verify database connection
3. Confirm admin permissions
4. Review implementation in `views.py`
5. Check table exists: `SHOW TABLES LIKE 'failed_login_attempts';`

## Conclusion

This failed login tracking system provides comprehensive security monitoring for the Safe Driver Program application. It helps administrators:
- Detect security threats early
- Identify attack patterns
- Protect user accounts
- Maintain system security
- Comply with security audit requirements

The system is production-ready and follows security best practices for logging and monitoring authentication failures.
