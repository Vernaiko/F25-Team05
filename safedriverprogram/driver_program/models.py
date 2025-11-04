from django.contrib.auth.models import User
from django.db import models

# New model for multiple delivery addresses
class DeliveryAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='delivery_addresses')
    address = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.address[:30]}"  # first 30 chars of address


# New SponsorProfile model
class SponsorProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='sponsor_profile')
    organization_name = models.CharField(max_length=255)
    contact_email = models.EmailField(blank=True, null=True)

    def __str__(self):
        return self.organization_name


# Single Profile model
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    delivery_address = models.TextField(blank=True, null=True)
    sponsor = models.ForeignKey(SponsorProfile, on_delete=models.SET_NULL, null=True, blank=True)
    # Store avatar filename or path (optional)
    avatar = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.user.username


# Driver Wallet Models (these correspond to your SQL tables)
class DriverWallet(models.Model):
    wallet_id = models.AutoField(primary_key=True)
    driver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='driver_wallet')
    points_balance = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_transaction_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'driver_wallets'
        unique_together = ['driver']

    def __str__(self):
        return f"Wallet for {self.driver.username} - {self.points_balance} points"


class WalletTransactionHistory(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ('adjustment', 'Adjustment'),
        ('refund', 'Refund'),
        ('purchase', 'Purchase'),
        ('reward', 'Reward'),
        ('penalty', 'Penalty'),
    ]

    REFERENCE_TYPE_CHOICES = [
        ('order', 'Order'),
        ('sponsor_reward', 'Sponsor Reward'),
        ('admin_adjustment', 'Admin Adjustment'),
        ('point_conversion', 'Point Conversion'),
        ('refund', 'Refund'),
        ('penalty', 'Penalty'),
        ('bonus', 'Bonus'),
        ('other', 'Other'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    transaction_id = models.AutoField(primary_key=True)
    wallet = models.ForeignKey(DriverWallet, on_delete=models.CASCADE, related_name='transactions')
    driver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='wallet_transactions')
    
    # Transaction details
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    points_amount = models.IntegerField()
    points_before = models.IntegerField()
    points_after = models.IntegerField()
    
    # Transaction metadata
    description = models.CharField(max_length=500, blank=True, null=True)
    reference_id = models.CharField(max_length=100, blank=True, null=True)
    reference_type = models.CharField(max_length=20, choices=REFERENCE_TYPE_CHOICES, blank=True, null=True)
    
    # Sponsor relationship (if applicable)
    sponsor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='sponsored_transactions')
    
    # Admin who performed action (if applicable)
    admin = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='admin_transactions')
    
    # Status and timestamps
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='completed')
    transaction_date = models.DateTimeField(auto_now_add=True)
    processed_by = models.CharField(max_length=100, blank=True, null=True)
    
    # Additional info
    notes = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    class Meta:
        db_table = 'wallet_transaction_history'
        ordering = ['-transaction_date']

    def __str__(self):
        return f"{self.transaction_type} - {self.points_amount} points - {self.driver.username}"


# New Address model for multiple address entries
class Address(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='addresses')
    street = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    zip_code = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.street}, {self.city}, {self.state} {self.zip_code}"

