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
