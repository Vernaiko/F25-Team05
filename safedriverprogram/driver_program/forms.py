from django import forms
from .models import Address

class AddressForm(forms.ModelForm):
    class Meta:
        model = Address
        fields = ['street', 'city', 'state', 'zip_code', 'is_default']
        widgets = {
            'street': forms.TextInput(attrs={'class': 'input', 'placeholder': 'Street address'}),
            'city': forms.TextInput(attrs={'class': 'input', 'placeholder': 'City'}),
            'state': forms.TextInput(attrs={'class': 'input', 'placeholder': 'State'}),
            'zip_code': forms.TextInput(attrs={'class': 'input', 'placeholder': 'Postal/ZIP code'}),
        }
        labels = {
            'is_default': 'Use as default delivery address',
        }
