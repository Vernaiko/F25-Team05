"""
Simple product cache fallback for Fake Store API.
Stores the last successful API response and serves it when the API is unavailable.
"""
import json
import os
from datetime import datetime, timedelta
from django.conf import settings

CACHE_FILE = os.path.join(settings.BASE_DIR, 'product_cache.json')
CACHE_DURATION = timedelta(hours=24)  # Refresh cache every 24 hours

def get_cached_products():
    """Load products from cache file if it exists and is recent."""
    if not os.path.exists(CACHE_FILE):
        return None
    
    try:
        with open(CACHE_FILE, 'r') as f:
            cache = json.load(f)
        
        # Check if cache is still valid
        cached_at = datetime.fromisoformat(cache.get('cached_at', ''))
        if datetime.now() - cached_at > CACHE_DURATION:
            return None  # Cache expired
        
        return cache.get('products', [])
    except Exception as e:
        print(f"Error reading product cache: {e}")
        return None

def save_products_to_cache(products):
    """Save products to cache file with timestamp."""
    try:
        cache = {
            'cached_at': datetime.now().isoformat(),
            'products': products
        }
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
        print(f"Saved {len(products)} products to cache")
    except Exception as e:
        print(f"Error saving product cache: {e}")

def get_cached_categories():
    """Extract unique categories from cached products."""
    products = get_cached_products()
    if not products:
        return None
    
    categories = sorted(list({p.get('category') for p in products if p.get('category')}))
    return categories if categories else None
