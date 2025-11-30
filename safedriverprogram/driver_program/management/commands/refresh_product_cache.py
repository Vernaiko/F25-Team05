"""
Django management command to refresh the product cache.
Run this on your local machine or a non-AWS server to populate the cache,
then deploy the cache file to EC2.

Usage:
    python manage.py refresh_product_cache
"""
from django.core.management.base import BaseCommand
import requests
from driver_program.product_cache import save_products_to_cache


class Command(BaseCommand):
    help = 'Fetch products from Fake Store API and save to cache'

    def handle(self, *args, **options):
        self.stdout.write('Fetching products from Fake Store API...')
        
        try:
            response = requests.get('https://fakestoreapi.com/products', timeout=10)
            response.raise_for_status()
            products = response.json()
            
            save_products_to_cache(products)
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully cached {len(products)} products')
            )
            
            # Show some stats
            categories = {p.get('category') for p in products if p.get('category')}
            self.stdout.write(f'Categories: {", ".join(sorted(categories))}')
            
        except requests.RequestException as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to fetch products: {str(e)}')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error: {str(e)}')
            )
