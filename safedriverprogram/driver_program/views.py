from django.shortcuts import render

# Rendering the home login page:
def homepage(request):
    return render(request, 'homepage.html')

def login_page(request):
    return render(request, 'login.html')

def signup_page(request):
    return render(request, 'signup.html')

def account_page(request):
    return render(request, 'account_page.html')