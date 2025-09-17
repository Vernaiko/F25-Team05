from django.shortcuts import render

# Rendering the home login page:
def homepage(request):
    return render(request, 'homepage.html')
