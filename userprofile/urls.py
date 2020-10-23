from django.urls import path
from .views import login, register, logout


app_name = 'userprofile'

urlpatterns = [
    path('', login, name='login'),
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    path('register/', register, name='register'),
]