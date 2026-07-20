from django.urls import path
from .views import ldap_login, login, oidc_login_callback, oidc_login_start, register, logout


app_name = 'userprofile'

urlpatterns = [
    path('', login, name='login'),
    path('login/', login, name='login'),
	path('auth/oidc/start/', oidc_login_start, name='oidc_login_start'),
	path('auth/oidc/callback/', oidc_login_callback, name='oidc_login_callback'),
	path('auth/ldap/', ldap_login, name='ldap_login'),
    path('logout/', logout, name='logout'),
    path('register/', register, name='register'),
]
