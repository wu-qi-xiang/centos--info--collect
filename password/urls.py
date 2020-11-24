from django.urls import path
from . import views
from .views import password_manage, password_create, password_update, password_delete


app_name = 'password'

urlpatterns = [
    path('', views.password_manage, name='password_manage'),
    path('password_create/', views.password_create, name='password_create'),
    path('password_search/', views.password_search, name='password_search'),
    path('password_update/<int:id>/', views.password_update, name='password_update'),
    path('password_delete/<int:id>/', views.password_delete, name='password_delete'),
]