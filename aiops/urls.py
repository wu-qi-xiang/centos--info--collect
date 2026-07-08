from django.urls import path

from . import views


app_name = 'aiops'

urlpatterns = [
	path('', views.dashboard, name='dashboard'),
	path('config/', views.save_config, name='config'),
	path('webhook/', views.alertmanager_webhook, name='webhook'),
]
