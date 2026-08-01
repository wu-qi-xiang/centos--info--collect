from django.urls import path

from . import views


app_name = 'aiops'

urlpatterns = [
	path('api/diagnostic-evidence/', views.diagnostic_evidence, name='api_diagnostic_evidence'),
	path('api/alert-groups/', views.alert_groups, name='api_alert_groups'),
	path('api/signal-freshness/', views.signal_freshness, name='api_signal_freshness'),
	path('api/service-impacts/', views.service_impacts, name='api_service_impacts'),
	path('api/service-workbench/<int:service_id>/', views.service_workbench, name='api_service_workbench'),
	path('', views.dashboard, name='dashboard'),
	path('config/', views.save_config, name='config'),
	path('webhook/', views.alertmanager_webhook, name='webhook'),
]
