from django.urls import path

from . import views


app_name = 'aiops'

urlpatterns = [
	path('api/operator-scan/', views.operator_scan, name='api_operator_scan'),
	path('api/k8s-analyzer/<int:cluster_id>/', views.k8s_analyzer, name='api_k8s_analyzer'),
	path('api/investigations/', views.investigations, name='api_investigations'),
	path('api/investigations/<int:investigation_id>/', views.investigations, name='api_investigation_detail'),
	path('api/investigations/<int:investigation_id>/feedback/', views.investigation_feedback, name='api_investigation_feedback'),
	path('api/diagnostic-evidence/', views.diagnostic_evidence, name='api_diagnostic_evidence'),
	path('api/alert-groups/', views.alert_groups, name='api_alert_groups'),
	path('api/alert-quality-governance/', views.alert_quality_governance, name='api_alert_quality_governance'),
	path('api/signal-freshness/', views.signal_freshness, name='api_signal_freshness'),
	path('api/service-impacts/', views.service_impacts, name='api_service_impacts'),
	path('api/service-workbench/<int:service_id>/', views.service_workbench, name='api_service_workbench'),
	path('api/service-reliability/', views.service_reliability, name='api_service_reliability'),
	path('api/runbook-recommendations/', views.runbook_recommendations, name='api_runbook_recommendations'),
	path('api/runbook-recommendations/<int:recommendation_id>/initiate/', views.runbook_recommendation_initiate, name='api_runbook_recommendation_initiate'),
	path('api/runbook-recommendations/<int:recommendation_id>/outcome/', views.runbook_recommendation_outcome, name='api_runbook_recommendation_outcome'),
	path('', views.dashboard, name='dashboard'),
	path('config/', views.save_config, name='config'),
	path('webhook/', views.alertmanager_webhook, name='webhook'),
]
