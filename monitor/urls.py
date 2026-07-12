from django.urls import path
from . import views


app_name = 'monitor'

urlpatterns = [
	path('manage/', views.monitor_home, name='monitor_home'),
	path('prometheus/', views.prometheus_config, name='prometheus_config'),
	path('prometheus/test/', views.prometheus_test, name='prometheus_test'),
	path('prometheus/<int:id>/update/', views.prometheus_update, name='prometheus_update'),
	path('prometheus/<int:id>/delete/', views.prometheus_delete, name='prometheus_delete'),
	path('alertmanager/', views.alertmanager_create, name='alertmanager_create'),
	path('alertmanager/test/', views.alertmanager_test, name='alertmanager_test'),
	path('alertmanager/<int:id>/update/', views.alertmanager_update, name='alertmanager_update'),
	path('alertmanager/<int:id>/delete/', views.alertmanager_delete, name='alertmanager_delete'),
	path('query/execute/', views.metric_query_execute, name='metric_query_execute'),
	path('query/', views.alert_query, name='alert_query'),
	path('notifications/', views.alert_notifications, name='alert_notifications'),
	path('notifications/test/', views.alert_notifications_test, name='alert_notifications_test'),
	path('', views.monitor_index, name='monitor_index'),
	path('monitor_update/<int:id>/', views.monitor_update, name='monitor_update'),
]
