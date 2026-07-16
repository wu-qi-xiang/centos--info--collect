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
	path('alertmanager/<int:id>/webhook/', views.alertmanager_webhook, name='alertmanager_webhook'),
	path('alertmanager/<int:id>/update/', views.alertmanager_update, name='alertmanager_update'),
	path('alertmanager/<int:id>/delete/', views.alertmanager_delete, name='alertmanager_delete'),
	path('query/execute/', views.metric_query_execute, name='metric_query_execute'),
	path('query/metadata/', views.metric_query_metadata, name='metric_query_metadata'),
	path('query/targets/', views.metric_query_targets, name='metric_query_targets'),
	path('query/rules/', views.metric_query_rules, name='metric_query_rules'),
	path('query/', views.alert_query, name='alert_query'),
	path('notifications/list/', views.alert_notification_list, name='alert_notification_list'),
	path('notifications/', views.alert_notifications, name='alert_notifications'),
	path('notifications/<int:id>/update/', views.alert_notification_update, name='alert_notification_update'),
	path('notifications/<int:id>/delete/', views.alert_notification_delete, name='alert_notification_delete'),
	path('notifications/test/', views.alert_notifications_test, name='alert_notifications_test'),
	path('', views.monitor_index, name='monitor_index'),
	path('monitor_update/<int:id>/', views.monitor_update, name='monitor_update'),
]
