from django.urls import path
from . import views


app_name = 'monitor'

urlpatterns = [
	path('manage/', views.monitor_home, name='monitor_home'),
	path('prometheus/', views.prometheus_config, name='prometheus_config'),
	path('prometheus/test/', views.prometheus_test, name='prometheus_test'),
	path('query/', views.alert_query, name='alert_query'),
	path('notifications/', views.alert_notifications, name='alert_notifications'),
	path('notifications/test/', views.alert_notifications_test, name='alert_notifications_test'),
	path('', views.monitor_index, name='monitor_index'),
	path('monitor_update/<int:id>/', views.monitor_update, name='monitor_update'),
]
