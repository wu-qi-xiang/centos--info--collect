from django.urls import path
from . import views


app_name = 'monitor'

urlpatterns = [
	path('', views.monitor_index, name='monitor_index'),
	path('monitor_update/<int:id>/', views.monitor_update, name='monitor_update'),
]
