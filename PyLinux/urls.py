"""PyLinux URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.http import HttpResponse
from django.urls import path, include
from linux.views import asset_management, index, linux, search  # url导入views
from PyLinux import health
# from RemoteLinux.views import linux_create, linux_detail, linux_list_detail, linux_update, linux_delete, connect_test
from RemoteLinux import views


import monitor

urlpatterns = [
    path('health/live/', health.liveness, name='health_liveness'),
    path('health/ready/', health.readiness, name='health_readiness'),
    path('runtime/status/', health.runtime_status, name='runtime_status'),
    path('', include('userprofile.urls', namespace='login')),
    path('index/', index, name='index'),
    path('assets/', asset_management, name='asset_management'),
    path('linux/', linux, name='linux'),
    path('admin/', admin.site.urls),
    path('search/', search, name='search'),
    path('create/', views.linux_create, name='linux_create'),
    path('import/', views.linux_import, name='linux_import'),
    path('import/template/', views.linux_import_template, name='linux_import_template'),
    path('detail/', views.linux_detail, name='linux_detail'),
    path('connect/<int:id>/', views.linux_connect, name='linux_connect'),
    path('list_detail/<int:id>/', views.linux_list_detail, name='linux_list_detail'),
    path('list_app/<int:id>/', views.linux_list_app, name='linux_list_app'),
    path('linux_update/<int:id>/', views.linux_update, name='linux_update'),
    path('linux_delete/<int:id>/', views.linux_delete, name='linux_delete'),
    path('connect_test/', views.connect_test, name='connect_test'),
    path('api/server/<int:id>/status/', views.server_status, name='server_status'),
    path('linux_copy/', views.linux_copy, name='copy_form'),
    path('userprofile/', include('userprofile.urls', namespace='userprofile')),
    path('monitor/', include('monitor.urls', namespace='monitor')),
    path('password/', include('password.urls', namespace='password')),
    path('devops/', include('devops.urls', namespace='devops')),
    path('integrations/github/', include('devops.github_urls')),
    path('aiops/', include('aiops.urls', namespace='aiops')),
    path('favicon.ico', lambda request: HttpResponse(status=204), name='favicon'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
