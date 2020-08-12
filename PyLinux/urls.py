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
from django.urls import path, include
from linux.views import index, linux, linux_local, search  # url导入views
from RemoteLinux.views import linux_create, linux_detail, linux_list_detail, linux_update, linux_delete, connect_test

import monitor

urlpatterns = [
    path('', index, name='index'),
    path('linux/', linux, name='linux'),
    path('admin/', admin.site.urls),
    path('local/', linux_local, name='linux_local'),
    path('search/', search, name='search'),
    path('create/', linux_create, name='linux_create'),
    path('detail/', linux_detail, name='linux_detail'),
    path('list_detail/<int:id>/', linux_list_detail, name='linux_list_detail'),
    path('linux_update/<int:id>/', linux_update, name='linux_update'),
    path('linux_delete/<int:id>/', linux_delete, name='linux_delete'),
    path('connect_test/', connect_test, name='connect_test'),
    path('monitor/', include('monitor.urls', namespace='monitor')),
]
