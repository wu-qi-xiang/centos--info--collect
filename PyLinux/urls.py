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
from linux.views import index, linux, search  # url导入views
# from RemoteLinux.views import linux_create, linux_detail, linux_list_detail, linux_update, linux_delete, connect_test
from RemoteLinux import views


import monitor

urlpatterns = [
    path('', include('userprofile.urls', namespace='login')),
    path('index/', index, name='index'),
    path('linux/', linux, name='linux'),
    path('admin/', admin.site.urls),
    path('search/', search, name='search'),
    path('create/', views.linux_create, name='linux_create'),
    path('detail/', views.linux_detail, name='linux_detail'),
    path('connect/<int:id>/', views.linux_connect, name='linux_connect'),
    path('list_detail/<int:id>/', views.linux_list_detail, name='linux_list_detail'),
    path('list_app/<int:id>/', views.linux_list_app, name='linux_list_app'),
    path('linux_update/<int:id>/', views.linux_update, name='linux_update'),
    path('linux_delete/<int:id>/', views.linux_delete, name='linux_delete'),
    path('connect_test/', views.connect_test, name='connect_test'),
    path('linux_copy/', views.linux_copy, name='copy_form'),
    path('userprofile/', include('userprofile.urls', namespace='userprofile')),
    path('monitor/', include('monitor.urls', namespace='monitor')),
    path('password/', include('password.urls', namespace='password')),
]
