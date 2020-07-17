from django.conf.urls import patterns, url
from .views import *

# Defining routes that apply to the command app.
urlpatterns = patterns('',
   url(r'^$', CommandHandler.as_view(), name='execution'),
   url(r'^available/$', AvailableCommandDefinitions.as_view(), name='available'),
)
