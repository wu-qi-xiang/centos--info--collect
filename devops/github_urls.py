from django.urls import path

from . import github_integration


app_name = 'github'

urlpatterns = [
    path('workflow-run/', github_integration.github_workflow_run, name='workflow_run'),
]
