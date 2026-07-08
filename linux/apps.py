from django.apps import AppConfig


class LinuxConfig(AppConfig):
    name = 'linux'

    def ready(self):
        import PyLinux.checks  # noqa
