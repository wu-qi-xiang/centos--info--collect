from functools import wraps

from django.shortcuts import redirect


def session_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.session.get('is_login'):
            return view_func(request, *args, **kwargs)
        return redirect('userprofile:login')

    return wrapper
