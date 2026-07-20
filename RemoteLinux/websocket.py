from functools import wraps


def accept_websocket(view_func):
    """Keep legacy WebSSH page requests usable without dwebsocket middleware."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'is_websocket'):
            request.is_websocket = lambda: False
        return view_func(request, *args, **kwargs)
    return wrapper
