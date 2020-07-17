# This module defines a thread local singleton decorator for marking classes as such.

from threading import local
current_thread = local()

def Singleton(clazz):

	class Decorated(clazz):

		# when we initialize, call the initializer on the wrapped class if it exists.
		def __init__(self, *args, **kwargs):
			if hasattr(clazz, '__init__'):
				clazz.__init__(self, *args, **kwargs)

		def __name__(self):
			return clazz.__name__

		def __repr__(self):
			return clazz.__name__

		def __str__(self):
			return clazz.__name__


	class ClassObject(object):

		# the first time we initialize, set instance to nothing.
		def __init__(cls):
			cls.instance = None

		def __repr__(cls):
			return clazz.__name__

		def __str__(cls):
			return clazz.__name__

		# whenever its called, if the instance doesn't exist then initialize a new one.
		def __call__(cls, *args, **kwargs):
			if not cls.instance:
				cls.instance = Decorated(*args, **kwargs)
			return cls.instance

	# keep the singleton definition (and instance on thread local to prevent cross request pollution)
	if not hasattr(current_thread,clazz.__name__):
		setattr(current_thread, clazz.__name__, ClassObject())
	return getattr(current_thread, clazz.__name__)