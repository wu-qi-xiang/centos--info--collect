# This module defines a plugin decorator that can be used on a base class in order
# to automatically register classes that inherit from it across django apps within your project.
from django.utils.module_loading import autodiscover_modules

# creating a decorator that effectively sets the above class as the meta class and passes along the key and module
def Plugin(key, module):

	class Plug(type):

		# here because we need to allow kwargs but not pass them to the type constructor
		def __new__(cls, name, bases, namespace, **kwargs):
			return super().__new__(cls, name, bases, namespace)

		# overriding the init method of the meta class
		def __init__(cls, what, bases, namespace, **kwargs):
			super().__init__(what, bases, namespace)

			# check if the registry exists yet. if not, we must be defining the base class.
			if not hasattr(cls, 'registry'):

				# we want to create a dict on the base class for the plugins to live in.
				cls._registry = {}

				# during the first definition the registry must not have been populated yet.
				cls._registry_populated = False

				# we want to store the key by which to hash the plugins as they are registered
				cls._registry_field_key = kwargs['key']

				# gets the name of the module to look for in each of the apps
				cls._modules_to_register = kwargs['module']

				# defining a property function that will register all of our plugins in the
				# various project apps the first time the registry field is accessed.
				def get_registry(accessor):
					if not cls._registry_populated:
						autodiscover_modules(cls._modules_to_register)
						cls._registry_populated = True
					return cls._registry

				# setting the registry as an accessible property
				cls.registry = property(get_registry)
			else:

				# This must be a plugin implementation, which should be registered.
				# Simply appending it to the list is all that's needed to keep
				# track of it later.
				cls._registry[getattr(cls, cls._registry_field_key)] = cls

	return lambda cls: Plug(cls.__name__, cls.__bases__, dict(cls.__dict__), key=key, module=module)