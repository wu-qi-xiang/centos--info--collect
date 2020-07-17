import inspect

def is_instance_method(method):
	number_of_args = len(inspect.getargspec(method)[0])
	if number_of_args > 2:
		raise ValueError('Functions may only take one (static method) or two (instance method) arguments.')
	return number_of_args == 2

class normalizer(object):
	"""
		The normalizer decorator is a method decorator that specifies
		a key of the expected param that it should normalize. Normalization
		consists of any data transformation that should always occur prior
		to custom validation and use inside of a command handler
	"""

	def __init__(self, key, order=0, *args, **kwargs):
		self.key = key
		self.order = order

	def __call__(self, func):
		func.normalizer = True
		func.key = self.key
		func.order = self.order
		func.is_instance = is_instance_method(func)
		return func