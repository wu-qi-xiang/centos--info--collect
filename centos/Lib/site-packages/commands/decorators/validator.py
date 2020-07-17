import inspect

def is_instance_method(method):
	number_of_args = len(inspect.getargspec(method)[0])
	if number_of_args > 2:
		raise ValueError('Functions may only take one (static method) or two (instance method) arguments.')
	return number_of_args == 2

class validator(object):
	"""
		The validator decorator is a method decorator that specifies
		a key and an error message indicating which data parameter
		the method validates and what the error message should be
		if the validation fails.
	"""

	def __init__(self, key, error, order=0, *args, **kwargs):
		self.key = key
		self.error = error
		self.order = order

	def __call__(self, func):
		func.validator = True
		func.key = self.key
		func.error = self.error
		func.order = self.order
		func.is_instance = is_instance_method(func)
		return func