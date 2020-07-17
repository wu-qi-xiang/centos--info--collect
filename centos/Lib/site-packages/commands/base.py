from .mixins import *
from .types import *
from .decorators import *
import json

def build_param_message(missing_params):
	return "The following parameters were missing: {0}".format(", ".join(missing_params))

def build_param_type_message(invalid_params):
	return "The following parameters were of the wrong type: {0}".format(", ".join(invalid_params))

class Param(object):
	"""
		A param object defines some properties about each parameter that
		may be passed during a command request. The information contained
		herein is used for validation as well as for attribute naming on
		the data objects that get passed around.
	"""

	def __init__(self, name, type, required=True, default=None):
		self.name = name
		self.type = type
		self.default = default
		self.required = required

	@property
	def is_serialized(self):
		return self.type not in [Types.BLOB, Types.FILE]

	def dictify(self):
		definition = {'name': self.name, 'type': self.type.value.representation, 'required': self.required}
		if self.default: definition['default'] = self.default
		return definition


@Plugin(key='command_name', module='commands')
class CommandHandlerBase(AjaxMixin):
	"""
		This CommandHandlerBase class contains the bulk of dealing with the static data
		associated with a CommandHandler. The static fields allow us to:

		1) dispatch to the appropriate CommandHandler,

		2) perform existence and type validation of the data in the request

		3) check that the user is authenticated if it is required for the request

		4) check that the user has appropriate permissions to make a request for the
		   execution of a particular command

		5) provide a basic definition of the command to the front end so that
		   it can perform validation upfront and minimize the number of
		   synchronization points between front end code and backend, since
		   the backend drives the available commands for the front end as well.

		The last thing that this class provides, is simply a #handle method that should
		be overridden in each of the command handlers in order to actually process a request.
	"""

	# a list of params.
	params = []

	# the canonical name for the command
	command_name = ''

	# whether or not the command requires a user to be authenticated
	auth_required = False

	# a list of required user permissions for a command
	permissions = []

	# defining a base init method to maintain the initial request and user as a field
	def __init__(self, request):
		self.request = request
		self.user = self.request.user

	# checks that the user on the request is logged in if 'authenticated' is a necessary permission
	@classmethod
	def validate_auth(cls, request):
		return request.user.is_authenticated() if cls.auth_required else True


	# checks that the user on the request has the necessary permissions for the command
	@classmethod
	def validate_permissions(cls, request):
		return request.user.has_perms(cls.permissions)


	# checks that the necessary parameters were provided with the command data
	@classmethod
	def validate_param_existence(cls, data):
		missing = [param.name for param in cls.params if (param.required) and (param.name not in data)]
		if len(missing) > 0: return False, build_param_message(missing)
		return True, ''


	# returns a list of the validator functions that have been defined in the class
	@classmethod
	def get_validators(cls):
		return sorted([func for func in cls.__dict__.values() if getattr(func, 'validator', False)], key=lambda validator: validator.order)


	# returns a list of the normalizer functions that have been defined in the class
	@classmethod
	def get_normalizers(cls):
		return sorted([func for func in cls.__dict__.values() if getattr(func, 'normalizer', False)], key=lambda normalizer: normalizer.order)


	# gets a simple serializable definition of the command
	@classmethod
	def to_definition(cls):
		return {'name': cls.command_name, 'params': [param.dictify() for param in cls.params]}


	# checks that all of the parameters in the request are of the correct type
	@classmethod
	def validate_param_types(cls, data):
		invalid = []
		cleaned_data = {}
		existing = [param for param in cls.params if param.name in data]
		[cleaned_data.setdefault(param.name, None) for param in cls.params if not param.name in data]

		for param in existing:

			# getting the appropriate set from the request data
			content = data[param.name]

			# if that type is generally serialized, then deserialize it
			if param.is_serialized:
				content = json.loads(content)

			# check if it's valid according to that type
			if not param.type.value.is_valid(content):
				invalid.append(param.name)
			else:
				try:
					cleaned_data[param.name] = param.type.value.cast(content)
				except TypeError:
					invalid.append(param.name)

		if len(invalid) > 0: return False, build_param_type_message(invalid)
		else: return True, cleaned_data


	# runs any normalizers that were defined on the class for individual fields
	def perform_data_normalization(self, data):
		errors, valid = {}, True
		for func in self.get_normalizers():
			value = getattr(data, func.key, None)
			if value is not None:
				try:
					normalized = self.call_func(func, value)
					setattr(data, func.key, normalized)
				except Exception:
					errors[func.key] = 'Error occurred during normalization of {0}.'.format(func.key)
					valid = False

		return data, valid, errors


	# runs any custom validators that were defined on the class for individual fields
	def perform_custom_validation(self, data):
		results, valid = {}, True
		for func in self.get_validators():
			value = getattr(data, func.key, None)
			
			if value is not None:
				valid = self.call_func(func, value)
			elif func.key.lower() == 'user':
				valid = self.call_func(func, self.user)
			else:
				valid = False
				results[func.key] = ['Parameter {0} could not be mapped from the data.'.format(func.key)]

			if not valid:
				if not func.key in results:
					results[func.key] = [func.error]
				else:
					results[func.key].append(func.error)
						
		return valid, results


	# used to dispatch calls appropriately from bound and unbound (imported/static) functions
	def call_func(self, func, value):
		if getattr(func, 'is_instance', False):
			return func(self, value)
		else:
			return func(value)


	# just a placeholder, but implementations should handle the actual incoming command and return a HTTP response
	def handle(self, data):
		raise NotImplementedError("The default handle method was not overridden by the custom handler.")