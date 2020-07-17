from enum import Enum, unique
from django.core.files.uploadedfile import InMemoryUploadedFile

# a decorator for converting a singular type into the array version
def array(cls):

	old_valid = cls.is_valid
	old_cast = cls.cast

	def new_valid(value):
		return all(map(old_valid, value))

	def new_cast(value):
		return list(map(old_cast, value))

	cls.is_valid = new_valid
	cls.cast = new_cast

	return cls

class ParamTypeBase(object):

	representation = ''

	@staticmethod
	def is_valid(value):
		raise NotImplementedError

	@staticmethod
	def cast(value):
		raise NotImplementedError

class Blob(ParamTypeBase):

	representation = 'blob'

	def is_valid(value):
		return isinstance(value, InMemoryUploadedFile)

	def cast(value):
		return value


class File(ParamTypeBase):

	representation = 'file'

	def is_valid(value):
		return True

	def cast(value):
		return value


class Float(ParamTypeBase):
	
	representation = 'float'

	def is_valid(value):
		return isinstance(value, float) or isinstance(value, int)

	def cast(value):
		return float(value)

@array
class FloatArray(Float):
	representation = 'float[]'

class Integer(ParamTypeBase):
	representation = 'integer'

	def is_valid(value):
		return isinstance(value, int)

	def cast(value):
		return value

@array
class IntegerArray(Integer):
	representation = 'integer[]'

class String(ParamTypeBase):
	representation = 'string'

	def is_valid(value):
		return isinstance(value, str)

	def cast(value):
		return value

@array
class StringArray(String):
	representation = 'string[]'


class Object(ParamTypeBase):
	representation = 'object'

	def is_valid(value):
		return isinstance(value, dict)

	def cast(value):
		return value

@array
class ObjectArray(Object):
	representation = 'object[]'

class Boolean(ParamTypeBase):
	representation = 'boolean'

	def is_valid(value):
		return isinstance(value, bool)

	def cast(value):
		return value

@array
class BooleanArray(Boolean):
	representation = 'boolean[]'


@unique
class Types(Enum):
	BLOB = Blob
	FILE = File
	BOOLEAN = Boolean
	BOOLEAN_ARRAY = BooleanArray
	FLOAT = Float
	FLOAT_ARRAY = FloatArray
	INTEGER = Integer
	INTEGER_ARRAY = IntegerArray
	STRING = String
	STRING_ARRAY = StringArray
	OBJECT = Object
	OBJECT_ARRAY = ObjectArray
