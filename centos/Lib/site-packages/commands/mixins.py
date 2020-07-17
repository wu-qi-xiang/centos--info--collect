from django.http import JsonResponse


class AjaxMixin(object):

	@staticmethod
	def success(results, meta=None, status=200):
		if isinstance(results, list) or isinstance(results, tuple):
			content = {'results': results}
		elif results is not None:
			content = {'result': results}
		else:
			content = {}

		if meta: content.update(meta)
		return JsonResponse(content, status=status)

	@staticmethod
	def error(message, meta=None, status=400):
		content = {'error': message}
		if meta: content.update(meta)
		return JsonResponse(content, status=status)

	@staticmethod
	def errors(fields, meta=None, status=400):
		content = {'errors': fields}
		if meta: content.update(meta)
		return JsonResponse(content, status=status)
