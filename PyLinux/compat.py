import gettext
import inspect


def patch_gettext_translation():
    signature = inspect.signature(gettext.translation)
    if 'codeset' in signature.parameters:
        return

    original_translation = gettext.translation

    def translation(domain, localedir=None, languages=None, class_=None,
                    fallback=False, codeset=None):
        return original_translation(
            domain,
            localedir=localedir,
            languages=languages,
            class_=class_,
            fallback=fallback,
        )

    gettext.translation = translation


patch_gettext_translation()
