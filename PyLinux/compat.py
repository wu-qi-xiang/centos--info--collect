"""Compatibility shims for running legacy Django 2.1 on modern Python."""

import gettext
import inspect


if 'codeset' not in inspect.signature(gettext.translation).parameters:
    _translation = gettext.translation

    def translation(domain, localedir=None, languages=None, class_=None, fallback=False, codeset=None):
        return _translation(
            domain,
            localedir=localedir,
            languages=languages,
            class_=class_,
            fallback=fallback,
        )

    gettext.translation = translation
