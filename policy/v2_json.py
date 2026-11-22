"""Strict raw JSON parsing for the opt-in v2 consumer boundary.

Parsing alone does not select or authenticate a policy, context, or evidence.
"""
import json
import math


class InputError(ValueError):
    """A submitted v2 document is not strict JSON."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def _reject_constant(value):
    raise InputError(f'invalid JSON constant: {value}')


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise InputError('non-finite JSON number')
    return result


def parse_json(raw):
    """Parse UTF-8 JSON bytes, rejecting duplicate keys and non-finite numbers.

    Requiring bytes keeps decoding and duplicate-key checks inside the boundary.
    It intentionally accepts all JSON value types; each caller must validate its
    own document shape and distinguish boolean from integer fields.
    """
    if not isinstance(raw, bytes):
        raise InputError('JSON input must be bytes')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    except InputError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InputError('invalid UTF-8 JSON') from exc
