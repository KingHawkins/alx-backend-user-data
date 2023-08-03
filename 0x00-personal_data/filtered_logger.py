#!/usr/bin/env python3
"""
Regex-ing.
"""
import re


def filter_datum(fields, redaction, message, separator):
    """
    Returns log message obfuscated.
    """
    messages = ("".join(message)).split(separator)
    collection = list()
    for dictionary in messages:
        res = tuple(dictionary.split("="))
        if res[0] != "":
            collection.append(res)
    collection = dict(collection)
    for field in fields:
        collection[field] = redaction
    return "".join(["=".join((key, value + ";"))
                   for key, value in collection.items()])
