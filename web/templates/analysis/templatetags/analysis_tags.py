try:
    import re2 as re
except ImportError:
    import re

from django.template.defaultfilters import register

@register.filter("mongo_id")
def mongo_id(value):
    """Retrieve _id value.
    @todo: it will be removed in future.
    """
    if isinstance(value, dict):
        if value.has_key("_id"):
            value = value["_id"]

    # Return value
    return unicode(value)

@register.filter("is_dict")
def is_dict(value):
    """Checks if value is an instance of dict"""
    return isinstance(value, dict)

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, "")

@register.filter(name="dehex")
def dehex(value):
    return re.sub(r"\\x[0-9a-f]{2}", "", value)

@register.filter(name="stats_total")
def stats_total(value):
    total = float()
    for item in value:
       total += item["time"]

    return total
