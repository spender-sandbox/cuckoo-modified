from django.template.defaultfilters import register

@register.filter("endswith")
def endswith(value, thestr):
    return value.endswith(thestr)