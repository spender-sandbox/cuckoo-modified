from django.template.defaultfilters import register
from collections import deque

@register.filter("endswith")
def endswith(value, thestr):
    return value.endswith(thestr)

@register.filter("proctreetolist")
def proctreetolist(tree):
    stack = deque(tree)
    outlist = []
    while stack:
        node = stack.popleft()
        outlist.append(node)
        if "startchildren" in node or "endchildren" in node:
            continue
        if node["children"]:
            stack.appendleft({"endchildren" : 1})
            stack.extendleft(reversed(node["children"]))
            stack.appendleft({"startchildren" : 1})
    return outlist
    