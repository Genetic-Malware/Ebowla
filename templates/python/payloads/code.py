loader="""
d = dict(locals(), **globals())
exec(self.payload, d, d)
"""
