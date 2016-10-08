loader="""
import os
with open(os.path.basename(self.output_name), 'w') as f:
    f.write(self.payload)
"""
