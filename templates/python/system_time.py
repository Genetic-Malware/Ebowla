'''
System time will be return in a list
with the following masks
[YYYY0000, YYYYMM00, YYYYMMDD]
'''

buildcode="""
def get_system_time():
    import time
    time_mask = []
    time_mask.append(time.strftime("%Y%m%d"))
    time_mask.append(time.strftime("%Y%m00"))
    time_mask.append(time.strftime("%Y0000"))
    return time_mask
"""

callcode="""
    key_combos.append(get_system_time())
"""