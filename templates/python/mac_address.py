#Make mask

buildcode="""
def get_mac_addr():
	from uuid import getnode
	hex(getnode())
"""


callcode="""
	key_combos.append(get_mac_addr())
"""