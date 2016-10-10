buildcode="""
def pull_environmentals(environmentals):
    env_string = ''
    for env_var in environmentals:
        try:
        	env_string += os.getenv(env_var)
        except:
        	pass
        	
    return env_string.lower()
    
"""

callcode="""
    key_combos.append(pull_environmentals(env_vars))
"""