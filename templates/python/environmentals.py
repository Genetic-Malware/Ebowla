buildcode="""
def pull_environmentals(environmentals):
    env_string = ''
    for env_var in environmentals:
        env_string += os.getenv(env_var)

    return env_string.lower()
    
"""

callcode="""
    key_combos.append(pull_environmentals(env_vars))
"""