imports=["strings","encoding/hex", "os"]


buildcode="""
func pull_environmentals(environmentals []string) string {
    env_string := ""
    for _,itr := range environmentals {
        env_string += os.Getenv(itr)
    }
    return(strings.ToLower(env_string))
}
"""

callcode="""
    key_combos[i] = []string{pull_environmentals(env_vars)}
    i += 1

"""