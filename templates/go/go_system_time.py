imports=["time", "fmt"]

buildcode="""
func get_system_time() []string{
	p := fmt.Sprintf
	t := time.Now()
	timeList := []string{}

	timeList = append(timeList,p("%d%02d%02d",t.Year(),t.Month(),t.Day()))
	timeList = append(timeList,p("%d%02d00",t.Year(),t.Month()))
	timeList = append(timeList,p("%d0000",t.Year()))

	return timeList
}
"""

callcode="""
	key_combos[i] = get_system_time()
	i += 1

"""
