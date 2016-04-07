imports=["strings", "strings", "github.com/miekg/dns", "log"]

buildcode="""
func getExtIP() string{

    target := "myip.opendns.com"
    server := "resolver2.opendns.com"

    c := dns.Client{}
    m := dns.Msg{}
    m.SetQuestion(target+".", dns.TypeA)
    //r, t, err := c.Exchange(&m, server+":53")
    r, _, err := c.Exchange(&m, server+":53")
    if err != nil {
        log.Fatal(err)
    }
    //log.Printf("Took %v", t)
    if len(r.Answer) == 0 {
        log.Fatal("No results")
    }
    for _, ans := range r.Answer {
        Arecord := ans.(*dns.A)
        return fmt.Sprintf("%s", Arecord.A)
        //log.Printf("%s", Arecord.A)
    }
    return "Error Looking up Address"
}

// same output format as python version
func get_external_ip() []string {
    ipList := getExtIP()
    ipArr := strings.Split(ipList,".")
    retVal := []string{}
    retVal = append(retVal,ipList)
    fmt.Printf("[*] External IP: %s\\n",strings.Join(ipArr[:],"."))
    for cnt,_ := range ipArr{
        //we don't want the 0.0.0.0 case included
        if cnt == len(ipArr)-1 {
            break
        }
        ipArr[len(ipArr)-1-cnt]="0"
        //fmt.Println(ipArr)
        retVal = append(retVal,strings.Join(ipArr[:],"."))
    }
    return retVal

}
"""

callcode="""
    key_combos[i] = get_external_ip()
    i += 1
"""
