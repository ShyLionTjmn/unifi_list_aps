package main

import (
  "fmt"
  "time"
  "bytes"
  "sort"
  "bufio"
  "os"
  "syscall"
  "strings"
  "net/http"
  "net/url"
  "encoding/json"
  "crypto/tls"
  "io/ioutil"
  "github.com/fatih/color"
  "golang.org/x/crypto/ssh/terminal"
)

const BASE_URI="https://localhost:8443"

type M map[string]interface{}

var sites M

func init() {
  sites = make(M)
}

type ByDescr []string

func (a ByDescr) Len() int		{ return len(a) }
func (a ByDescr) Swap(i, j int)		{ a[i], a[j] = a[j], a[i] }
func (a ByDescr) Less(i, j int) bool	{ return sites[a[i]].(M)["descr"].(string) < sites[a[j]].(M)["descr"].(string) }

func usage() {
  fmt.Printf("Usage: %s [-u user] [-p password] [search strings]\n", os.Args[0])
}

func main() {

  opt_u := ""
  opt_p := ""

  m := make(M)

  args := os.Args[1:]

  for len(args) > 0 && len(args[0]) > 0 && args[0][0] == '-' {
    switch args[0] {
    case "-u":
      if len(args) < 2 {
        usage()
        os.Exit(1)
      }
      opt_u = args[1]
      args = args[2:]
    case "-p":
      if len(args) < 2 {
        usage()
        os.Exit(1)
      }
      opt_p = args[1]
      args = args[2:]
    default:
      usage()
      os.Exit(1)
    }
  }

  if opt_u == "" {
    fmt.Print("User: ")
    reader := bufio.NewReader(os.Stdin)
    user, _ := reader.ReadString('\n')
    opt_u = strings.Replace(user, "\n", "", -1)
  }

  if opt_p == "" {
    fmt.Print("Password: ")
    pass, err := terminal.ReadPassword(int(syscall.Stdin))
    fmt.Println()
    if err != nil { panic(err) }
    opt_p = string(pass)
  }


  m["username"] = opt_u
  m["password"] = opt_p



  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

  j, err := json.Marshal(m)
  if err != nil { panic(err) }

  client := &http.Client{}
  resp, err := client.Post(BASE_URI+"/api/login", "application/x-www-form-urlencoded", bytes.NewBuffer(j))
  if err != nil { panic(err) }

  if resp.StatusCode != 200 {
    fmt.Println("Login error. Code:", resp.StatusCode)
  }

  cookies := resp.Cookies()

  req, err := http.NewRequest("GET", BASE_URI+"/api/self/sites", nil)
  if err != nil { panic(err) }


  for _, cookie := range cookies {
    req.AddCookie(cookie)
  }

  resp, err = client.Do(req)
  if err != nil { panic(err) }

  body, err := ioutil.ReadAll(resp.Body)
  resp.Body.Close()
  if err != nil { panic(err) }

  data := make(M)

  err = json.Unmarshal(body, &data)

  if err != nil { panic(err) }

  for _, st_m := range data["data"].([]interface{}) {
    st_h := st_m.(map[string]interface{})

    st_id := st_h["_id"].(string)
    st_descr := st_h["desc"].(string)
    st_name := st_h["name"].(string)

    sites[st_id] = make(M)
    sites[st_id].(M)["name"] = st_name
    sites[st_id].(M)["descr"] = st_descr

    sites[st_id].(M)["aps"] = make(M)

    url, err := url.Parse(BASE_URI+"/api/s/"+st_name+"/stat/device")
    if err != nil { panic(err) }
    req.URL = url

    resp, err = client.Do(req)
    if err != nil { panic(err) }

    body, err := ioutil.ReadAll(resp.Body)
    resp.Body.Close()
    if err != nil { panic(err) }

    st_data := make(M)

    err = json.Unmarshal(body, &st_data)
    if err != nil { panic(err) }

    for _, ap_m := range st_data["data"].([]interface{}) {
      ap_h := ap_m.(map[string]interface{})

      //ap_id := ap_h["_id"].(string)
      var ap_uptime int64
      if ap_h["uptime"] != nil {
        ap_uptime = int64(ap_h["uptime"].(float64))
      }
      ap_adopted := ap_h["adopted"].(bool)
      ap_ip := ap_h["ip"].(string)
      var ap_ls int64
      if ap_h["last_seen"] != nil {
        ap_ls = int64(ap_h["last_seen"].(float64))
      }
      //ap_lic_state := ap_h["license_state"].(string)
      ap_mac := ap_h["mac"].(string)
      //ap_model := ap_h["model"].(string)
      //ap_type := ap_h["type"].(string)

      var ap_name string=ap_mac
      if ap_h["name"] != nil {
        ap_name = ap_h["name"].(string)
      }

      var ap_serial string="n/d"
      if ap_h["serial"] != nil {
        ap_serial = ap_h["serial"].(string)
      }
      ap_state := int64(ap_h["state"].(float64))

      seen := "never"
      if ap_ls > 0 {
        seen_d := time.Now().Sub( time.Unix(ap_ls,0) )
        seen_d = (seen_d/time.Second)*time.Second
        seen = seen_d.String()
      }

      ut := "n/d"
      if ap_uptime > 0 {
        ut = time.Duration( time.Duration(ap_uptime)*time.Second).String()
      }

      sites[st_id].(M)["aps"].(M)[ap_mac] = make(M)

      sites[st_id].(M)["aps"].(M)[ap_mac].(M)["name"] = ap_name
      sites[st_id].(M)["aps"].(M)[ap_mac].(M)["ip"] = ap_ip
      sites[st_id].(M)["aps"].(M)[ap_mac].(M)["serial"] = ap_serial
      sites[st_id].(M)["aps"].(M)[ap_mac].(M)["ut"] = ut
      sites[st_id].(M)["aps"].(M)[ap_mac].(M)["seen"] = seen
      sites[st_id].(M)["aps"].(M)[ap_mac].(M)["adopted"] = ap_adopted
      sites[st_id].(M)["aps"].(M)[ap_mac].(M)["state"] = ap_state

    }
  }

  st_ids := make([]string, 0)

  for k, _ := range sites {
    st_ids = append(st_ids, k)
  }

  sort.Sort(ByDescr(st_ids))

  for _, id := range st_ids {

    site_printed := false

    ap_macs := make([]string, 0)

    for m, _ := range sites[id].(M)["aps"].(M) {
      ap_macs = append(ap_macs, m)
    }

    sort.Strings(ap_macs)

    for _, mac := range ap_macs {
      ap_h := sites[id].(M)["aps"].(M)[mac].(M)

      ap_matched := true

      if len(args) > 0 {
        ap_matched = false

        lc_mac := strings.ToLower(mac)
        plain_mac := strings.Replace(lc_mac, ":", "", -1)
        lc_serial := strings.ToLower(ap_h["serial"].(string))
        lc_name := strings.ToLower(ap_h["name"].(string))

        for i := 0; i < len(args); i++ {
          lc_arg := strings.ToLower(args[i])
//fmt.Println(
          if strings.Index(lc_mac, lc_arg) >= 0 ||
             strings.Index(plain_mac, lc_arg) >= 0 ||
             strings.Index(lc_serial, lc_arg) >= 0 ||
             strings.Index(lc_name, lc_arg) >= 0 ||
             strings.Index(ap_h["ip"].(string), lc_arg) >= 0 ||
             false {
            //if
            ap_matched = true
            break
          }

        }
      }

      if ap_matched {
        if !site_printed {
          fmt.Println(sites[id].(M)["descr"])
          site_printed = true
        }

        ap_state := ap_h["state"].(int64)

        if ap_state == 0 {
          color.Set(color.FgRed)
        } else if ap_state == 1 {
          color.Set(color.FgGreen)
        } else {
          color.Set(color.FgCyan)
        }
        fmt.Println("\t", mac+" ("+ap_h["serial"].(string)+")", ap_h["name"], "Uptime: "+ap_h["ut"].(string), "Adopted:", ap_h["adopted"], "IP:", ap_h["ip"], "Last seen:", ap_h["seen"], "St:", ap_state)
        color.Unset()
      }
    }

  }
}
