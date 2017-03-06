package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/levigross/grequests"
	"github.com/spf13/viper"
)

var (
	baseURL             string
	poolName            string
	username            string
	password            string
	hostName, hostIP    string
	hostPort, hostRatio int
	hostEnabled         bool
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type poolIP struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
}
type poolServer struct {
	RewriteHostHeader bool   `json:"rewrite_host_header"`
	Port              int    `json:"port"`
	Ratio             int    `json:"ratio"`
	IP                poolIP `json:"ip"`
	Enabled           bool   `json:"enabled"`
	VerifyNetwork     bool   `json:"verfiy_network"`
	Static            bool   `json:"static"`
	Hostname          string `json:"hostname"`
}

func jprint(x interface{}) {
	b, err := json.MarshalIndent(x, " ", "  ")
	if err != nil {
		fmt.Println("MARSHALL ERR:", err)
		return
	}
	fmt.Println(string(b))
}

func addToPool(cfg *grequests.RequestOptions, poolName, hostname, ip string, port, ratio int, enabled bool) {
	uuid, err := uuidLookup(cfg, poolName)
	if err != nil {
		panic(err)
	}
	resp, err := grequests.Get(baseURL+"/api/pool/"+uuid, cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
	var pool map[string]interface{}
	resp.JSON(&pool)
	svr := poolServer{
		Port:     port,
		Ratio:    ratio,
		IP:       poolIP{Addr: ip, Type: "V4"},
		Enabled:  enabled,
		Hostname: hostname,
	}
	s1 := pool["servers"]
	if s1 == nil {
		s1 = make([]interface{}, 0, 10)
	}
	servers := s1.([]interface{})
	servers = append(servers, svr)
	pool["servers"] = servers

	cfg.JSON = pool
	_, err = grequests.Put(baseURL+"/api/pool/"+uuid, cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
}

func deleteFromPool(cfg *grequests.RequestOptions, poolName, hostName string) {
	uuid, err := uuidLookup(cfg, poolName)
	if err != nil {
		panic(err)
	}
	resp, err := grequests.Get(baseURL+"/api/pool/"+uuid, cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
	var pool map[string]interface{}
	resp.JSON(&pool)
	servers := pool["servers"].([]interface{})
	for i, s := range servers {
		server := s.(map[string]interface{})
		name := server["hostname"].(string)
		if name == hostName {
			servers = append(servers[:i], servers[i+1:]...)
			pool["servers"] = servers

			cfg.JSON = pool
			_, err = grequests.Put(baseURL+"/api/pool/"+uuid, cfg)
			if err != nil {
				fmt.Println("POOL ERR:", err)
			}
		}
	}
}

func deletePool(cfg *grequests.RequestOptions, poolName, hostName string) {
	uuid, err := uuidLookup(cfg, poolName)
	if err != nil {
		panic(err)
	}
	_, err = grequests.Delete(baseURL+"/api/pool/"+uuid, cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
}

func showPool(cfg *grequests.RequestOptions, uuid string) {
	resp, err := grequests.Get(baseURL+"/api/pool/"+uuid, cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
	var pool map[string]interface{}
	resp.JSON(&pool)
	jprint(pool)
}

func poolList(cfg *grequests.RequestOptions) {
	resp, err := grequests.Get(baseURL+"/api/pool/", cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
	var pool map[string]interface{}
	resp.JSON(&pool)

	results := pool["results"].([]interface{})
	for _, r := range results {
		result := r.(map[string]interface{})
		fmt.Println("Name:", result["name"], "UUID:", result["uuid"])
	}
	return
}

func pooly(cfg *grequests.RequestOptions) {
	resp, err := grequests.Get(baseURL+"/api/pool/", cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
	var pool map[string]interface{}
	resp.JSON(&pool)
	results := pool["results"].([]interface{})
	for _, r := range results {
		result := r.(map[string]interface{})
		fmt.Println("Name:", result["name"], "UUID:", result["uuid"])
	}
	return
}

func poolDetails(pool map[string]interface{}) {
	s := pool["servers"]
	if s == nil {
		return
	}
	servers := s.([]interface{})
	fmt.Printf("%-20s %-17s %5s %s\n", "Hostname", "IP", "Ratio", "Enabled")
	for _, s := range servers {
		var server poolServer
		b, _ := json.Marshal(s)
		json.Unmarshal(b, &server)
		fmt.Printf("%-20s %-17s %5d %t\n", server.Hostname, server.IP.Addr, server.Ratio, server.Enabled)
	}
}

func poolInfo(cfg *grequests.RequestOptions, name string) {
	resp, err := grequests.Get(baseURL+"/api/pool/", cfg)
	if err != nil {
		fmt.Println("POOL ERR:", err)
	}
	var pools map[string]interface{}
	resp.JSON(&pools)
	results := pools["results"].([]interface{})
	for _, r := range results {
		result := r.(map[string]interface{})
		if result["name"] == name {
			poolDetails(result)
			break
		}
	}
}

func uuidLookup(cfg *grequests.RequestOptions, name string) (string, error) {
	resp, err := grequests.Get(baseURL+"/api/pool/", cfg)
	if err != nil {
		return "", err
	}
	var pool map[string]interface{}
	resp.JSON(&pool)
	results := pool["results"].([]interface{})
	for _, r := range results {
		result := r.(map[string]interface{})
		if result["name"] == name {
			return result["uuid"].(string), nil
		}
	}
	return "", fmt.Errorf("no uuid found for pool: %s", name)
}

func connect(username, password string) *grequests.RequestOptions {
	if len(username) == 0 {
		panic("username not set!")
	}
	if len(password) == 0 {
		panic("password not set!")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	cfg := &grequests.RequestOptions{
		JSON:         credentials{username, password},
		HTTPClient:   client,
		UseCookieJar: true,
	}

	resp, err := grequests.Post(baseURL+"/login", cfg)
	if err != nil {
		fmt.Println("LOGIN ERR:", err)
	}
	var csrftoken, scook *http.Cookie
	for _, c := range resp.RawResponse.Cookies() {
		switch c.Name {
		case "sessionid":
			scook = c
		case "csrftoken":
			csrftoken = c
		}
	}

	var Xcsrftoken = &http.Cookie{
		Name:  csrftoken.Name,
		Value: csrftoken.Value,
	}
	cfg.Cookies = []*http.Cookie{scook, Xcsrftoken}
	cfg.Headers = map[string]string{
		"Referer":     "https://10.101.2.42",
		"X-CSRFToken": csrftoken.Value,
	}
	return cfg
}

func init() {
	flag.StringVar(&poolName, "pool", "", "pool")
	flag.StringVar(&hostName, "name", "", "hostname")
	flag.StringVar(&hostIP, "ip", "", "ip")
	flag.IntVar(&hostPort, "port", 80, "port")
	flag.IntVar(&hostRatio, "ratio", 1, "ratio")
	flag.BoolVar(&hostEnabled, "enabled", true, "enabled")
}

func poolCheck() {
	if len(poolName) == 0 {
		fmt.Println("no pool name specified")
		os.Exit(1)
	}
}

func main() {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.AddConfigPath(".")      // optionally look for config in the working directory
	viper.SetConfigType("toml")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		config := viper.ConfigFileUsed()
		if len(config) == 0 {
			fmt.Printf("Fatal error - config file not found: %s\n", "config.toml")
		} else {
			fmt.Printf("Fatal error - config file (%s): %s \n", config, err)
		}
		os.Exit(1)
	}

	username = viper.GetString("main.username")
	password = viper.GetString("main.password")
	aviHost := viper.GetString("main.avi_host")
	if len(aviHost) == 0 {
		fmt.Println("no AVI host in config")
		os.Exit(1)
	}
	baseURL = "https://" + aviHost

	flag.Parse()
	args := flag.Args()

	cfg := connect(username, password)
	if len(args) == 0 {
		fmt.Println("no command specified")
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		poolCheck()
		addToPool(cfg, poolName, hostName, hostIP, hostPort, hostRatio, hostEnabled)
	case "del", "delete":
		poolCheck()
		if len(hostName) == 0 {
			fmt.Println("no hostName specified")
			os.Exit(1)
		}
		deleteFromPool(cfg, poolName, hostName)
	case "list":
		poolCheck()
		poolInfo(cfg, poolName)
	case "pools":
		pooly(cfg)
	default:
		fmt.Println("invalid command:", args[0])
		os.Exit(1)
	}
}
