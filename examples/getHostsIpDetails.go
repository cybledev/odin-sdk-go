package main

import (
	"fmt"
	"github.com/cybledev/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	resp, err := client.GetHostsIpDetails("100.26.248.109")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Success: %t, IP: %s\n", resp.Success, resp.Data.IP)
	for _, svc := range resp.Data.Services {
		fmt.Printf("Service Name: %s, Service Port: %d\n", svc.Name, svc.Port)
	}
}
