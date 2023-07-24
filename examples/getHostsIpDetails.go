package main

import (
	"fmt"
	"github.com/odin-cyble/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	resp, err := client.GetHostsIpDetails("223.217.65.218")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.Success)
	for _, svc := range resp.Data.Services {
		fmt.Println("Service Name:", svc.Name)
	}
}
