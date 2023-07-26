package main

import (
	"fmt"
	"github.com/cybledev/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	resp, err := client.GetIpCveDetails("100.26.248.109")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Success: %t\n", resp.Success)
	for _, cve := range resp.Data {
		fmt.Printf("ID: %s,\nSummary: %s\n", cve.ID, cve.Summary)
	}
}
