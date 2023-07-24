package main

import (
	"fmt"
	"github.com/odin-cyble/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	resp, err := client.GetCertificateCount("string")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.Success)
	fmt.Println(resp.Data.Count)
}
