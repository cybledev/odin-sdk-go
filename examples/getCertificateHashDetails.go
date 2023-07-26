package main

import (
	"fmt"
	"github.com/cybledev/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	resp, err := client.GetCertificateHashDetails("5821D920257433710022A66B701E794A954012601CABE63F8F0499A74D3489FE")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.Success)
	fmt.Println(resp.Data)
}
