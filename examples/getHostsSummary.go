package main

import (
	"fmt"
	"github.com/odin-cyble/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	resp, err := client.GetHostsSummary(odin.HostsSummaryRequest{
		Field: "services.port",
		Limit: 10,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.Success)
	fmt.Println(len(resp.Data.Buckets))

}
