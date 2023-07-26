package main

import (
	"fmt"
	"github.com/cybledev/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	resp, err := client.GetHostsSummary(odin.HostsSummaryRequest{
		Field: "services.name",
		Limit: 10,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, bucket := range resp.Data.Buckets {
		fmt.Printf("Service: %s, Count: %d\n", bucket.Key, bucket.DocCount)
	}
}
