package main

import (
	"fmt"
	"github.com/cybledev/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	opts := &odin.HostsSearchRequest{
		Query: "services.port:80",
		Limit: 10,
		Start: nil,
	}
	var data []odin.HostsSearchData
	for i := 0; i < 5; i++ {
		resp, err := client.SearchHosts(*opts)
		if err != nil {
			fmt.Println(err)
			return
		}
		data = append(data, resp.Data...)
		opts.Start = resp.Pagination.Last
	}
	fmt.Println(len(data))
}
