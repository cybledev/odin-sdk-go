package main

import (
	"fmt"
	"github.com/cybledev/odin-sdk-go"
)

func main() {
	client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
	opts := &odin.CertificateSearchRequest{
		Query: "certificate.issuer.common_name:R3",
		Limit: 10,
		Start: nil,
	}
	var data []odin.CertificateSearchData
	for i := 0; i < 5; i++ {
		resp, err := client.SearchCertificates(*opts)
		if err != nil {
			fmt.Println(err)
			return
		}
		data = append(data, resp.Data...)
		opts.Start = resp.Pagination.Last
	}
	fmt.Println(len(data))
}
