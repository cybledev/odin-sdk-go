# Odin SDK For Go

[![Go Reference](https://pkg.go.dev/badge/github.com/cybledev/odin-sdk-go.svg)](https://pkg.go.dev/github.com/cybledev/odin-sdk-go)

The Odin SDK for Go provides a simple way to interact with the Odin API and access various services related to cybersecurity, certificates, and more.

## Installation

To use the Odin SDK in your Go project, you need to install it using the `go get` command:

```bash
go get github.com/cybledev/odin-sdk-go
```

## Usage

Import the package into your Go code and create an instance of the `odin.APIClient` by providing the base API URL and your API key:
```golang
import github.com/cybledev/odin-sdk-go

client := odin.NewAPIClient("https://api.getodin.com/v1", "<APIKey>")
```

## APIs and Response Types

| API                           | Request Type              | Response Type                  |
|-------------------------------|---------------------------|--------------------------------|
| GetCertificateCount           | string                    | CertificateCountResponse       |
| GetCertificateHashDetails     | string                    | CertificateDetailsResponse     |
| GetHostsIpDetails             | string                    | HostDetailsResponse            |
| GetCertificatesSummary        | CertificateSummaryRequest | CertificateSummaryResponse     |
| GetHostsCount                 | string                    | HostCountResponse              |
| GetHostsSummary               | HostsSummaryRequest       | HostsSummaryResponse           |
| SearchCertificates            | CertificateSearchRequest  | CertificateSearchResponse      |
| SearchHosts                   | HostsSearchRequest        | HostsSearchResponse            |




## Examples

In the "examples" folder of this repository, you can find various usage examples demonstrating how to interact with the Odin API using the `odin-sdk-go` package.

Each example is a standalone Go program that showcases specific functionalities of the SDK.

```go

package main

import (
	"fmt"
	"github.com/cybledev/odin-sdk-go"
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
```

Make sure to replace `<APIKey>` with your actual Odin API key. 


Thank you for using the Odin SDK for Go. If you encounter any issues, find a bug, or want to contribute, feel free to open an issue or submit a pull request. Your feedback and contributions are highly appreciated!

For more information about our other projects and services, visit our website at https://www.getodin.com.