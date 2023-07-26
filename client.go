package odin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type APIClient struct {
	BaseUrl string
	APIKey  string
}

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%d %s", e.StatusCode, e.Message)
}

// NewAPIClient Returns the APIClient
func NewAPIClient(baseUrl, apiKey string) *APIClient {
	return &APIClient{
		BaseUrl: baseUrl,
		APIKey:  apiKey,
	}
}

// GetHostsCount Fetch the record count
// Returns the total no of records based on query
// @return HostCountResponse
func (c *APIClient) GetHostsCount(query string) (*HostCountResponse, error) {
	countReq := &HostCountRequestModel{
		Query: query,
	}
	apiUrl := fmt.Sprintf("%s/hosts/count", c.BaseUrl)
	var response HostCountResponse
	resp, err := c.MakeRequest(apiUrl, "post", countReq, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, err
}

// GetHostsIpDetails Fetch the latest ip details
// Returns the complete ip details
// @return HostsIpDetailsResponse
func (c *APIClient) GetHostsIpDetails(ip string) (*HostsIpDetailsResponse, error) {
	apiUrl := fmt.Sprintf("%s/hosts/%s/", c.BaseUrl, ip)
	var response HostsIpDetailsResponse
	resp, err := c.MakeRequest(apiUrl, "GET", ip, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, err
}

// GetIpCveDetails Fetch the latest cve details
// Returns the complete cve details
// @return IpCveResponse
func (c *APIClient) GetIpCveDetails(ip string) (*IpCveResponse, error) {
	apiUrl := fmt.Sprintf("%s/hosts/cve/%s/", c.BaseUrl, ip)
	var response IpCveResponse
	resp, err := c.MakeRequest(apiUrl, "GET", ip, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, err
}

// SearchHosts Fetch the record based on query
// Returns the record based on query and blank query will return all records. It uses es searchafter for the pagination.
// @return HostsSearchResponse
func (c *APIClient) SearchHosts(query HostsSearchRequest) (*HostsSearchResponse, error) {

	apiUrl := fmt.Sprintf("%s/hosts/search", c.BaseUrl)
	var response HostsSearchResponse
	resp, err := c.MakeRequest(apiUrl, "POST", query, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, nil
}

// GetHostsSummary Create the summary of the field based on query
// Returns the summary of the field based on query
// @return HostsSummaryResponse
func (c *APIClient) GetHostsSummary(query HostsSummaryRequest) (*HostsSummaryResponse, error) {
	apiUrl := fmt.Sprintf("%s/hosts/summary", c.BaseUrl)
	var response HostsSummaryResponse
	resp, err := c.MakeRequest(apiUrl, "POST", query, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, err
}

// GetCertificateCount Fetch the record count
// Returns the total no of records based on query
// @return CertificateCountResponse
func (c *APIClient) GetCertificateCount(query string) (*CertificateCountResponse, error) {
	countReq := &CertificateCountRequest{
		Query: query,
	}
	apiUrl := fmt.Sprintf("%s/certificates/count", c.BaseUrl)
	var response CertificateCountResponse
	resp, err := c.MakeRequest(apiUrl, "post", countReq, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, err
}

// GetCertificateHashDetails Fetch the complete certificate
// Returns the complete certificate
// @return CertificateHashResponse
func (c *APIClient) GetCertificateHashDetails(hash string) (*CertificateHashResponse, error) {
	apiUrl := fmt.Sprintf("%s/certificates/%s/", c.BaseUrl, hash)
	var response CertificateHashResponse
	resp, err := c.MakeRequest(apiUrl, "GET", hash, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, err
}

// SearchCertificates Fetch the record based on query
// Returns the record based on query and blank query will return all records. It uses es searchafter for the pagination.
// @return CertificateSearchResponse
func (c *APIClient) SearchCertificates(query CertificateSearchRequest) (*CertificateSearchResponse, error) {

	apiUrl := fmt.Sprintf("%s/certificates/search", c.BaseUrl)
	var response CertificateSearchResponse
	resp, err := c.MakeRequest(apiUrl, "POST", query, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, nil
}

// GetCertificatesSummary Create the summary of the field based on query
// Returns the summary of the field based on query
// @return CertificateSummaryResponse
func (c *APIClient) GetCertificatesSummary(query CertificateSummaryRequest) (*CertificateSummaryResponse, error) {
	apiUrl := fmt.Sprintf("%s/certificates/summary", c.BaseUrl)
	var response CertificateSummaryResponse
	resp, err := c.MakeRequest(apiUrl, "POST", query, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		err = &APIError{
			StatusCode: resp.StatusCode,
			Message:    response.Message,
		}
		return nil, err
	}
	return &response, err
}

// MakeRequest sends an HTTP request to the specified API endpoint using the given method and query parameters.
// It marshals the query into JSON, sets the necessary headers including the API key, and unmarshals the response into the provided responseModel.
func (c *APIClient) MakeRequest(apiUrl string, method string, query any, responseModel any) (*http.Response, error) {

	jsonPayload, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(strings.ToUpper(method), apiUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}

	// Set Headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(respBody, responseModel); err != nil {
		return nil, err
	}

	return resp, nil
}
