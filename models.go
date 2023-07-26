package odin

type HostCountRequestModel struct {
	Query string `json:"query"`
}

type HostCountResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Count int `json:"count"`
	} `json:"data"`
	Message string `json:"message,omitempty"`
}

type HostsIpDetailsResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    struct {
		ASN struct {
			CountryCode  any    `json:"country_code"`
			Number       string `json:"number"`
			Organization string `json:"organization"`
		} `json:"asn"`
		ASNUpdatedAt string `json:"asn_updated_at"`
		Domains      any    `json:"domains"`
		Hostnames    []struct {
			LastUpdatedAt string `json:"last_updated_at"`
			Name          string `json:"name"`
		} `json:"hostnames"`
		IP            string `json:"ip"`
		IsIPv4        bool   `json:"is_ipv4"`
		IsIPv6        bool   `json:"is_ipv6"`
		LastUpdatedAt string `json:"last_updated_at"`
		Location      struct {
			City        string `json:"city"`
			Continent   string `json:"continent"`
			Coordinates struct {
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			} `json:"coordinates"`
			CountryCode string `json:"country_code"`
			CountryName string `json:"country_name"`
			GeoPoint    string `json:"geo_point"`
			LocaleCode  string `json:"locale_code"`
			Network     string `json:"network"`
			PostalCode  string `json:"postal_code"`
		} `json:"location"`
		LocationUpdatedAt string `json:"location_updated_at"`
		ScanID            int64  `json:"scan_id"`
		Services          []struct {
			Meta struct {
				Category string `json:"category"`
				Desc     string `json:"desc"`
				Name     string `json:"name"`
				Tags     any    `json:"tags"`
			} `json:"_meta"`
			CVE []struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"cve"`
			ExtraInfo     string `json:"extra_info"`
			LastUpdatedAt string `json:"last_updated_at"`
			Modules       struct {
				Oracle struct {
					AcceptVersion        int64           `json:"accept_version"`
					ConnectFlags0        map[string]bool `json:"connect_flags0"`
					ConnectFlags1        map[string]bool `json:"connect_flags1"`
					DidResend            bool            `json:"did_resend"`
					GlobalServiceOptions struct {
						FullDuplex     bool `json:"FULL_DUPLEX"`
						HeaderChecksum bool `json:"HEADER_CHECKSUM"`
						Unknown0001    bool `json:"UNKNOWN_0001"`
						Unknown0040    bool `json:"UNKNOWN_0040"`
					} `json:"global_service_options"`
					NSNServiceVersions struct {
						Authentication string `json:"authentication"`
						DataIntegrity  string `json:"data_integrity"`
						Encryption     string `json:"encryption"`
						Supervisor     string `json:"supervisor"`
					} `json:"nsn_service_versions"`
				} `json:"oracle"`
			} `json:"modules"`
			Name      string `json:"name"`
			Port      int64  `json:"port"`
			Product   string `json:"product"`
			Protocol  string `json:"protocol"`
			Softwares []struct {
				Edition  string `json:"edition"`
				Language string `json:"language"`
				Part     string `json:"part"`
				Product  string `json:"product"`
				Update   string `json:"update"`
				URI      string `json:"uri"`
				Vendor   string `json:"vendor"`
				Version  string `json:"version"`
			} `json:"softwares"`
			Tunnel  string `json:"tunnel"`
			Version string `json:"version"`
		} `json:"services"`
		ServicesHash string `json:"services_hash"`
		Tags         []struct {
			LastUpdatedAt string `json:"last_updated_at"`
			Name          string `json:"name"`
			PrettyName    string `json:"pretty_name"`
			Value         bool   `json:"value"`
		} `json:"tags"`
		Whois struct {
			Encoding struct {
				Raw string `json:"raw"`
			} `json:"_encoding"`
			Description  string `json:"descr"`
			Network      string `json:"network"`
			Organization string `json:"organization"`
			Raw          any    `json:"raw"`
		} `json:"whois"`
		WhoisUpdatedAt string `json:"whois_updated_at"`
	} `json:"data"`
}

type IpCveDetails struct {
	ID           string   `json:"id"`
	References   []string `json:"references"`
	Score        float64  `json:"score"`
	Services     []string `json:"services"`
	Severity     string   `json:"severity"`
	Summary      string   `json:"summary"`
	VectorString string   `json:"vector_string"`
	Weakness     string   `json:"weakness"`
}

type IpCveResponse struct {
	Success bool                    `json:"success"`
	Data    map[string]IpCveDetails `json:"data"`
	Message string                  `json:"message,omitempty"`
}

type HostsSearchRequest struct {
	Limit int       `json:"limit"`
	Query string    `json:"query,omitempty"`
	Start []float64 `json:"start,omitempty"`
}

type HostsSearchResponse struct {
	Data       []HostsSearchData `json:"data"`
	Message    string            `json:"message"`
	Pagination struct {
		Last  []float64 `json:"last"`
		Limit int       `json:"limit"`
		Start []float64 `json:"start"`
		Total int       `json:"total"`
	} `json:"pagination"`
	Success bool `json:"success"`
}
type HostsSearchData struct {
	ASN struct {
		CountryCode  any    `json:"country_code"`
		Number       string `json:"number"`
		Organization string `json:"organization"`
	} `json:"asn"`
	ASNUpdatedAt  string `json:"asn_updated_at"`
	Domains       any    `json:"domains"`
	Hostnames     []any  `json:"hostnames"`
	IP            string `json:"ip"`
	IsIPv4        bool   `json:"is_ipv4"`
	IsIPv6        bool   `json:"is_ipv6"`
	LastUpdatedAt string `json:"last_updated_at"`
	Location      struct {
		City        any    `json:"city"`
		Continent   string `json:"continent"`
		Coordinates struct {
			Latitude  string `json:"latitude"`
			Longitude string `json:"longitude"`
		} `json:"coordinates"`
		CountryCode string `json:"country_code"`
		CountryName string `json:"country_name"`
		GeoPoint    string `json:"geo_point"`
		LocaleCode  string `json:"locale_code"`
		Network     string `json:"network"`
		PostalCode  any    `json:"postal_code"`
	} `json:"location"`
	LocationUpdatedAt string `json:"location_updated_at"`
	ScanID            int    `json:"scan_id"`
	Services          []struct {
		Meta struct {
			Category string `json:"category"`
			Desc     string `json:"desc"`
			Name     string `json:"name"`
			Tags     []any  `json:"tags"`
		} `json:"_meta"`
		Cve struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"cve"`
		ExtraInfo     any    `json:"extra_info"`
		LastUpdatedAt string `json:"last_updated_at"`
		Modules       struct {
			Smtp struct {
				Banner string `json:"banner"`
			} `json:"smtp"`
			HTTP struct {
				ContentLength    int              `json:"content_length"`
				Headers          map[string][]any `json:"headers"`
				Protocol         string           `json:"protocol"`
				StatusCode       int              `json:"status_code"`
				TransferEncoding any              `json:"transfer_encoding"`
			} `json:"http"`
			TLS any `json:"tls"`
		} `json:"modules"`
		//Modules   interface{}   `json:"modules"`
		Name      string `json:"name"`
		Port      int    `json:"port"`
		Product   any    `json:"product"`
		Protocol  string `json:"protocol"`
		Softwares []any  `json:"softwares"`
		Tunnel    any    `json:"tunnel"`
		Version   any    `json:"version"`
	} `json:"services"`
	ServicesHash string `json:"services_hash"`
	Tags         []struct {
		LastUpdatedAt string `json:"last_updated_at"`
		Name          string `json:"name"`
		PrettyName    string `json:"pretty_name"`
		Value         bool   `json:"value"`
	} `json:"tags"`
	Whois struct {
		Encoding struct {
			Raw string `json:"raw"`
		} `json:"_encoding"`
		Descr        string `json:"descr"`
		Network      string `json:"network"`
		Organization string `json:"organization"`
		Raw          any    `json:"raw"`
	} `json:"whois"`
	WhoisUpdatedAt string `json:"whois_updated_at"`
}
type HostsSummaryRequest struct {
	Limit int32  `json:"limit"`
	Field string `json:"field,omitempty"`
}

type HostsSummaryResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		DocCountErrorUpperBound int `json:"doc_count_error_upper_bound"`
		SumOtherDocCount        int `json:"sum_other_doc_count"`
		Buckets                 []struct {
			DocCount int `json:"doc_count"`
			Key      any `json:"key"`
		} `json:"buckets"`
	} `json:"data,omitempty"`
}

type CertificateCountRequest struct {
	Query string `json:"query"`
}
type CertificateCountResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    struct {
		Count int `json:"count"`
	} `json:"data"`
}

type CertificateSearchRequest struct {
	Limit int       `json:"limit"`
	Query string    `json:"query,omitempty"`
	Start []float64 `json:"start,omitempty"`
	Pages int       `json:"pages,omitempty"`
}
type CertificateSearchResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Pagination struct {
		Start []float64 `json:"start"`
		Last  []float64 `json:"last"`
		Limit int       `json:"limit"`
		Total int       `json:"total"`
	} `json:"pagination"`
	Data []CertificateSearchData `json:"data"`
}
type CertificateSearchData struct {
	FingerprintMD5    string `json:"fingerprint_md5"`
	FingerprintSHA1   string `json:"fingerprint_sha1"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Issuer            struct {
		CommonName   []string `json:"common_name"`
		Country      []string `json:"country"`
		Organization []string `json:"organization"`
	} `json:"issuer"`
	Subject struct {
		CommonName []string `json:"common_name"`
	} `json:"subject"`
	SubjectAltName struct {
		DNSNames []string `json:"dns_names"`
	} `json:"subject_alt_name"`
	Tags     []string `json:"tags"`
	Validity struct {
		End    string `json:"end"`
		Length int    `json:"length"`
		Start  string `json:"start"`
	} `json:"validity"`
}

type CertificateHashResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    struct {
		Certificate struct {
			Extensions struct {
				AuthorityInfoAccess struct {
					IssuerURLs []string `json:"issuer_urls"`
					OCSPURLs   []string `json:"ocsp_urls"`
				} `json:"authority_info_access"`
				AuthorityKeyID   string `json:"authority_key_id"`
				BasicConstraints struct {
					IsCA bool `json:"is_ca"`
				} `json:"basic_constraints"`
				CertificatePolicies []struct {
					ID  string   `json:"id"`
					CPS []string `json:"cps,omitempty"`
				} `json:"certificate_policies"`
				CTPoison         bool `json:"ct_poison"`
				ExtendedKeyUsage struct {
					ClientAuth bool `json:"client_auth"`
					ServerAuth bool `json:"server_auth"`
				} `json:"extended_key_usage"`
				KeyUsage struct {
					DigitalSignature bool `json:"digital_signature"`
				} `json:"key_usage"`
				SubjectAltName struct {
					DNSNames []string `json:"dns_names"`
				} `json:"subject_alt_name"`
				SubjectKeyID string `json:"subject_key_id"`
			} `json:"extensions"`
			FingerprintMD5    string `json:"fingerprint_md5"`
			FingerprintSHA1   string `json:"fingerprint_sha1"`
			FingerprintSHA256 string `json:"fingerprint_sha256"`
			Issuer            struct {
				CommonName   []string `json:"common_name"`
				Country      []string `json:"country"`
				Organization []string `json:"organization"`
			} `json:"issuer"`
			Redacted     bool   `json:"redacted"`
			SerialNumber string `json:"serial_number"`
			Signature    struct {
				SignatureAlgorithm struct {
					Name string `json:"name"`
					OID  string `json:"oid"`
				} `json:"signature_algorithm"`
			} `json:"signature"`
			Subject struct {
				CommonName []string `json:"common_name"`
			} `json:"subject"`
			SubjectAltName struct {
				DNSNames         []string `json:"dns_names"`
				ExtendedDNSNames []struct {
					Domain    string `json:"domain"`
					Fld       string `json:"fld"`
					Subdomain string `json:"subdomain"`
					TLD       string `json:"tld"`
				} `json:"extended_dns_names"`
			} `json:"subject_alt_name"`
			SubjectKeyInfo struct {
				FingerprintSHA256 string `json:"fingerprint_sha256"`
				KeyAlgorithm      string `json:"key_algorithm"`
				PublicKey         struct {
					B      string `json:"b"`
					Curve  string `json:"curve"`
					GX     string `json:"gx"`
					GY     string `json:"gy"`
					Length int    `json:"length"`
					P      string `json:"p"`
					X      string `json:"x"`
					Y      string `json:"y"`
				} `json:"public_key"`
			} `json:"subject_key_info"`
			TBSFingerprint  string `json:"tbs_fingerprint"`
			ValidationLevel string `json:"validation_level"`
			Validity        struct {
				End    string `json:"end"`
				Length int    `json:"length"`
				Start  string `json:"start"`
			} `json:"validity"`
			Version int `json:"version"`
		} `json:"certificate"`
		Tags []string `json:"tags"`
	} `json:"data"`
}

type CertificateSummaryRequest struct {
	Limit int32  `json:"limit"`
	Field string `json:"field,omitempty"`
	Query string `json:"query,omitempty"`
}

type CertificateSummaryResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		DocCountErrorUpperBound int    `json:"doc_count_error_upper_bound"`
		Message                 string `json:"message"`
		SumOtherDocCount        int    `json:"sum_other_doc_count"`
		Buckets                 []struct {
			DocCount int    `json:"doc_count"`
			Key      string `json:"key"`
		} `json:"buckets"`
	} `json:"data"`
}
