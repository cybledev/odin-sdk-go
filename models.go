package odin

import "time"

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
		ASNUpdatedAt string   `json:"asn_updated_at"`
		Banner       []string `json:"banner"`
		Domains      any      `json:"domains"`
		Hostnames    []struct {
			LastUpdatedAt string `json:"last_updated_at"`
			Name          string `json:"name"`
		} `json:"hostnames"`
		IP            string `json:"ip"`
		IsIPv4        bool   `json:"is_ipv4"`
		IsIPv6        bool   `json:"is_ipv6"`
		IsVuln        bool   `json:"is_vuln"`
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
		LocationUpdatedAt time.Time `json:"location_updated_at"`
		ScanID            int64     `json:"scan_id"`
		Services          []struct {
			Meta struct {
				Category string `json:"category"`
				Desc     string `json:"desc"`
				Name     string `json:"name"`
				Tags     any    `json:"tags"`
			} `json:"_meta"`
			Cve []struct {
				Id       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"cve"`
			ExtraInfo     string    `json:"extra_info"`
			LastUpdatedAt time.Time `json:"last_updated_at"`
			Modules       struct {
				Oracle struct {
					AcceptVersion        int64           `json:"accept_version,omitempty"`
					ConnectFlags0        map[string]bool `json:"connect_flags0,omitempty"`
					ConnectFlags1        map[string]bool `json:"connect_flags1,omitempty"`
					DidResend            bool            `json:"did_resend,omitempty"`
					GlobalServiceOptions struct {
						FullDuplex     bool `json:"FULL_DUPLEX,omitempty"`
						HeaderChecksum bool `json:"HEADER_CHECKSUM,omitempty"`
						Unknown0001    bool `json:"UNKNOWN_0001,omitempty"`
						Unknown0040    bool `json:"UNKNOWN_0040,omitempty"`
					} `json:"global_service_options,omitempty"`
					NSNServiceVersions struct {
						Authentication string `json:"authentication,omitempty"`
						DataIntegrity  string `json:"data_integrity,omitempty"`
						Encryption     string `json:"encryption,omitempty"`
						Supervisor     string `json:"supervisor,omitempty"`
					} `json:"nsn_service_versions,omitempty"`
				} `json:"oracle,omitempty"`
				Ssh struct {
					Banner                    string   `json:"banner"`
					ClientToServerCiphers     []string `json:"client_to_server_ciphers"`
					ClientToServerCompression []string `json:"client_to_server_compression"`
					ClientToServerMacs        []string `json:"client_to_server_macs"`
					HostKeyAlgorithms         []string `json:"host_key_algorithms"`
					KexAlgorithms             []string `json:"kex_algorithms"`
					Key                       struct {
						Algorithm         string `json:"algorithm"`
						FingerprintSha256 string `json:"fingerprint_sha256"`
					} `json:"key"`
					ServerToClientCiphers     []string `json:"server_to_client_ciphers"`
					ServerToClientCompression []string `json:"server_to_client_compression"`
					ServerToClientMacs        []string `json:"server_to_client_macs"`
					Software                  string   `json:"software"`
					Version                   string   `json:"version"`
				} `json:"ssh,omitempty"`
				Http struct {
					Body struct {
						MurmurHash int    `json:"murmur_hash"`
						Sha256Hash string `json:"sha256_hash"`
					} `json:"body"`
					Component     []string `json:"component"`
					ContentLength int      `json:"content_length"`
					Favicon       struct {
					} `json:"favicon"`
					Headers struct {
						ContentType []string `json:"content_type"`
						Date        []string `json:"date"`
						Server      []string `json:"server"`
						XPoweredBy  []string `json:"x_powered_by"`
					} `json:"headers"`
					Protocol         string   `json:"protocol"`
					StatusCode       int      `json:"status_code"`
					TransferEncoding []string `json:"transfer_encoding"`
				} `json:"http,omitempty"`
				Tls struct {
					Certificate struct {
						Extensions struct {
							AuthorityInfoAccess struct {
								IssuerUrls []string `json:"issuer_urls"`
								OcspUrls   []string `json:"ocsp_urls"`
							} `json:"authority_info_access"`
							AuthorityKeyId   string `json:"authority_key_id"`
							BasicConstraints struct {
								IsCa bool `json:"is_ca"`
							} `json:"basic_constraints"`
							CertificatePolicies []struct {
								Cps []string `json:"cps,omitempty"`
								Id  string   `json:"id"`
							} `json:"certificate_policies"`
							ExtendedKeyUsage struct {
								Any                            bool `json:"any"`
								AppleCodeSigning               bool `json:"apple_code_signing"`
								AppleCodeSigningDevelopment    bool `json:"apple_code_signing_development"`
								AppleCodeSigningThirdParty     bool `json:"apple_code_signing_third_party"`
								AppleCryptoDevelopmentEnv      bool `json:"apple_crypto_development_env"`
								AppleCryptoEnv                 bool `json:"apple_crypto_env"`
								AppleCryptoMaintenanceEnv      bool `json:"apple_crypto_maintenance_env"`
								AppleCryptoProductionEnv       bool `json:"apple_crypto_production_env"`
								AppleCryptoQos                 bool `json:"apple_crypto_qos"`
								AppleCryptoTestEnv             bool `json:"apple_crypto_test_env"`
								AppleCryptoTier0Qos            bool `json:"apple_crypto_tier0_qos"`
								AppleCryptoTier1Qos            bool `json:"apple_crypto_tier1_qos"`
								AppleCryptoTier2Qos            bool `json:"apple_crypto_tier2_qos"`
								AppleCryptoTier3Qos            bool `json:"apple_crypto_tier3_qos"`
								AppleIchatEncryption           bool `json:"apple_ichat_encryption"`
								AppleIchatSigning              bool `json:"apple_ichat_signing"`
								AppleResourceSigning           bool `json:"apple_resource_signing"`
								AppleSoftwareUpdateSigning     bool `json:"apple_software_update_signing"`
								AppleSystemIdentity            bool `json:"apple_system_identity"`
								ClientAuth                     bool `json:"client_auth"`
								CodeSigning                    bool `json:"code_signing"`
								Dvcs                           bool `json:"dvcs"`
								EapOverLan                     bool `json:"eap_over_lan"`
								EapOverPpp                     bool `json:"eap_over_ppp"`
								EmailProtection                bool `json:"email_protection"`
								IpsecEndSystem                 bool `json:"ipsec_end_system"`
								IpsecIntermediateSystemUsage   bool `json:"ipsec_intermediate_system_usage"`
								IpsecTunnel                    bool `json:"ipsec_tunnel"`
								IpsecUser                      bool `json:"ipsec_user"`
								MicrosoftCaExchange            bool `json:"microsoft_ca_exchange"`
								MicrosoftCertTrustListSigning  bool `json:"microsoft_cert_trust_list_signing"`
								MicrosoftCspSignature          bool `json:"microsoft_csp_signature"`
								MicrosoftDocumentSigning       bool `json:"microsoft_document_signing"`
								MicrosoftDrm                   bool `json:"microsoft_drm"`
								MicrosoftDrmIndividualization  bool `json:"microsoft_drm_individualization"`
								MicrosoftEfsRecovery           bool `json:"microsoft_efs_recovery"`
								MicrosoftEmbeddedNtCrypto      bool `json:"microsoft_embedded_nt_crypto"`
								MicrosoftEncryptedFileSystem   bool `json:"microsoft_encrypted_file_system"`
								MicrosoftEnrollmentAgent       bool `json:"microsoft_enrollment_agent"`
								MicrosoftKernelModeCodeSigning bool `json:"microsoft_kernel_mode_code_signing"`
								MicrosoftKeyRecovery21         bool `json:"microsoft_key_recovery_21"`
								MicrosoftKeyRecovery3          bool `json:"microsoft_key_recovery_3"`
								MicrosoftLicenseServer         bool `json:"microsoft_license_server"`
								MicrosoftLicenses              bool `json:"microsoft_licenses"`
								MicrosoftLifetimeSigning       bool `json:"microsoft_lifetime_signing"`
								MicrosoftMobileDeviceSoftware  bool `json:"microsoft_mobile_device_software"`
								MicrosoftNt5Crypto             bool `json:"microsoft_nt5_crypto"`
								MicrosoftOemWhqlCrypto         bool `json:"microsoft_oem_whql_crypto"`
								MicrosoftQualifiedSubordinate  bool `json:"microsoft_qualified_subordinate"`
								MicrosoftRootListSigner        bool `json:"microsoft_root_list_signer"`
								MicrosoftServerGatedCrypto     bool `json:"microsoft_server_gated_crypto"`
								MicrosoftSgcSerialized         bool `json:"microsoft_sgc_serialized"`
								MicrosoftSmartDisplay          bool `json:"microsoft_smart_display"`
								MicrosoftSmartcardLogon        bool `json:"microsoft_smartcard_logon"`
								MicrosoftSystemHealth          bool `json:"microsoft_system_health"`
								MicrosoftSystemHealthLoophole  bool `json:"microsoft_system_health_loophole"`
								MicrosoftTimestampSigning      bool `json:"microsoft_timestamp_signing"`
								MicrosoftWhqlCrypto            bool `json:"microsoft_whql_crypto"`
								NetscapeServerGatedCrypto      bool `json:"netscape_server_gated_crypto"`
								OcspSigning                    bool `json:"ocsp_signing"`
								SbgpCertAaServiceAuth          bool `json:"sbgp_cert_aa_service_auth"`
								ServerAuth                     bool `json:"server_auth"`
								TimeStamping                   bool `json:"time_stamping"`
							} `json:"extended_key_usage"`
							KeyUsage struct {
								CertificateSign   bool `json:"certificate_sign"`
								ContentCommitment bool `json:"content_commitment"`
								CrlSign           bool `json:"crl_sign"`
								DataEncipherment  bool `json:"data_encipherment"`
								DecipherOnly      bool `json:"decipher_only"`
								DigitalSignature  bool `json:"digital_signature"`
								EncipherOnly      bool `json:"encipher_only"`
								KeyAgreement      bool `json:"key_agreement"`
								KeyEncipherment   bool `json:"key_encipherment"`
							} `json:"key_usage"`
							SubjectAltName struct {
								DnsNames []string `json:"dns_names"`
							} `json:"subject_alt_name"`
							SubjectKeyId string `json:"subject_key_id"`
						} `json:"extensions"`
						FingerprintMd5    string `json:"fingerprint_md5"`
						FingerprintSha1   string `json:"fingerprint_sha1"`
						FingerprintSha256 string `json:"fingerprint_sha256"`
						Issuer            struct {
							CommonName   []string `json:"common_name"`
							Country      []string `json:"country"`
							Locality     []string `json:"locality"`
							Organization []string `json:"organization"`
							Province     []string `json:"province"`
						} `json:"issuer"`
						Jarm       string `json:"jarm"`
						Redacted   bool   `json:"redacted"`
						Revocation struct {
							Ocsp struct {
								Reason  string `json:"reason"`
								Revoked bool   `json:"revoked"`
							} `json:"ocsp"`
						} `json:"revocation"`
						SerialNumber string `json:"serial_number"`
						Signature    struct {
							Algorithm struct {
								Name string `json:"name"`
								Oid  string `json:"oid"`
							} `json:"algorithm"`
							SelfSigned bool `json:"self_signed"`
						} `json:"signature"`
						SignedCertificateTimestamps []struct {
							EntryType string `json:"entry_type"`
							LogId     string `json:"log_id"`
							Signature struct {
								Algorithm     string `json:"algorithm"`
								HashAlgorithm string `json:"hash_algorithm"`
								Value         string `json:"value"`
							} `json:"signature"`
							Timestamp string `json:"timestamp"`
							Version   string `json:"version"`
						} `json:"signed_certificate_timestamps"`
						SignedCertificateTimestampsOid string `json:"signed_certificate_timestamps_oid"`
						Subject                        struct {
							CommonName []string `json:"common_name"`
						} `json:"subject"`
						SubjectAltName struct {
							DnsNames         []string `json:"dns_names"`
							ExtendedDnsNames []struct {
								Domain    string `json:"domain"`
								Fld       string `json:"fld"`
								Subdomain string `json:"subdomain"`
								Tld       string `json:"tld"`
							} `json:"extended_dns_names"`
						} `json:"subject_alt_name"`
						SubjectKeyInfo struct {
							Key string `json:"_key"`
							Dh  struct {
							} `json:"dh"`
							Dsa struct {
							} `json:"dsa"`
							Ecdsa struct {
							} `json:"ecdsa"`
							FingerprintSha256 string `json:"fingerprint_sha256"`
							KeyAlgorithm      string `json:"key_algorithm"`
							Rsa               struct {
								Exponent int `json:"exponent"`
								Length   int `json:"length"`
							} `json:"rsa"`
						} `json:"subject_key_info"`
						TbsFingerprint     string `json:"tbs_fingerprint"`
						TbsNoctFingerprint string `json:"tbs_noct_fingerprint"`
						ValidationLevel    string `json:"validation_level"`
						Validity           struct {
							LengthSeconds int    `json:"length_seconds"`
							NotAfter      string `json:"not_after"`
							NotBefore     string `json:"not_before"`
						} `json:"validity"`
						Version int `json:"version"`
					} `json:"certificate"`
					FingerprintSha256 string   `json:"fingerprint_sha256"`
					Precert           bool     `json:"precert"`
					Tags              []string `json:"tags"`
				} `json:"tls,omitempty"`
			} `json:"modules"`
			Name      string `json:"name"`
			Port      int    `json:"port"`
			Product   string `json:"product"`
			Protocol  string `json:"protocol"`
			Softwares []struct {
				Edition  string `json:"edition"`
				Language string `json:"language"`
				Part     string `json:"part"`
				Product  string `json:"product"`
				Update   string `json:"update"`
				Uri      string `json:"uri"`
				Vendor   string `json:"vendor"`
				Version  string `json:"version"`
			} `json:"softwares"`
			Tunnel  string `json:"tunnel"`
			Version string `json:"version"`
		} `json:"services"`
		ServicesHash string `json:"services_hash"`
		Tags         []struct {
			LastUpdatedAt time.Time `json:"last_updated_at"`
			Name          string    `json:"name"`
			PrettyName    string    `json:"pretty_name"`
			Value         bool      `json:"value"`
		} `json:"tags"`
		Whois struct {
			Encoding struct {
				Raw string `json:"raw"`
			} `json:"_encoding"`
			Descr        any    `json:"descr"`
			Network      string `json:"network"`
			Organization any    `json:"organization"`
			Raw          any    `json:"raw"`
		} `json:"whois"`
		WhoisUpdatedAt any `json:"whois_updated_at"`
	} `json:"data"`
}

type IpCveDetails struct {
	Exploit []struct {
		Description string `json:"description"`
		File        string `json:"file"`
		Id          string `json:"id"`
		Platform    string `json:"platform"`
		Type        string `json:"type"`
		Url         string `json:"url"`
	} `json:"exploit"`
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
	Asn struct {
		CountryCode  *string `json:"country_code"`
		Number       string  `json:"number"`
		Organization string  `json:"organization"`
	} `json:"asn"`
	AsnUpdatedAt time.Time `json:"asn_updated_at"`
	Banner       []any     `json:"banner"`
	Domains      any       `json:"domains"`
	Hostnames    []struct {
		LastUpdatedAt time.Time `json:"last_updated_at"`
		Name          string    `json:"name"`
	} `json:"hostnames"`
	Ip            string    `json:"ip"`
	IsIpv4        bool      `json:"is_ipv4"`
	IsIpv6        bool      `json:"is_ipv6"`
	IsVuln        bool      `json:"is_vuln"`
	LastUpdatedAt time.Time `json:"last_updated_at"`
	Location      struct {
		City        *string `json:"city"`
		Continent   string  `json:"continent"`
		Coordinates struct {
			Latitude  string `json:"latitude"`
			Longitude string `json:"longitude"`
		} `json:"coordinates"`
		CountryCode string  `json:"country_code"`
		CountryName string  `json:"country_name"`
		GeoPoint    string  `json:"geo_point"`
		LocaleCode  string  `json:"locale_code"`
		Network     string  `json:"network"`
		PostalCode  *string `json:"postal_code"`
	} `json:"location"`
	LocationUpdatedAt time.Time `json:"location_updated_at"`
	ScanId            int       `json:"scan_id"`
	Services          []struct {
		Meta struct {
			Category string `json:"category"`
			Desc     string `json:"desc"`
			Name     string `json:"name"`
			Tags     any    `json:"tags"`
		} `json:"_meta"`
		Cve           any       `json:"cve"`
		ExtraInfo     string    `json:"extra_info"`
		LastUpdatedAt time.Time `json:"last_updated_at"`
		Modules       struct {
			Zookeeper struct {
				Clients   []any  `json:"clients"`
				Mode      string `json:"mode"`
				NodeCount string `json:"node_count"`
				Version   string `json:"version"`
				Zxid      string `json:"zxid"`
			} `json:"zookeeper,omitempty"`
		} `json:"modules"`
		Name      string `json:"name"`
		Port      int    `json:"port"`
		Product   string `json:"product"`
		Protocol  string `json:"protocol"`
		Softwares []any  `json:"softwares"`
		Tunnel    string `json:"tunnel"`
		Version   string `json:"version"`
	} `json:"services"`
	ServicesHash string `json:"services_hash"`
	Tags         []struct {
		LastUpdatedAt time.Time `json:"last_updated_at"`
		Name          string    `json:"name"`
		PrettyName    string    `json:"pretty_name"`
		Value         bool      `json:"value"`
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
	WhoisUpdatedAt time.Time `json:"whois_updated_at"`
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
