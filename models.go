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
					Banner                    string   `json:"banner,omitempty"`
					ClientToServerCiphers     []string `json:"client_to_server_ciphers,omitempty"`
					ClientToServerCompression []string `json:"client_to_server_compression,omitempty"`
					ClientToServerMacs        []string `json:"client_to_server_macs,omitempty"`
					HostKeyAlgorithms         []string `json:"host_key_algorithms,omitempty"`
					KexAlgorithms             []string `json:"kex_algorithms,omitempty"`
					Key                       struct {
						Algorithm         string `json:"algorithm,omitempty"`
						FingerprintSha256 string `json:"fingerprint_sha256,omitempty"`
					} `json:"key,omitempty"`
					ServerToClientCiphers     []string `json:"server_to_client_ciphers,omitempty"`
					ServerToClientCompression []string `json:"server_to_client_compression,omitempty"`
					ServerToClientMacs        []string `json:"server_to_client_macs,omitempty"`
					Software                  string   `json:"software,omitempty"`
					Version                   string   `json:"version,omitempty"`
				} `json:"ssh,omitempty"`
				Http struct {
					Body struct {
						MurmurHash int    `json:"murmur_hash,omitempty"`
						Sha256Hash string `json:"sha256_hash,omitempty"`
					} `json:"body,omitempty"`
					Component     []string `json:"component,omitempty"`
					ContentLength int      `json:"content_length,omitempty"`
					Favicon       struct {
					} `json:"favicon,omitempty"`
					Headers struct {
						ContentType []string `json:"content_type,omitempty"`
						Date        []string `json:"date,omitempty"`
						Server      []string `json:"server,omitempty"`
						XPoweredBy  []string `json:"x_powered_by,omitempty"`
					} `json:"headers,omitempty"`
					Protocol         string   `json:"protocol,omitempty"`
					StatusCode       int      `json:"status_code,omitempty"`
					TransferEncoding []string `json:"transfer_encoding,omitempty"`
				} `json:"http,omitempty"`
				Tls struct {
					Certificate struct {
						Extensions struct {
							AuthorityInfoAccess struct {
								IssuerUrls []string `json:"issuer_urls,omitempty"`
								OcspUrls   []string `json:"ocsp_urls,omitempty"`
							} `json:"authority_info_access,omitempty"`
							AuthorityKeyId   string `json:"authority_key_id,omitempty"`
							BasicConstraints struct {
								IsCa bool `json:"is_ca,omitempty"`
							} `json:"basic_constraints,omitempty"`
							CertificatePolicies []struct {
								Cps []string `json:"cps,omitempty"`
								Id  string   `json:"id,omitempty"`
							} `json:"certificate_policies,omitempty"`
							ExtendedKeyUsage struct {
								Any                            bool `json:"any,omitempty"`
								AppleCodeSigning               bool `json:"apple_code_signing,omitempty"`
								AppleCodeSigningDevelopment    bool `json:"apple_code_signing_development,omitempty"`
								AppleCodeSigningThirdParty     bool `json:"apple_code_signing_third_party,omitempty"`
								AppleCryptoDevelopmentEnv      bool `json:"apple_crypto_development_env,omitempty"`
								AppleCryptoEnv                 bool `json:"apple_crypto_env,omitempty"`
								AppleCryptoMaintenanceEnv      bool `json:"apple_crypto_maintenance_env,omitempty"`
								AppleCryptoProductionEnv       bool `json:"apple_crypto_production_env,omitempty"`
								AppleCryptoQos                 bool `json:"apple_crypto_qos,omitempty"`
								AppleCryptoTestEnv             bool `json:"apple_crypto_test_env,omitempty"`
								AppleCryptoTier0Qos            bool `json:"apple_crypto_tier0_qos,omitempty"`
								AppleCryptoTier1Qos            bool `json:"apple_crypto_tier1_qos,omitempty"`
								AppleCryptoTier2Qos            bool `json:"apple_crypto_tier2_qos,omitempty"`
								AppleCryptoTier3Qos            bool `json:"apple_crypto_tier3_qos,omitempty"`
								AppleIchatEncryption           bool `json:"apple_ichat_encryption,omitempty"`
								AppleIchatSigning              bool `json:"apple_ichat_signing,omitempty"`
								AppleResourceSigning           bool `json:"apple_resource_signing,omitempty"`
								AppleSoftwareUpdateSigning     bool `json:"apple_software_update_signing,omitempty"`
								AppleSystemIdentity            bool `json:"apple_system_identity,omitempty"`
								ClientAuth                     bool `json:"client_auth,omitempty"`
								CodeSigning                    bool `json:"code_signing,omitempty"`
								Dvcs                           bool `json:"dvcs,omitempty"`
								EapOverLan                     bool `json:"eap_over_lan,omitempty"`
								EapOverPpp                     bool `json:"eap_over_ppp,omitempty"`
								EmailProtection                bool `json:"email_protection,omitempty"`
								IpsecEndSystem                 bool `json:"ipsec_end_system,omitempty"`
								IpsecIntermediateSystemUsage   bool `json:"ipsec_intermediate_system_usage,omitempty"`
								IpsecTunnel                    bool `json:"ipsec_tunnel,omitempty"`
								IpsecUser                      bool `json:"ipsec_user,omitempty"`
								MicrosoftCaExchange            bool `json:"microsoft_ca_exchange,omitempty"`
								MicrosoftCertTrustListSigning  bool `json:"microsoft_cert_trust_list_signing,omitempty"`
								MicrosoftCspSignature          bool `json:"microsoft_csp_signature,omitempty"`
								MicrosoftDocumentSigning       bool `json:"microsoft_document_signing,omitempty"`
								MicrosoftDrm                   bool `json:"microsoft_drm,omitempty"`
								MicrosoftDrmIndividualization  bool `json:"microsoft_drm_individualization,omitempty"`
								MicrosoftEfsRecovery           bool `json:"microsoft_efs_recovery,omitempty"`
								MicrosoftEmbeddedNtCrypto      bool `json:"microsoft_embedded_nt_crypto,omitempty"`
								MicrosoftEncryptedFileSystem   bool `json:"microsoft_encrypted_file_system,omitempty"`
								MicrosoftEnrollmentAgent       bool `json:"microsoft_enrollment_agent,omitempty"`
								MicrosoftKernelModeCodeSigning bool `json:"microsoft_kernel_mode_code_signing,omitempty"`
								MicrosoftKeyRecovery21         bool `json:"microsoft_key_recovery_21,omitempty"`
								MicrosoftKeyRecovery3          bool `json:"microsoft_key_recovery_3,omitempty"`
								MicrosoftLicenseServer         bool `json:"microsoft_license_server,omitempty"`
								MicrosoftLicenses              bool `json:"microsoft_licenses,omitempty"`
								MicrosoftLifetimeSigning       bool `json:"microsoft_lifetime_signing,omitempty"`
								MicrosoftMobileDeviceSoftware  bool `json:"microsoft_mobile_device_software,omitempty"`
								MicrosoftNt5Crypto             bool `json:"microsoft_nt5_crypto,omitempty"`
								MicrosoftOemWhqlCrypto         bool `json:"microsoft_oem_whql_crypto,omitempty"`
								MicrosoftQualifiedSubordinate  bool `json:"microsoft_qualified_subordinate,omitempty"`
								MicrosoftRootListSigner        bool `json:"microsoft_root_list_signer,omitempty"`
								MicrosoftServerGatedCrypto     bool `json:"microsoft_server_gated_crypto,omitempty"`
								MicrosoftSgcSerialized         bool `json:"microsoft_sgc_serialized,omitempty"`
								MicrosoftSmartDisplay          bool `json:"microsoft_smart_display,omitempty"`
								MicrosoftSmartcardLogon        bool `json:"microsoft_smartcard_logon,omitempty"`
								MicrosoftSystemHealth          bool `json:"microsoft_system_health,omitempty"`
								MicrosoftSystemHealthLoophole  bool `json:"microsoft_system_health_loophole,omitempty"`
								MicrosoftTimestampSigning      bool `json:"microsoft_timestamp_signing,omitempty"`
								MicrosoftWhqlCrypto            bool `json:"microsoft_whql_crypto,omitempty"`
								NetscapeServerGatedCrypto      bool `json:"netscape_server_gated_crypto,omitempty"`
								OcspSigning                    bool `json:"ocsp_signing,omitempty"`
								SbgpCertAaServiceAuth          bool `json:"sbgp_cert_aa_service_auth,omitempty"`
								ServerAuth                     bool `json:"server_auth,omitempty"`
								TimeStamping                   bool `json:"time_stamping,omitempty"`
							} `json:"extended_key_usage,omitempty"`
							KeyUsage struct {
								CertificateSign   bool `json:"certificate_sign,omitempty"`
								ContentCommitment bool `json:"content_commitment,omitempty"`
								CrlSign           bool `json:"crl_sign,omitempty"`
								DataEncipherment  bool `json:"data_encipherment,omitempty"`
								DecipherOnly      bool `json:"decipher_only,omitempty"`
								DigitalSignature  bool `json:"digital_signature,omitempty"`
								EncipherOnly      bool `json:"encipher_only,omitempty"`
								KeyAgreement      bool `json:"key_agreement,omitempty"`
								KeyEncipherment   bool `json:"key_encipherment,omitempty"`
							} `json:"key_usage,omitempty"`
							SubjectAltName struct {
								DnsNames []string `json:"dns_names,omitempty"`
							} `json:"subject_alt_name,omitempty"`
							SubjectKeyId string `json:"subject_key_id,omitempty"`
						} `json:"extensions,omitempty"`
						FingerprintMd5    string `json:"fingerprint_md5,omitempty"`
						FingerprintSha1   string `json:"fingerprint_sha1,omitempty"`
						FingerprintSha256 string `json:"fingerprint_sha256,omitempty"`
						Issuer            struct {
							CommonName   []string `json:"common_name,omitempty"`
							Country      []string `json:"country,omitempty"`
							Locality     []string `json:"locality,omitempty"`
							Organization []string `json:"organization,omitempty"`
							Province     []string `json:"province,omitempty"`
						} `json:"issuer,omitempty"`
						Jarm       string `json:"jarm,omitempty"`
						Redacted   bool   `json:"redacted,omitempty"`
						Revocation struct {
							Ocsp struct {
								Reason  string `json:"reason,omitempty"`
								Revoked bool   `json:"revoked,omitempty"`
							} `json:"ocsp,omitempty"`
						} `json:"revocation,omitempty"`
						SerialNumber string `json:"serial_number,omitempty"`
						Signature    struct {
							Algorithm struct {
								Name string `json:"name,omitempty"`
								Oid  string `json:"oid,omitempty"`
							} `json:"algorithm,omitempty"`
							SelfSigned bool `json:"self_signed,omitempty"`
						} `json:"signature,omitempty"`
						SignedCertificateTimestamps []struct {
							EntryType string `json:"entry_type,omitempty"`
							LogId     string `json:"log_id,omitempty"`
							Signature struct {
								Algorithm     string `json:"algorithm,omitempty"`
								HashAlgorithm string `json:"hash_algorithm,omitempty"`
								Value         string `json:"value,omitempty"`
							} `json:"signature,omitempty"`
							Timestamp string `json:"timestamp,omitempty"`
							Version   string `json:"version,omitempty"`
						} `json:"signed_certificate_timestamps,omitempty"`
						SignedCertificateTimestampsOid string `json:"signed_certificate_timestamps_oid,omitempty"`
						Subject                        struct {
							CommonName []string `json:"common_name,omitempty"`
						} `json:"subject,omitempty"`
						SubjectAltName struct {
							DnsNames         []string `json:"dns_names,omitempty"`
							ExtendedDnsNames []struct {
								Domain    string `json:"domain,omitempty"`
								Fld       string `json:"fld,omitempty"`
								Subdomain string `json:"subdomain,omitempty"`
								Tld       string `json:"tld,omitempty"`
							} `json:"extended_dns_names,omitempty"`
						} `json:"subject_alt_name,omitempty"`
						SubjectKeyInfo struct {
							Key string `json:"_key,omitempty"`
							Dh  struct {
							} `json:"dh,omitempty"`
							Dsa struct {
							} `json:"dsa,omitempty"`
							Ecdsa struct {
							} `json:"ecdsa,omitempty"`
							FingerprintSha256 string `json:"fingerprint_sha256,omitempty"`
							KeyAlgorithm      string `json:"key_algorithm,omitempty"`
							Rsa               struct {
								Exponent int `json:"exponent,omitempty"`
								Length   int `json:"length,omitempty"`
							} `json:"rsa,omitempty"`
						} `json:"subject_key_info,omitempty"`
						TbsFingerprint     string `json:"tbs_fingerprint,omitempty"`
						TbsNoctFingerprint string `json:"tbs_noct_fingerprint,omitempty"`
						ValidationLevel    string `json:"validation_level,omitempty"`
						Validity           struct {
							LengthSeconds int    `json:"length_seconds,omitempty"`
							NotAfter      string `json:"not_after,omitempty"`
							NotBefore     string `json:"not_before,omitempty"`
						} `json:"validity,omitempty"`
						Version int `json:"version,omitempty"`
					} `json:"certificate,omitempty"`
					FingerprintSha256 string   `json:"fingerprint_sha256,omitempty"`
					Precert           bool     `json:"precert,omitempty"`
					Tags              []string `json:"tags,omitempty"`
				} `json:"tls,omitempty"`
			} `json:"modules,omitempty"`
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
