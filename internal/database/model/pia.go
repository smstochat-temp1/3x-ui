package model

const (
	PiaAuthUnknown  = "unknown"
	PiaAuthValid    = "valid"
	PiaAuthExpired  = "expired"
	PiaAuthRejected = "rejected"
	PiaAuthError    = "error"

	PiaEgressDraft        = "draft"
	PiaEgressNeedsAuth    = "needs_auth"
	PiaEgressProvisioning = "provisioning"
	PiaEgressReady        = "ready"
	PiaEgressError        = "error"
	PiaEgressDisabled     = "disabled"
	PiaEgressUncertain    = "provision_uncertain"

	PiaSelectionPinned = "pinned_server"
	PiaIPv6Block       = "block"
	PiaIPv6DirectWarn  = "direct_with_warning"
	PiaScopeLocal      = "local"

	PiaCatalogParserVersion = 1
	PiaBindingActiveSlot    = 1
)

type PiaProfile struct {
	Id                   int    `json:"id" gorm:"primaryKey;autoIncrement"`
	UID                  string `json:"uid" gorm:"column:uid;uniqueIndex;size:36"`
	Name                 string `json:"name" gorm:"size:128"`
	AccountHint          string `json:"accountHint" gorm:"column:account_hint;size:64"`
	TokenCiphertext      string `json:"-" gorm:"column:token_ciphertext;type:text"`
	TokenExpiresAt       int64  `json:"tokenExpiresAt" gorm:"column:token_expires_at"`
	AuthStatus           string `json:"authStatus" gorm:"column:auth_status;size:32;default:unknown"`
	LastAuthenticatedAt  int64  `json:"lastAuthenticatedAt" gorm:"column:last_authenticated_at"`
	LastAuthErrorCode    string `json:"lastAuthErrorCode" gorm:"column:last_auth_error_code;size:64"`
	LastAuthErrorMessage string `json:"lastAuthErrorMessage" gorm:"column:last_auth_error_message;size:256"`
	Enabled              bool   `json:"enabled" gorm:"default:true"`
	Revision             int    `json:"revision" gorm:"default:1"`
	CreatedAt            int64  `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt            int64  `json:"updatedAt" gorm:"autoUpdateTime"`
}

func (PiaProfile) TableName() string { return "pia_profiles" }

type PiaEgress struct {
	Id               int    `json:"id" gorm:"primaryKey;autoIncrement"`
	UID              string `json:"uid" gorm:"column:uid;uniqueIndex;size:36"`
	ProfileID        int    `json:"profileId" gorm:"column:profile_id;index"`
	Name             string `json:"name" gorm:"size:128"`
	OutboundTag      string `json:"outboundTag" gorm:"column:outbound_tag;uniqueIndex;size:64"`
	SelectionMode    string `json:"selectionMode" gorm:"column:selection_mode;size:32;default:pinned_server"`
	RegionID         string `json:"regionId" gorm:"column:region_id;index;size:64"`
	RegionName       string `json:"regionName" gorm:"column:region_name;size:128"`
	ServerHostname   string `json:"serverHostname" gorm:"column:server_hostname;size:255"`
	ServerIP         string `json:"serverIp" gorm:"column:server_ip;size:64"`
	Enabled          bool   `json:"enabled" gorm:"default:true"`
	MTU              int    `json:"mtu" gorm:"default:1420"`
	KeepaliveSeconds int    `json:"keepaliveSeconds" gorm:"column:keepalive_seconds;default:25"`
	IPv6Policy       string `json:"ipv6Policy" gorm:"column:ipv6_policy;size:32;default:block"`
	NodeScope        string `json:"nodeScope" gorm:"column:node_scope;size:16;default:local"`
	Status           string `json:"status" gorm:"size:32;default:draft"`
	LastErrorCode    string `json:"lastErrorCode" gorm:"column:last_error_code;size:64"`
	LastErrorMessage string `json:"lastErrorMessage" gorm:"column:last_error_message;size:256"`
	DesiredRevision  int    `json:"desiredRevision" gorm:"column:desired_revision;default:1"`
	AppliedRevision  int    `json:"appliedRevision" gorm:"column:applied_revision;default:0"`
	CreatedAt        int64  `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt        int64  `json:"updatedAt" gorm:"autoUpdateTime"`
}

func (PiaEgress) TableName() string { return "pia_egresses" }

type PiaBinding struct {
	Id                   int    `json:"id" gorm:"primaryKey;autoIncrement"`
	UID                  string `json:"uid" gorm:"column:uid;uniqueIndex;size:36"`
	EgressID             int    `json:"egressId" gorm:"column:egress_id;uniqueIndex:ux_pia_binding_active"`
	NodeID               *int   `json:"nodeId,omitempty" gorm:"column:node_id;index"`
	ScopeKey             string `json:"scopeKey" gorm:"column:scope_key;size:64;uniqueIndex:ux_pia_binding_active"`
	ActiveSlot           *int   `json:"-" gorm:"column:active_slot;uniqueIndex:ux_pia_binding_active"`
	PrivateKeyCiphertext string `json:"-" gorm:"column:private_key_ciphertext;type:text"`
	PublicKey            string `json:"publicKey" gorm:"column:public_key;size:64"`
	PeerIP               string `json:"peerIp" gorm:"column:peer_ip;size:64"`
	ServerPublicKey      string `json:"serverPublicKey" gorm:"column:server_public_key;size:64"`
	ServerIP             string `json:"serverIp" gorm:"column:server_ip;size:64"`
	ServerHostname       string `json:"serverHostname" gorm:"column:server_hostname;size:255"`
	ServerPort           int    `json:"serverPort" gorm:"column:server_port"`
	DNSServersJSON       string `json:"dnsServers" gorm:"column:dns_servers_json;type:text"`
	CatalogDigest        string `json:"catalogDigest" gorm:"column:catalog_digest;size:128"`
	State                string `json:"state" gorm:"size:32;default:ready"`
	ProvisionedAt        int64  `json:"provisionedAt" gorm:"column:provisioned_at"`
	LastAppliedAt        int64  `json:"lastAppliedAt" gorm:"column:last_applied_at"`
	LastTestedAt         int64  `json:"lastTestedAt" gorm:"column:last_tested_at"`
	LastLatencyMs        int    `json:"lastLatencyMs" gorm:"column:last_latency_ms"`
	LastExternalIP       string `json:"lastExternalIp" gorm:"column:last_external_ip;size:64"`
	LastErrorCode        string `json:"lastErrorCode" gorm:"column:last_error_code;size:64"`
	LastErrorMessage     string `json:"lastErrorMessage" gorm:"column:last_error_message;size:256"`
	Generation           int    `json:"generation" gorm:"default:1"`
	Active               bool   `json:"active" gorm:"default:true"`
	CreatedAt            int64  `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt            int64  `json:"updatedAt" gorm:"autoUpdateTime"`
}

func (PiaBinding) TableName() string { return "pia_bindings" }

type PiaCatalogSnapshot struct {
	Id                int    `json:"id" gorm:"primaryKey;autoIncrement"`
	PayloadJSON       string `json:"-" gorm:"column:payload_json;type:text"`
	PayloadSHA256     string `json:"payloadSha256" gorm:"column:payload_sha256;size:64"`
	SignatureVerified bool   `json:"signatureVerified" gorm:"column:signature_verified"`
	FetchedAt         int64  `json:"fetchedAt" gorm:"column:fetched_at"`
	ParserVersion     int    `json:"parserVersion" gorm:"column:parser_version"`
	RegionCount       int    `json:"regionCount" gorm:"column:region_count"`
	ServerCount       int    `json:"serverCount" gorm:"column:server_count"`
	Schema            string `json:"schema" gorm:"size:16"`
	LastErrorCode     string `json:"lastErrorCode" gorm:"column:last_error_code;size:64"`
	LastErrorMessage  string `json:"lastErrorMessage" gorm:"column:last_error_message;size:256"`
	UpdatedAt         int64  `json:"updatedAt" gorm:"autoUpdateTime"`
}

func (PiaCatalogSnapshot) TableName() string { return "pia_catalog_snapshots" }
