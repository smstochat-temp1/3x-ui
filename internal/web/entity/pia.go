package entity

type PiaErrorInfo struct {
	Code        string `json:"code" example:"pia_invalid_credentials"`
	Retryable   bool   `json:"retryable" example:"false"`
	OperationID string `json:"operationId,omitempty" example:"provision"`
	Details     any    `json:"details,omitempty"`
}

type PiaStatusView struct {
	Enabled        bool   `json:"enabled" example:"false"`
	SecretboxReady bool   `json:"secretboxReady" example:"true"`
	EncryptionMode string `json:"encryptionMode" example:"required"`
}

type PiaProfileView struct {
	UID                  string `json:"uid" example:"a1b2c3d4e5f6"`
	Name                 string `json:"name" example:"home"`
	AccountHint          string `json:"accountHint" example:"p***34"`
	HasToken             bool   `json:"hasToken" example:"true"`
	TokenExpiresAt       int64  `json:"tokenExpiresAt" example:"1760000000"`
	AuthStatus           string `json:"authStatus" example:"valid"`
	LastAuthenticatedAt  int64  `json:"lastAuthenticatedAt" example:"1760000000"`
	LastAuthErrorCode    string `json:"lastAuthErrorCode"`
	LastAuthErrorMessage string `json:"lastAuthErrorMessage"`
	Enabled              bool   `json:"enabled" example:"true"`
	Revision             int    `json:"revision" example:"1"`
}

type PiaBindingView struct {
	UID            string `json:"uid" example:"b1c2d3e4"`
	PublicKey      string `json:"publicKey" example:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`
	PeerIP         string `json:"peerIp" example:"10.0.0.2/32"`
	ServerHostname string `json:"serverHostname" example:"useast401"`
	ServerIP       string `json:"serverIp" example:"198.51.100.10"`
	ServerPort     int    `json:"serverPort" example:"1337"`
	Generation     int    `json:"generation" example:"1"`
	Active         bool   `json:"active" example:"true"`
}

type PiaEgressView struct {
	UID              string          `json:"uid" example:"e1f2a3b4"`
	ProfileUID       string          `json:"profileUid" example:"a1b2c3d4e5f6"`
	Name             string          `json:"name" example:"US East"`
	OutboundTag      string          `json:"outboundTag" example:"pia-a1b2c3d4"`
	RegionID         string          `json:"regionId" example:"us-east"`
	RegionName       string          `json:"regionName" example:"US East"`
	ServerHostname   string          `json:"serverHostname" example:"useast401"`
	ServerIP         string          `json:"serverIp" example:"198.51.100.10"`
	Enabled          bool            `json:"enabled" example:"true"`
	MTU              int             `json:"mtu" example:"1420"`
	KeepaliveSeconds int             `json:"keepaliveSeconds" example:"25"`
	IPv6Policy       string          `json:"ipv6Policy" example:"block"`
	Status           string          `json:"status" example:"ready"`
	LastErrorCode    string          `json:"lastErrorCode"`
	LastErrorMessage string          `json:"lastErrorMessage"`
	HasActiveBinding bool            `json:"hasActiveBinding" example:"true"`
	PublicKey        string          `json:"publicKey" example:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`
	PeerIP           string          `json:"peerIp" example:"10.0.0.2/32"`
	Generation       int             `json:"generation" example:"1"`
	LastExternalIP   string          `json:"lastExternalIp"`
	LastLatencyMs    int             `json:"lastLatencyMs"`
	Binding          *PiaBindingView `json:"binding,omitempty" example:"{\"uid\":\"b1c2d3e4\",\"publicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"peerIp\":\"10.0.0.2/32\",\"serverHostname\":\"useast401\",\"serverIp\":\"198.51.100.10\",\"serverPort\":1337,\"generation\":1,\"active\":true}"`
}

type PiaCatalogStatusView struct {
	Fresh             bool   `json:"fresh" example:"true"`
	FetchedAt         int64  `json:"fetchedAt" example:"1760000000"`
	RegionCount       int    `json:"regionCount" example:"12"`
	ServerCount       int    `json:"serverCount" example:"40"`
	PayloadSHA256     string `json:"payloadSha256" example:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	LastErrorCode     string `json:"lastErrorCode"`
	LastErrorMessage  string `json:"lastErrorMessage"`
	SignatureVerified bool   `json:"signatureVerified" example:"true"`
}

type PiaRegionView struct {
	ID          string `json:"id" example:"us-east"`
	Name        string `json:"name" example:"US East"`
	CountryCode string `json:"countryCode" example:"US"`
	ServerCount int    `json:"serverCount" example:"3"`
}

type PiaServerView struct {
	Hostname string `json:"hostname" example:"useast401"`
	IP       string `json:"ip" example:"198.51.100.10"`
}

type PiaDependencyView struct {
	Kind  string `json:"kind" example:"routing_rule"`
	Label string `json:"label" example:"rule 3"`
	Field string `json:"field" example:"outboundTag"`
}
