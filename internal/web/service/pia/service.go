package pia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/secretbox"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	piaprotocol "github.com/mhsanaei/3x-ui/v3/internal/pia"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/managedoutbound"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/outbound"
)

const (
	testCooldown      = 15 * time.Second
	nsProfileToken    = "pia/profile-token"
	nsBindingPriv     = "pia/binding-private-key"
	catalogSnapshotID = 1
)

type Service struct {
	Auth      piaprotocol.Authenticator
	Catalog   piaprotocol.ServerListSource
	Registrar piaprotocol.Registrar
	Box       *secretbox.Codec
	Now       func() time.Time

	authFlight sync.Map
	catalogMu  sync.Mutex
	egressMu   sync.Map
	testLast   sync.Map
}

func Default() *Service {
	return &Service{
		Auth:      piaprotocol.NewAuthClient(piaprotocol.DefaultTokenEndpoint),
		Catalog:   piaprotocol.NewCatalogClient(piaprotocol.DefaultServerListEndpoint, piaprotocol.EmbeddedServerListPublicKey),
		Registrar: piaprotocol.NewRegistrationClient(piaprotocol.EmbeddedPIACA),
		Now:       time.Now,
	}
}

func RegisterSource() {
	managedoutbound.Register(&Source{svc: Default()})
}

type Source struct{ svc *Service }

func (s *Source) Name() string { return "pia" }

func (s *Source) Outbounds() ([]any, []string, error) {
	return s.svc.ReadyOutbounds()
}

func (s *Service) box() *secretbox.Codec {
	if s.Box != nil {
		return s.Box
	}
	return secretbox.Active()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) requireEnabled() error {
	if !config.IsPIAEnabled() {
		return piaprotocol.NewError(piaprotocol.CodeDisabled, "PIA managed egress is disabled. Set XUI_PIA_ENABLED=true.")
	}
	return nil
}

func (s *Service) requireBox() (*secretbox.Codec, error) {
	box := s.box()
	if box == nil || !box.Enabled() {
		return nil, piaprotocol.NewError(piaprotocol.CodeEncryptionRequired, "PIA requires NODE_TOKEN_ENCRYPTION=migration or required and a keyring.")
	}
	return box, nil
}

func (s *Service) Status() map[string]any {
	box := s.box()
	return map[string]any{
		"enabled":        config.IsPIAEnabled(),
		"secretboxReady": box != nil && box.Enabled(),
		"encryptionMode": config.GetNodeTokenEncryptionMode(),
	}
}

type ProfileView struct {
	UID                  string `json:"uid" example:"01j6m4q8abcd"`
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

func toProfileView(p *model.PiaProfile) ProfileView {
	return ProfileView{
		UID: p.UID, Name: p.Name, AccountHint: p.AccountHint,
		HasToken: p.TokenCiphertext != "", TokenExpiresAt: p.TokenExpiresAt,
		AuthStatus: p.AuthStatus, LastAuthenticatedAt: p.LastAuthenticatedAt,
		LastAuthErrorCode: p.LastAuthErrorCode, LastAuthErrorMessage: p.LastAuthErrorMessage,
		Enabled: p.Enabled, Revision: p.Revision,
	}
}

type EgressView struct {
	UID              string         `json:"uid" example:"01j6m4q8efgh"`
	ProfileUID       string         `json:"profileUid"`
	Name             string         `json:"name" example:"US East"`
	OutboundTag      string         `json:"outboundTag" example:"pia-a1b2c3d4"`
	RegionID         string         `json:"regionId" example:"us-east"`
	RegionName       string         `json:"regionName" example:"US East"`
	ServerHostname   string         `json:"serverHostname"`
	ServerIP         string         `json:"serverIp"`
	Enabled          bool           `json:"enabled" example:"true"`
	MTU              int            `json:"mtu" example:"1420"`
	KeepaliveSeconds int            `json:"keepaliveSeconds" example:"25"`
	IPv6Policy       string         `json:"ipv6Policy" example:"block"`
	Status           string         `json:"status" example:"ready"`
	LastErrorCode    string         `json:"lastErrorCode"`
	LastErrorMessage string         `json:"lastErrorMessage"`
	HasActiveBinding bool           `json:"hasActiveBinding" example:"true"`
	PublicKey        string         `json:"publicKey"`
	PeerIP           string         `json:"peerIp"`
	Generation       int            `json:"generation"`
	LastExternalIP   string         `json:"lastExternalIp"`
	LastLatencyMs    int            `json:"lastLatencyMs"`
	Binding          *BindingPublic `json:"binding,omitempty"`
}

type BindingPublic struct {
	UID            string `json:"uid"`
	PublicKey      string `json:"publicKey"`
	PeerIP         string `json:"peerIp"`
	ServerHostname string `json:"serverHostname"`
	ServerIP       string `json:"serverIp"`
	ServerPort     int    `json:"serverPort"`
	Generation     int    `json:"generation"`
	Active         bool   `json:"active"`
}

type CatalogStatusView struct {
	Fresh             bool   `json:"fresh"`
	FetchedAt         int64  `json:"fetchedAt"`
	RegionCount       int    `json:"regionCount"`
	ServerCount       int    `json:"serverCount"`
	PayloadSHA256     string `json:"payloadSha256"`
	LastErrorCode     string `json:"lastErrorCode"`
	LastErrorMessage  string `json:"lastErrorMessage"`
	SignatureVerified bool   `json:"signatureVerified"`
}

type RegionView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CountryCode string `json:"countryCode"`
	ServerCount int    `json:"serverCount"`
}

type ServerView struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

func (s *Service) ListProfiles() ([]ProfileView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	var rows []model.PiaProfile
	if err := database.GetDB().Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]ProfileView, 0, len(rows))
	for i := range rows {
		out = append(out, toProfileView(&rows[i]))
	}
	return out, nil
}

func (s *Service) CreateProfile(name string) (*ProfileView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Profile name is required.")
	}
	row := &model.PiaProfile{UID: newUID(), Name: name, AuthStatus: model.PiaAuthUnknown, Enabled: true, Revision: 1}
	if err := database.GetDB().Create(row).Error; err != nil {
		return nil, err
	}
	v := toProfileView(row)
	return &v, nil
}

func (s *Service) PatchProfile(uid, name string, enabled *bool) (*ProfileView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	row, err := s.profileByUID(uid)
	if err != nil {
		return nil, err
	}
	if name = strings.TrimSpace(name); name != "" {
		row.Name = name
	}
	if enabled != nil {
		row.Enabled = *enabled
	}
	row.Revision++
	if err := database.GetDB().Save(row).Error; err != nil {
		return nil, err
	}
	v := toProfileView(row)
	return &v, nil
}

func (s *Service) DeleteProfile(uid string) error {
	if err := s.requireEnabled(); err != nil {
		return err
	}
	row, err := s.profileByUID(uid)
	if err != nil {
		return err
	}
	var egresses []model.PiaEgress
	if err := database.GetDB().Where("profile_id = ?", row.Id).Find(&egresses).Error; err != nil {
		return err
	}
	for i := range egresses {
		deps, err := CollectDependencies(egresses[i].OutboundTag)
		if err != nil {
			return err
		}
		if len(deps) > 0 {
			return &ConflictError{Err: piaprotocol.NewError(piaprotocol.CodeDependencyConflict, "This PIA outbound is still referenced."), Deps: deps}
		}
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if len(egresses) > 0 {
			egressIDs := make([]int, 0, len(egresses))
			for i := range egresses {
				egressIDs = append(egressIDs, egresses[i].Id)
			}
			if err := tx.Where("egress_id IN ?", egressIDs).Delete(&model.PiaBinding{}).Error; err != nil {
				return err
			}
			if err := tx.Delete(&egresses).Error; err != nil {
				return err
			}
		}
		return tx.Delete(row).Error
	})
}

func (s *Service) Authenticate(ctx context.Context, uid, username string, password []byte) (*ProfileView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	box, err := s.requireBox()
	if err != nil {
		return nil, err
	}
	row, err := s.profileByUID(uid)
	if err != nil {
		return nil, err
	}
	unlock := s.lockKey(&s.authFlight, uid)
	defer unlock()
	tok, err := s.Auth.Authenticate(ctx, username, password)
	defer tok.Clear()
	if err != nil {
		row.AuthStatus = model.PiaAuthRejected
		if piaprotocol.CodeOf(err) != piaprotocol.CodeInvalidCredentials {
			row.AuthStatus = model.PiaAuthError
		}
		row.LastAuthErrorCode = piaprotocol.CodeOf(err)
		row.LastAuthErrorMessage = piaprotocol.MessageOf(err)
		_ = database.GetDB().Save(row).Error
		logger.Warningf("provider=pia operation=authenticate uid=%s error_code=%s", uid, piaprotocol.CodeOf(err))
		return nil, err
	}
	ct, err := box.Encrypt(secretbox.SecretRef{Namespace: nsProfileToken, RecordID: row.UID, Field: "token"}, tok.Value)
	if err != nil {
		return nil, piaprotocol.WrapError(piaprotocol.CodeEncryptionRequired, "Could not encrypt the PIA token.", err)
	}
	row.TokenCiphertext = ct
	row.TokenExpiresAt = tok.ExpiresAt.Unix()
	row.AuthStatus = model.PiaAuthValid
	row.AccountHint = accountHint(username)
	row.LastAuthenticatedAt = s.now().Unix()
	row.LastAuthErrorCode = ""
	row.LastAuthErrorMessage = ""
	row.Revision++
	if err := database.GetDB().Save(row).Error; err != nil {
		return nil, err
	}
	logger.Infof("provider=pia operation=authenticate uid=%s status=ok", uid)
	v := toProfileView(row)
	return &v, nil
}

func (s *Service) CatalogStatus() (*CatalogStatusView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	snap, _ := s.loadSnapshot()
	view := &CatalogStatusView{}
	if snap != nil {
		view.FetchedAt = snap.FetchedAt
		view.RegionCount = snap.RegionCount
		view.ServerCount = snap.ServerCount
		view.PayloadSHA256 = snap.PayloadSHA256
		view.LastErrorCode = snap.LastErrorCode
		view.LastErrorMessage = snap.LastErrorMessage
		view.SignatureVerified = snap.SignatureVerified
		age := s.now().Unix() - snap.FetchedAt
		view.Fresh = snap.SignatureVerified && age >= 0 && age < int64(piaprotocol.DefaultCatalogFreshTTL.Seconds())
	}
	return view, nil
}

func (s *Service) RefreshCatalog(ctx context.Context) (*CatalogStatusView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	if _, err := s.fetchCatalog(ctx, true); err != nil {
		return nil, err
	}
	return s.CatalogStatus()
}

func (s *Service) ListRegions(ctx context.Context) ([]RegionView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	regions, err := s.regions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RegionView, 0, len(regions))
	for _, r := range regions {
		out = append(out, RegionView{ID: r.ID, Name: r.Name, CountryCode: r.CountryCode, ServerCount: len(r.WireGuard)})
	}
	return out, nil
}

func (s *Service) ListServers(ctx context.Context, regionID string) ([]ServerView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	region, err := s.regionByID(ctx, regionID)
	if err != nil {
		return nil, err
	}
	out := make([]ServerView, 0, len(region.WireGuard))
	for _, srv := range region.WireGuard {
		out = append(out, ServerView{Hostname: srv.Hostname, IP: srv.IP.String()})
	}
	return out, nil
}

type CreateEgressInput struct {
	ProfileUID       string
	Name             string
	RegionID         string
	ServerHostname   string
	MTU              int
	KeepaliveSeconds *int
	IPv6Policy       string
}

func (s *Service) CreateEgress(ctx context.Context, in CreateEgressInput) (*EgressView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	profile, err := s.profileByUID(in.ProfileUID)
	if err != nil {
		return nil, err
	}
	region, err := s.regionByID(ctx, in.RegionID)
	if err != nil {
		return nil, err
	}
	server, err := pickServer(region, in.ServerHostname)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = region.Name
	}
	mtu, ka, ipv6, err := normalizeTunnelOpts(in.MTU, in.KeepaliveSeconds, in.IPv6Policy)
	if err != nil {
		return nil, err
	}
	uid := newUID()
	tag, err := s.allocateTag(uid)
	if err != nil {
		return nil, err
	}
	row := &model.PiaEgress{
		UID: uid, ProfileID: profile.Id, Name: name, OutboundTag: tag,
		SelectionMode: model.PiaSelectionPinned, RegionID: region.ID, RegionName: region.Name,
		ServerHostname: server.Hostname, ServerIP: server.IP.String(), Enabled: true,
		MTU: mtu, KeepaliveSeconds: ka, IPv6Policy: ipv6, NodeScope: model.PiaScopeLocal,
		Status: model.PiaEgressDraft, DesiredRevision: 1,
	}
	if profile.AuthStatus != model.PiaAuthValid || profile.TokenCiphertext == "" {
		row.Status = model.PiaEgressNeedsAuth
	}
	db := database.GetDB()
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		if in.KeepaliveSeconds != nil && ka == 0 {
			return tx.Model(row).UpdateColumn("keepalive_seconds", 0).Error
		}
		return nil
	}); err != nil {
		return nil, err
	}
	row.KeepaliveSeconds = ka
	return s.egressView(row)
}

func (s *Service) ListEgresses() ([]EgressView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	var rows []model.PiaEgress
	if err := database.GetDB().Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]EgressView, 0, len(rows))
	for i := range rows {
		v, err := s.egressView(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, nil
}

func (s *Service) GetEgress(uid string) (*EgressView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	row, err := s.egressByUID(uid)
	if err != nil {
		return nil, err
	}
	return s.egressView(row)
}

func (s *Service) PatchEgress(uid, name string, mtu int, keepalive *int, ipv6 string) (*EgressView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	row, err := s.egressByUID(uid)
	if err != nil {
		return nil, err
	}
	if name = strings.TrimSpace(name); name != "" {
		row.Name = name
	}
	if keepalive == nil {
		keepalive = &row.KeepaliveSeconds
	}
	nextMTU, nextKA, nextIPv6, err := normalizeTunnelOpts(firstPositive(mtu, row.MTU), keepalive, firstNonEmpty(ipv6, row.IPv6Policy))
	if err != nil {
		return nil, err
	}
	row.MTU, row.KeepaliveSeconds, row.IPv6Policy = nextMTU, nextKA, nextIPv6
	row.DesiredRevision++
	if err := database.GetDB().Save(row).Error; err != nil {
		return nil, err
	}
	return s.egressView(row)
}

func (s *Service) DeleteEgress(uid, replacement string, deleteRules bool) error {
	if err := s.requireEnabled(); err != nil {
		return err
	}
	unlock := s.lockKey(&s.egressMu, uid)
	defer unlock()
	row, err := s.egressByUID(uid)
	if err != nil {
		return err
	}
	deps, err := CollectDependencies(row.OutboundTag)
	if err != nil {
		return err
	}
	if len(deps) > 0 {
		if replacement == "" && !deleteRules {
			return &ConflictError{Err: piaprotocol.NewError(piaprotocol.CodeDependencyConflict, "This PIA outbound is still referenced."), Deps: deps}
		}
		if err := RewriteOrDeleteDependencies(row.OutboundTag, replacement, deleteRules); err != nil {
			return err
		}
	}
	if err := database.GetDB().Where("egress_id = ?", row.Id).Delete(&model.PiaBinding{}).Error; err != nil {
		return err
	}
	return database.GetDB().Delete(row).Error
}

func (s *Service) SetEnabled(uid string, enabled bool, replacement string, deleteRules bool) (*EgressView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	unlock := s.lockKey(&s.egressMu, uid)
	defer unlock()
	row, err := s.egressByUID(uid)
	if err != nil {
		return nil, err
	}
	if !enabled {
		deps, err := CollectDependencies(row.OutboundTag)
		if err != nil {
			return nil, err
		}
		if len(deps) > 0 {
			if replacement == "" && !deleteRules {
				return nil, &ConflictError{Err: piaprotocol.NewError(piaprotocol.CodeDependencyConflict, "This PIA outbound is still referenced."), Deps: deps}
			}
			if err := RewriteOrDeleteDependencies(row.OutboundTag, replacement, deleteRules); err != nil {
				return nil, err
			}
		}
		row.Enabled = false
		row.Status = model.PiaEgressDisabled
	} else {
		row.Enabled = true
		if b, _ := s.activeBinding(row.Id); b != nil {
			row.Status = model.PiaEgressReady
		}
	}
	row.DesiredRevision++
	if err := database.GetDB().Save(row).Error; err != nil {
		return nil, err
	}
	return s.egressView(row)
}

func (s *Service) Provision(ctx context.Context, uid string) (*EgressView, error) {
	return s.provision(ctx, uid)
}

func (s *Service) RotateKey(ctx context.Context, uid string) (*EgressView, error) {
	return s.provision(ctx, uid)
}

func (s *Service) Reprovision(ctx context.Context, uid string) (*EgressView, error) {
	return s.provision(ctx, uid)
}

func (s *Service) provision(ctx context.Context, uid string) (*EgressView, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	box, err := s.requireBox()
	if err != nil {
		return nil, err
	}
	unlock := s.lockKey(&s.egressMu, uid)
	defer unlock()
	row, err := s.egressByUID(uid)
	if err != nil {
		return nil, err
	}
	profile, err := s.profileByID(row.ProfileID)
	if err != nil {
		return nil, err
	}
	token, err := s.decryptProfileToken(box, profile)
	if err != nil {
		if row.Status != model.PiaEgressReady {
			row.Status = model.PiaEgressNeedsAuth
			_ = database.GetDB().Save(row).Error
		}
		return nil, err
	}
	region, err := s.regionByID(ctx, row.RegionID)
	if err != nil {
		return nil, err
	}
	server, err := pickServer(region, row.ServerHostname)
	if err != nil {
		return nil, err
	}
	priv, pub, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		return nil, err
	}
	row.Status = model.PiaEgressProvisioning
	_ = database.GetDB().Save(row).Error
	reg, err := s.Registrar.RegisterKey(ctx, server, token, pub)
	if err != nil {
		row.Status = model.PiaEgressError
		row.LastErrorCode = piaprotocol.CodeOf(err)
		row.LastErrorMessage = piaprotocol.MessageOf(err)
		_ = database.GetDB().Save(row).Error
		logger.Warningf("provider=pia operation=provision uid=%s error_code=%s", uid, piaprotocol.CodeOf(err))
		return nil, err
	}
	bindingUID := newUID()
	ct, err := box.Encrypt(secretbox.SecretRef{Namespace: nsBindingPriv, RecordID: bindingUID, Field: "private-key"}, []byte(priv))
	if err != nil {
		return nil, piaprotocol.WrapError(piaprotocol.CodeEncryptionRequired, "Could not encrypt the WireGuard private key.", err)
	}
	dns, _ := json.Marshal(addrsToStrings(reg.DNSServers))
	gen := 1
	cur, err := s.activeBinding(row.Id)
	if err != nil {
		return nil, err
	}
	if cur != nil {
		gen = cur.Generation + 1
		cur.Active = false
		cur.ActiveSlot = nil
		if err := database.GetDB().Save(cur).Error; err != nil {
			return nil, err
		}
	}
	slot := model.PiaBindingActiveSlot
	binding := &model.PiaBinding{
		UID: bindingUID, EgressID: row.Id, ScopeKey: model.PiaScopeLocal, ActiveSlot: &slot,
		PrivateKeyCiphertext: ct, PublicKey: pub, PeerIP: reg.PeerIP.String(),
		ServerPublicKey: reg.ServerKey, ServerIP: reg.ServerIP.String(), ServerHostname: server.Hostname,
		ServerPort: int(reg.ServerPort), DNSServersJSON: string(dns), State: model.PiaEgressReady,
		ProvisionedAt: s.now().Unix(), Generation: gen, Active: true,
	}
	if err := database.GetDB().Create(binding).Error; err != nil {
		row.Status = model.PiaEgressUncertain
		_ = database.GetDB().Save(row).Error
		return nil, err
	}
	row.Status = model.PiaEgressReady
	row.LastErrorCode = ""
	row.LastErrorMessage = ""
	row.ServerHostname = server.Hostname
	row.ServerIP = server.IP.String()
	row.AppliedRevision = row.DesiredRevision
	if err := database.GetDB().Save(row).Error; err != nil {
		return nil, err
	}
	logger.Infof("provider=pia operation=provision uid=%s tag=%s generation=%d", uid, row.OutboundTag, gen)
	return s.egressView(row)
}

func (s *Service) TestByTag(ctx context.Context, uid, testURL, mode string) (*outbound.TestOutboundResult, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	box, err := s.requireBox()
	if err != nil {
		return nil, err
	}
	unlock := s.lockKey(&s.egressMu, uid)
	defer unlock()
	row, err := s.egressByUID(uid)
	if err != nil {
		return nil, err
	}
	if last, ok := s.testLast.Load(uid); ok {
		if s.now().Sub(last.(time.Time)) < testCooldown {
			return nil, piaprotocol.NewError(piaprotocol.CodeCooldown, "Wait before testing this outbound again.")
		}
	}
	binding, err := s.activeBinding(row.Id)
	if err != nil || binding == nil {
		return nil, piaprotocol.NewError(piaprotocol.CodeNotReady, "This PIA outbound has no active WireGuard binding.")
	}
	priv, err := box.Decrypt(secretbox.SecretRef{Namespace: nsBindingPriv, RecordID: binding.UID, Field: "private-key"}, binding.PrivateKeyCiphertext)
	if err != nil {
		return nil, piaprotocol.NewError(piaprotocol.CodeEncryptionRequired, "The WireGuard private key could not be decrypted.")
	}
	_, raw, err := BuildWireGuardOutbound(BuildInput{
		Tag: row.OutboundTag, SecretKey: string(priv), Address: binding.PeerIP,
		PeerPublicKey: binding.ServerPublicKey, EndpointHost: binding.ServerIP, EndpointPort: binding.ServerPort,
		MTU: row.MTU, KeepaliveSeconds: &row.KeepaliveSeconds,
	})
	if err != nil {
		return nil, err
	}
	s.testLast.Store(uid, s.now())
	result, err := (&outbound.OutboundService{}).TestOutboundContext(ctx, string(raw), testURL, "", mode)
	if err != nil {
		return nil, err
	}
	binding.LastTestedAt = s.now().Unix()
	if result != nil {
		binding.LastLatencyMs = int(result.Delay)
		if result.Egress != nil && result.Egress.IPv4 != "" {
			binding.LastExternalIP = result.Egress.IPv4
		}
		if result.Success {
			binding.LastErrorCode = ""
			binding.LastErrorMessage = ""
		} else {
			binding.LastErrorCode = piaprotocol.CodeNetworkUnavailable
			binding.LastErrorMessage = result.Error
		}
	}
	_ = database.GetDB().Save(binding).Error
	return result, nil
}

func (s *Service) Dependencies(uid string) ([]Dependency, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	row, err := s.egressByUID(uid)
	if err != nil {
		return nil, err
	}
	return CollectDependencies(row.OutboundTag)
}

func (s *Service) Reconcile() {
	if !config.IsPIAEnabled() {
		return
	}
	var rows []model.PiaEgress
	if err := database.GetDB().Find(&rows).Error; err != nil {
		logger.Warningf("provider=pia operation=reconcile error=%v", err)
		return
	}
	box := s.box()
	for i := range rows {
		row := &rows[i]
		if !row.Enabled {
			continue
		}
		b, err := s.activeBinding(row.Id)
		if err != nil || b == nil {
			if row.Status == model.PiaEgressReady {
				row.Status = model.PiaEgressError
				row.LastErrorCode = piaprotocol.CodeNotReady
				row.LastErrorMessage = "No active WireGuard binding."
				_ = database.GetDB().Save(row).Error
			}
			continue
		}
		if box == nil || !box.Enabled() || !secretbox.IsEncrypted(b.PrivateKeyCiphertext) {
			row.LastErrorCode = piaprotocol.CodeEncryptionRequired
			row.LastErrorMessage = "Keyring missing; outbound will not be injected."
			_ = database.GetDB().Save(row).Error
			continue
		}
		if _, err := box.Decrypt(secretbox.SecretRef{Namespace: nsBindingPriv, RecordID: b.UID, Field: "private-key"}, b.PrivateKeyCiphertext); err != nil {
			row.LastErrorCode = piaprotocol.CodeEncryptionRequired
			row.LastErrorMessage = "Private key could not be decrypted."
			_ = database.GetDB().Save(row).Error
		}
	}
	logger.Infof("provider=pia operation=reconcile egresses=%d", len(rows))
}

func (s *Service) ReadyOutbounds() ([]any, []string, error) {
	if !config.IsPIAEnabled() {
		return nil, nil, nil
	}
	var rows []model.PiaEgress
	if err := database.GetDB().Where("enabled = ? AND status = ?", true, model.PiaEgressReady).Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	var ready []any
	var skipped []string
	box := s.box()
	if box == nil || !box.Enabled() {
		for i := range rows {
			skipped = append(skipped, rows[i].OutboundTag)
		}
		return ready, skipped, nil
	}
	for i := range rows {
		row := &rows[i]
		b, err := s.activeBinding(row.Id)
		if err != nil || b == nil {
			skipped = append(skipped, row.OutboundTag)
			continue
		}
		priv, err := box.Decrypt(secretbox.SecretRef{Namespace: nsBindingPriv, RecordID: b.UID, Field: "private-key"}, b.PrivateKeyCiphertext)
		if err != nil {
			skipped = append(skipped, row.OutboundTag)
			logger.Warningf("provider=pia operation=merge tag=%s error_code=%s", row.OutboundTag, piaprotocol.CodeEncryptionRequired)
			continue
		}
		ob, _, err := BuildWireGuardOutbound(BuildInput{
			Tag: row.OutboundTag, SecretKey: string(priv), Address: b.PeerIP,
			PeerPublicKey: b.ServerPublicKey, EndpointHost: b.ServerIP, EndpointPort: b.ServerPort,
			MTU: row.MTU, KeepaliveSeconds: &row.KeepaliveSeconds,
		})
		if err != nil {
			skipped = append(skipped, row.OutboundTag)
			logger.Warningf("provider=pia operation=merge tag=%s error=%v", row.OutboundTag, err)
			continue
		}
		ready = append(ready, ob)
	}
	return ready, skipped, nil
}

func (s *Service) MarkReadyOutboundsApplied() error {
	if !config.IsPIAEnabled() {
		return nil
	}
	var egressIDs []int
	if err := database.GetDB().Model(&model.PiaEgress{}).
		Where("enabled = ? AND status = ?", true, model.PiaEgressReady).
		Pluck("id", &egressIDs).Error; err != nil || len(egressIDs) == 0 {
		return err
	}
	return database.GetDB().Model(&model.PiaBinding{}).
		Where("egress_id IN ? AND active = ?", egressIDs, true).
		Update("last_applied_at", s.now().Unix()).Error
}

func (s *Service) PublicOutbounds() []map[string]any {
	if !config.IsPIAEnabled() {
		return nil
	}
	var rows []model.PiaEgress
	if err := database.GetDB().Where("enabled = ?", true).Find(&rows).Error; err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		out = append(out, PublicOutboundView(rows[i].UID, rows[i].OutboundTag, rows[i].RegionName, rows[i].ServerHostname, rows[i].Status))
	}
	return out
}

func (s *Service) PublicTags() []string {
	if !config.IsPIAEnabled() {
		return nil
	}
	var rows []model.PiaEgress
	if err := database.GetDB().Where("enabled = ? AND status = ?", true, model.PiaEgressReady).Find(&rows).Error; err != nil {
		return nil
	}
	tags := make([]string, 0, len(rows))
	for i := range rows {
		tags = append(tags, rows[i].OutboundTag)
	}
	return tags
}

type ConflictError struct {
	Err  *piaprotocol.Error
	Deps []Dependency
}

func (e *ConflictError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ConflictError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func Retryable(code string) bool {
	switch code {
	case piaprotocol.CodeTimeout, piaprotocol.CodeNetworkUnavailable, piaprotocol.CodeAuthenticationUnavailable,
		piaprotocol.CodeCatalogUnavailable, piaprotocol.CodeCancelled, piaprotocol.CodeCooldown:
		return true
	default:
		return false
	}
}

func (s *Service) profileByUID(uid string) (*model.PiaProfile, error) {
	var row model.PiaProfile
	if err := database.GetDB().Where("uid = ?", uid).First(&row).Error; err != nil {
		return nil, piaprotocol.NewError(piaprotocol.CodeNotFound, "PIA profile not found.")
	}
	return &row, nil
}

func (s *Service) profileByID(id int) (*model.PiaProfile, error) {
	var row model.PiaProfile
	if err := database.GetDB().First(&row, id).Error; err != nil {
		return nil, piaprotocol.NewError(piaprotocol.CodeNotFound, "PIA profile not found.")
	}
	return &row, nil
}

func (s *Service) egressByUID(uid string) (*model.PiaEgress, error) {
	var row model.PiaEgress
	if err := database.GetDB().Where("uid = ?", uid).First(&row).Error; err != nil {
		return nil, piaprotocol.NewError(piaprotocol.CodeNotFound, "PIA outbound not found.")
	}
	return &row, nil
}

func (s *Service) activeBinding(egressID int) (*model.PiaBinding, error) {
	var row model.PiaBinding
	err := database.GetDB().Where("egress_id = ? AND scope_key = ? AND active = ?", egressID, model.PiaScopeLocal, true).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *Service) egressView(row *model.PiaEgress) (*EgressView, error) {
	var profile model.PiaProfile
	_ = database.GetDB().First(&profile, row.ProfileID)
	view := &EgressView{
		UID: row.UID, ProfileUID: profile.UID, Name: row.Name, OutboundTag: row.OutboundTag,
		RegionID: row.RegionID, RegionName: row.RegionName, ServerHostname: row.ServerHostname,
		ServerIP: row.ServerIP, Enabled: row.Enabled, MTU: row.MTU, KeepaliveSeconds: row.KeepaliveSeconds,
		IPv6Policy: row.IPv6Policy, Status: row.Status, LastErrorCode: row.LastErrorCode,
		LastErrorMessage: row.LastErrorMessage,
	}
	if b, err := s.activeBinding(row.Id); err == nil && b != nil {
		view.HasActiveBinding = true
		view.PublicKey = b.PublicKey
		view.PeerIP = b.PeerIP
		view.Generation = b.Generation
		view.LastExternalIP = b.LastExternalIP
		view.LastLatencyMs = b.LastLatencyMs
		view.Binding = &BindingPublic{
			UID: b.UID, PublicKey: b.PublicKey, PeerIP: b.PeerIP, ServerHostname: b.ServerHostname,
			ServerIP: b.ServerIP, ServerPort: b.ServerPort, Generation: b.Generation, Active: b.Active,
		}
	}
	return view, nil
}

func (s *Service) decryptProfileToken(box *secretbox.Codec, profile *model.PiaProfile) (string, error) {
	if profile.TokenCiphertext == "" || profile.AuthStatus != model.PiaAuthValid {
		return "", piaprotocol.NewError(piaprotocol.CodeTokenRejected, "Authenticate this PIA profile first.")
	}
	if profile.TokenExpiresAt > 0 && s.now().Unix() >= profile.TokenExpiresAt {
		profile.AuthStatus = model.PiaAuthExpired
		_ = database.GetDB().Save(profile).Error
		return "", piaprotocol.NewError(piaprotocol.CodeTokenRejected, "The PIA token has expired. Sign in again.")
	}
	pt, err := box.Decrypt(secretbox.SecretRef{Namespace: nsProfileToken, RecordID: profile.UID, Field: "token"}, profile.TokenCiphertext)
	if err != nil {
		return "", piaprotocol.NewError(piaprotocol.CodeEncryptionRequired, "The PIA token could not be decrypted.")
	}
	return string(pt), nil
}

func (s *Service) loadSnapshot() (*model.PiaCatalogSnapshot, error) {
	var row model.PiaCatalogSnapshot
	if err := database.GetDB().First(&row, catalogSnapshotID).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *Service) regions(ctx context.Context) ([]piaprotocol.Region, error) {
	if snap, err := s.loadSnapshot(); err == nil && snap.SignatureVerified && snap.PayloadJSON != "" {
		age := time.Duration(s.now().Unix()-snap.FetchedAt) * time.Second
		if age >= 0 && age < piaprotocol.DefaultCatalogFreshTTL {
			regions, _, err := piaprotocol.ParseServerList([]byte(snap.PayloadJSON), snap.Schema)
			if err == nil {
				return regions, nil
			}
		}
	}
	return s.fetchCatalog(ctx, false)
}

func (s *Service) fetchCatalog(ctx context.Context, force bool) ([]piaprotocol.Region, error) {
	s.catalogMu.Lock()
	defer s.catalogMu.Unlock()
	if !force {
		if snap, err := s.loadSnapshot(); err == nil && snap.SignatureVerified {
			age := time.Duration(s.now().Unix()-snap.FetchedAt) * time.Second
			if age >= 0 && age < piaprotocol.DefaultCatalogFreshTTL {
				regions, _, err := piaprotocol.ParseServerList([]byte(snap.PayloadJSON), snap.Schema)
				if err == nil {
					return regions, nil
				}
			}
		}
	}
	snapNet, err := s.Catalog.Fetch(ctx)
	if err != nil {
		if snap, lerr := s.loadSnapshot(); lerr == nil && snap.SignatureVerified {
			age := time.Duration(s.now().Unix()-snap.FetchedAt) * time.Second
			if age >= 0 && age < piaprotocol.DefaultCatalogMaxStale {
				regions, _, perr := piaprotocol.ParseServerList([]byte(snap.PayloadJSON), snap.Schema)
				if perr == nil {
					snap.LastErrorCode = piaprotocol.CodeOf(err)
					snap.LastErrorMessage = piaprotocol.MessageOf(err)
					_ = database.GetDB().Save(snap).Error
					return regions, nil
				}
			}
		}
		return nil, err
	}
	if !snapNet.SignatureVerified {
		return nil, piaprotocol.NewError(piaprotocol.CodeCatalogSignatureInvalid, "The PIA region list was not signature-verified.")
	}
	regions, schema, err := piaprotocol.ParseServerList(snapNet.Payload, snapNet.SchemaHint)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(snapNet.Payload)
	servers := 0
	for _, r := range regions {
		servers += len(r.WireGuard)
	}
	row := model.PiaCatalogSnapshot{
		Id: catalogSnapshotID, PayloadJSON: string(snapNet.Payload), PayloadSHA256: hex.EncodeToString(sum[:]),
		SignatureVerified: true, FetchedAt: s.now().Unix(), ParserVersion: model.PiaCatalogParserVersion,
		RegionCount: len(regions), ServerCount: servers, Schema: schema,
	}
	db := database.GetDB()
	var existing model.PiaCatalogSnapshot
	if err := db.First(&existing, catalogSnapshotID).Error; err != nil {
		if err := db.Create(&row).Error; err != nil {
			return nil, err
		}
	} else {
		row.Id = existing.Id
		if err := db.Save(&row).Error; err != nil {
			return nil, err
		}
	}
	return regions, nil
}

func (s *Service) regionByID(ctx context.Context, id string) (*piaprotocol.Region, error) {
	regions, err := s.regions(ctx)
	if err != nil {
		return nil, err
	}
	for i := range regions {
		if regions[i].ID == id {
			return &regions[i], nil
		}
	}
	return nil, piaprotocol.NewError(piaprotocol.CodeRegionNotFound, "That PIA region was not found.")
}

func pickServer(region *piaprotocol.Region, hostname string) (piaprotocol.WireGuardServer, error) {
	if hostname != "" {
		for _, srv := range region.WireGuard {
			if srv.Hostname == hostname {
				return srv, nil
			}
		}
		return piaprotocol.WireGuardServer{}, piaprotocol.NewError(piaprotocol.CodeServerNotFound, "That PIA WireGuard server was not found.")
	}
	if len(region.WireGuard) == 0 {
		return piaprotocol.WireGuardServer{}, piaprotocol.NewError(piaprotocol.CodeServerNotFound, "That region has no WireGuard servers.")
	}
	return region.WireGuard[0], nil
}

func (s *Service) allocateTag(uid string) (string, error) {
	occupied, err := OccupiedTags()
	if err != nil {
		return "", err
	}
	base := strings.ReplaceAll(uid, "-", "")
	if len(base) > 8 {
		base = base[:8]
	}
	tag := "pia-" + base
	if _, used := occupied[tag]; !used {
		return tag, nil
	}
	for i := 0; i < 8; i++ {
		tag = "pia-" + newUID()[:8]
		if _, used := occupied[tag]; !used {
			return tag, nil
		}
	}
	return "", piaprotocol.NewError(piaprotocol.CodeTagConflict, "Could not allocate a unique PIA outbound tag.")
}

func OccupiedTags() (map[string]struct{}, error) {
	tags := map[string]struct{}{}
	db := database.GetDB()
	var setting model.Setting
	if err := db.Where("key = ?", "xrayTemplateConfig").First(&setting).Error; err == nil {
		var cfg map[string]any
		if json.Unmarshal([]byte(setting.Value), &cfg) == nil {
			if obs, ok := cfg["outbounds"].([]any); ok {
				for _, ob := range obs {
					if m, ok := ob.(map[string]any); ok {
						if tag, _ := m["tag"].(string); tag != "" {
							tags[tag] = struct{}{}
						}
					}
				}
			}
		}
	}
	var subs []model.OutboundSubscription
	if err := db.Find(&subs).Error; err == nil {
		for _, sub := range subs {
			var arr []map[string]any
			if json.Unmarshal([]byte(sub.LastFetchedOutbounds), &arr) == nil {
				for _, ob := range arr {
					if tag, _ := ob["tag"].(string); tag != "" {
						tags[tag] = struct{}{}
					}
				}
			}
		}
	}
	var egresses []model.PiaEgress
	if err := db.Find(&egresses).Error; err == nil {
		for _, e := range egresses {
			if e.OutboundTag != "" {
				tags[e.OutboundTag] = struct{}{}
			}
		}
	}
	var inbounds []model.Inbound
	if err := db.Select("tag").Find(&inbounds).Error; err == nil {
		for _, ib := range inbounds {
			if ib.Tag != "" {
				tags[ib.Tag] = struct{}{}
			}
		}
	}
	return tags, nil
}

func (s *Service) lockKey(m *sync.Map, key string) func() {
	muIface, _ := m.LoadOrStore(key, &sync.Mutex{})
	mu := muIface.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func newUID() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}

func accountHint(username string) string {
	u := strings.TrimSpace(username)
	if len(u) <= 4 {
		return strings.Repeat("*", len(u))
	}
	return u[:2] + strings.Repeat("*", len(u)-4) + u[len(u)-2:]
}

func normalizeTunnelOpts(mtu int, keepalive *int, ipv6 string) (int, int, string, error) {
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 1280 || mtu > 1500 {
		return 0, 0, "", piaprotocol.NewError(piaprotocol.CodeInvalidInput, "MTU must be between 1280 and 1500.")
	}
	ka := defaultKeepalive
	if keepalive != nil {
		ka = *keepalive
	}
	if ka < 0 || ka > 120 {
		return 0, 0, "", piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Keepalive must be between 0 and 120 seconds.")
	}
	switch ipv6 {
	case "", model.PiaIPv6Block:
		ipv6 = model.PiaIPv6Block
	case model.PiaIPv6DirectWarn:
	default:
		return 0, 0, "", piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Unsupported IPv6 policy.")
	}
	return mtu, ka, ipv6, nil
}

func firstPositive(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func addrsToStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func ConfigReferencesTag(routing []byte, extra []string, tag string) bool {
	if tag == "" {
		return false
	}
	for _, e := range extra {
		if e == tag {
			return true
		}
	}
	var obj map[string]any
	if json.Unmarshal(routing, &obj) != nil {
		return false
	}
	if rules, ok := obj["rules"].([]any); ok {
		for _, r := range rules {
			rm, _ := r.(map[string]any)
			if strField(rm, "outboundTag") == tag || strField(rm, "balancerTag") == tag {
				return true
			}
		}
	}
	if bals, ok := obj["balancers"].([]any); ok {
		for _, b := range bals {
			bm, _ := b.(map[string]any)
			if selectorContains(bm["selector"], tag) {
				return true
			}
		}
	}
	return false
}
