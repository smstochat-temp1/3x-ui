package controller

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/gin-gonic/gin"

	piaprotocol "github.com/mhsanaei/3x-ui/v3/internal/pia"
	"github.com/mhsanaei/3x-ui/v3/internal/web/entity"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/pia"
)

type PIAController struct {
	svc *pia.Service
}

func NewPIAController(g *gin.RouterGroup) *PIAController {
	a := &PIAController{svc: pia.Default()}
	a.initRouter(g)
	return a
}

func (a *PIAController) initRouter(g *gin.RouterGroup) {
	g.GET("/status", a.status)
	g.GET("/profiles", a.listProfiles)
	g.POST("/profiles", a.createProfile)
	g.POST("/profiles/:uid/authenticate", a.authenticate)
	g.PATCH("/profiles/:uid", a.patchProfile)
	g.DELETE("/profiles/:uid", a.deleteProfile)
	g.GET("/catalog/status", a.catalogStatus)
	g.POST("/catalog/refresh", a.catalogRefresh)
	g.GET("/catalog/regions", a.listRegions)
	g.GET("/catalog/regions/:id/servers", a.listServers)
	g.GET("/egresses", a.listEgresses)
	g.POST("/egresses", a.createEgress)
	g.GET("/egresses/:uid", a.getEgress)
	g.PATCH("/egresses/:uid", a.patchEgress)
	g.DELETE("/egresses/:uid", a.deleteEgress)
	g.POST("/egresses/:uid/provision", a.provision)
	g.POST("/egresses/:uid/rotate-key", a.rotateKey)
	g.POST("/egresses/:uid/reprovision", a.reprovision)
	g.POST("/egresses/:uid/test", a.testEgress)
	g.POST("/egresses/:uid/enable", a.enableEgress)
	g.POST("/egresses/:uid/disable", a.disableEgress)
	g.GET("/egresses/:uid/dependencies", a.dependencies)
}

func (a *PIAController) respond(c *gin.Context, obj any, err error) {
	if err == nil {
		jsonObj(c, obj, nil)
		return
	}
	code := piaprotocol.CodeOf(err)
	msg := piaprotocol.MessageOf(err)
	info := entity.PiaErrorInfo{Code: code, Retryable: pia.Retryable(code)}
	var conflict *pia.ConflictError
	if errors.As(err, &conflict) {
		info.Details = conflict.Deps
	}
	jsonMsgObj(c, msg, map[string]any{"error": info}, err)
}

func (a *PIAController) status(c *gin.Context) {
	jsonObj(c, a.svc.Status(), nil)
}

func (a *PIAController) listProfiles(c *gin.Context) {
	rows, err := a.svc.ListProfiles()
	a.respond(c, rows, err)
}

func (a *PIAController) createProfile(c *gin.Context) {
	var body struct {
		Name string `json:"name"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	row, err := a.svc.CreateProfile(body.Name)
	a.respond(c, row, err)
}

func (a *PIAController) authenticate(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	row, err := a.svc.Authenticate(c.Request.Context(), c.Param("uid"), body.Username, []byte(body.Password))
	a.respond(c, row, err)
}

func (a *PIAController) patchProfile(c *gin.Context) {
	var body struct {
		Name    string `json:"name"`
		Enabled *bool  `json:"enabled"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	row, err := a.svc.PatchProfile(c.Param("uid"), body.Name, body.Enabled)
	a.respond(c, row, err)
}

func (a *PIAController) deleteProfile(c *gin.Context) {
	a.respond(c, nil, a.svc.DeleteProfile(c.Param("uid")))
}

func (a *PIAController) catalogStatus(c *gin.Context) {
	row, err := a.svc.CatalogStatus()
	a.respond(c, row, err)
}

func (a *PIAController) catalogRefresh(c *gin.Context) {
	row, err := a.svc.RefreshCatalog(c.Request.Context())
	a.respond(c, row, err)
}

func (a *PIAController) listRegions(c *gin.Context) {
	rows, err := a.svc.ListRegions(c.Request.Context())
	a.respond(c, rows, err)
}

func (a *PIAController) listServers(c *gin.Context) {
	rows, err := a.svc.ListServers(c.Request.Context(), c.Param("id"))
	a.respond(c, rows, err)
}

func (a *PIAController) listEgresses(c *gin.Context) {
	rows, err := a.svc.ListEgresses()
	a.respond(c, rows, err)
}

func (a *PIAController) createEgress(c *gin.Context) {
	var body struct {
		ProfileUID       string `json:"profileUid"`
		Name             string `json:"name"`
		RegionID         string `json:"regionId"`
		ServerHostname   string `json:"serverHostname"`
		MTU              int    `json:"mtu"`
		KeepaliveSeconds *int   `json:"keepaliveSeconds"`
		IPv6Policy       string `json:"ipv6Policy"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	row, err := a.svc.CreateEgress(c.Request.Context(), pia.CreateEgressInput{
		ProfileUID: body.ProfileUID, Name: body.Name, RegionID: body.RegionID,
		ServerHostname: body.ServerHostname, MTU: body.MTU, KeepaliveSeconds: body.KeepaliveSeconds,
		IPv6Policy: body.IPv6Policy,
	})
	a.respond(c, row, err)
}

func (a *PIAController) getEgress(c *gin.Context) {
	row, err := a.svc.GetEgress(c.Param("uid"))
	a.respond(c, row, err)
}

func (a *PIAController) patchEgress(c *gin.Context) {
	var body struct {
		Name             string `json:"name"`
		MTU              int    `json:"mtu"`
		KeepaliveSeconds *int   `json:"keepaliveSeconds"`
		IPv6Policy       string `json:"ipv6Policy"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	row, err := a.svc.PatchEgress(c.Param("uid"), body.Name, body.MTU, body.KeepaliveSeconds, body.IPv6Policy)
	a.respond(c, row, err)
}

func (a *PIAController) deleteEgress(c *gin.Context) {
	var body struct {
		ReplacementTag string `json:"replacementTag"`
		DeleteRules    bool   `json:"deleteRules"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	if body.ReplacementTag == "" {
		body.ReplacementTag = c.Query("replacementTag")
	}
	if !body.DeleteRules {
		body.DeleteRules = c.Query("deleteRules") == "true"
	}
	a.respond(c, nil, a.svc.DeleteEgress(c.Param("uid"), body.ReplacementTag, body.DeleteRules))
}

func (a *PIAController) provision(c *gin.Context) {
	row, err := a.svc.Provision(c.Request.Context(), c.Param("uid"))
	a.respond(c, row, err)
}

func (a *PIAController) rotateKey(c *gin.Context) {
	row, err := a.svc.RotateKey(c.Request.Context(), c.Param("uid"))
	a.respond(c, row, err)
}

func (a *PIAController) reprovision(c *gin.Context) {
	row, err := a.svc.Reprovision(c.Request.Context(), c.Param("uid"))
	a.respond(c, row, err)
}

func (a *PIAController) testEgress(c *gin.Context) {
	var body struct {
		TestURL string `json:"testUrl"`
		Mode    string `json:"mode"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	row, err := a.svc.TestByTag(c.Request.Context(), c.Param("uid"), body.TestURL, body.Mode)
	a.respond(c, row, err)
}

func (a *PIAController) enableEgress(c *gin.Context) {
	row, err := a.svc.SetEnabled(c.Param("uid"), true, "", false)
	a.respond(c, row, err)
}

func (a *PIAController) disableEgress(c *gin.Context) {
	var body struct {
		ReplacementTag string `json:"replacementTag"`
		DeleteRules    bool   `json:"deleteRules"`
	}
	if err := bindPIAJSON(c, &body); err != nil {
		a.respond(c, nil, piaprotocol.NewError(piaprotocol.CodeInvalidInput, "Invalid JSON body."))
		return
	}
	row, err := a.svc.SetEnabled(c.Param("uid"), false, body.ReplacementTag, body.DeleteRules)
	a.respond(c, row, err)
}

func (a *PIAController) dependencies(c *gin.Context) {
	rows, err := a.svc.Dependencies(c.Param("uid"))
	a.respond(c, rows, err)
}

func bindPIAJSON(c *gin.Context, dest any) error {
	dec := json.NewDecoder(io.LimitReader(c.Request.Body, 1<<20))
	if err := dec.Decode(dest); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
