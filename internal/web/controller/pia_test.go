package controller

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestBindPIAJSONRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	payload := `{"name":"` + strings.Repeat("a", 2<<20) + `"}`
	c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	var dest struct {
		Name string `json:"name"`
	}
	if err := bindPIAJSON(c, &dest); err == nil {
		t.Fatal("oversized PIA JSON body must fail")
	}
}

func TestPIAMutationHandlersRejectMalformedJSON(t *testing.T) {
	t.Setenv("XUI_PIA_ENABLED", "true")
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	NewPIAController(engine.Group("/panel/api/pia"))
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodDelete, path: "/panel/api/pia/egresses/missing"},
		{method: http.MethodPost, path: "/panel/api/pia/egresses/missing/test"},
		{method: http.MethodPost, path: "/panel/api/pia/egresses/missing/disable"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(test.method, test.path, strings.NewReader(`{"broken":`))
			engine.ServeHTTP(w, req)
			if !strings.Contains(w.Body.String(), `"code":"pia_invalid_input"`) {
				t.Fatalf("malformed body was not rejected: %s", w.Body.String())
			}
		})
	}
}

func TestPIAControllerOmitsCiphertext(t *testing.T) {
	t.Setenv("XUI_PIA_ENABLED", "true")
	gin.SetMode(gin.TestMode)
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })
	secret := "enc:v1:k1:SECRET-PIA-TOKEN-VALUE"
	if err := database.GetDB().Create(&model.PiaProfile{
		UID:             "p1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name:            "acct",
		TokenCiphertext: secret,
		AuthStatus:      model.PiaAuthValid,
		Enabled:         true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	NewPIAController(engine.Group("/panel/api/pia"))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panel/api/pia/profiles", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, needle := range []string{secret, "SECRET-PIA-TOKEN", "tokenCiphertext", "privateKey", "password"} {
		if strings.Contains(body, needle) {
			t.Fatalf("leaked %q: %s", needle, body)
		}
	}
}
