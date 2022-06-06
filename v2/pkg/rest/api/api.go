package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/handlers"
)

// API is a REST API server structure
type API struct {
	echo *echo.Echo
}

// Config contains configuration options for REST API
type Config struct {
	Token  string
	Host   string
	Port   int
	TLS    bool
	Server *handlers.Server
}

//const defaultCacheSize = 100 * 1024 * 1024 // 100MB server side cache.

// New returns a new REST API server structure
func New(config *Config) *API {
	// Echo instance
	e := echo.New()
	e.Debug = true // todo: disable before prod
	e.JSONSerializer = &JSONIterSerializer{}

	scheme := "http"
	if config.TLS {
		scheme = "https"
	}

	// Use a fixed side server-side cache with 1m ttl
	//c := freecache.NewCache(defaultCacheSize)
	//e.Use(cache.New(&cache.Config{}, c))

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{fmt.Sprintf("%s://%s:%d", scheme, config.Host, config.Port)},
		AllowMethods:     []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
		AllowCredentials: true,
		AllowHeaders:     []string{HeaderAuthKey},
	}))
	// Use basic auth
	//e.Use(HeaderAuthenticator(config.Token))

	apiGroup := e.Group("/api/v1")

	apiGroup.POST("/login", config.Server.Login)
	apiGroup.POST("/modPwd", config.Server.ModPwd)
	authorizedGroup := e.Group("/authorized")
	authorizedGroup.Use(middleware.JWT([]byte(handlers.JWT_KEY)))

	// /templates endpoints
	authorizedGroup.GET("/templates", config.Server.GetTemplates)
	authorizedGroup.POST("/templates", config.Server.AddTemplate)
	authorizedGroup.PUT("/templates", config.Server.UpdateTemplate)
	authorizedGroup.DELETE("/templates", config.Server.DeleteTemplate)
	authorizedGroup.GET("/templates/raw", config.Server.GetTemplatesRaw)
	authorizedGroup.POST("/templates/execute", config.Server.ExecuteTemplate)
	authorizedGroup.POST("/templates/file", config.Server.FileUpload)

	// /targets endpoints
	authorizedGroup.GET("/targets", config.Server.GetTargets)
	authorizedGroup.POST("/targets", config.Server.AddTarget)
	authorizedGroup.PUT("/targets/:id", config.Server.UpdateTarget)
	authorizedGroup.DELETE("/targets/:id", config.Server.DeleteTarget)
	authorizedGroup.GET("/targets/:id", config.Server.GetTargetContents)

	// /settings endpoints
	authorizedGroup.GET("/settings", config.Server.GetSettings)
	authorizedGroup.POST("/settings", config.Server.SetSetting)
	authorizedGroup.GET("/settings/:name", config.Server.GetSettingByName)
	authorizedGroup.PUT("/settings/:name", config.Server.UpdateSettingByName)

	// /scans endpoints
	authorizedGroup.GET("/scans", config.Server.GetScans)
	authorizedGroup.POST("/scans", config.Server.AddScan)
	authorizedGroup.GET("/scans/progress", config.Server.GetScanProgress)
	authorizedGroup.GET("/scans/:id", config.Server.GetScan)
	authorizedGroup.PUT("/scans/:id", config.Server.UpdateScan)
	authorizedGroup.DELETE("/scans/:id", config.Server.DeleteScan)
	authorizedGroup.GET("/scans/:id/execute", config.Server.ExecuteScan)
	authorizedGroup.GET("/scans/:id/matches", config.Server.GetScanMatches)
	authorizedGroup.GET("/scans/:id/errors", config.Server.GetScanErrors)
	//获取模板执行进度
	authorizedGroup.GET("/scans/:id/progress", config.Server.GetScanTmpStatus)
	//获取当前或上一次执行的某个模板的时间轴
	authorizedGroup.GET("/scans/:tid/stamp", config.Server.GetScanTmpStamp)

	// /issues endpoints
	authorizedGroup.GET("/issues", config.Server.GetIssues)
	authorizedGroup.POST("/issues", config.Server.AddIssue)
	authorizedGroup.GET("/issues/:id", config.Server.GetIssue)
	authorizedGroup.PUT("/issues/:id", config.Server.UpdateIssue)
	authorizedGroup.DELETE("/issues/:id", config.Server.DeleteIssue)

	return &API{echo: e}
}

// Echo returns the echo router
func (a *API) Echo() *echo.Echo {
	return a.echo
}

// JSONIterSerializer implements JSON encoding using jsoniter for echo.
type JSONIterSerializer struct{}

// Serialize converts an interface into a json and writes it to the response.
// You can optionally use the indent parameter to produce pretty JSONs.
func (d JSONIterSerializer) Serialize(c echo.Context, i interface{}, indent string) error {
	enc := jsoniter.NewEncoder(c.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}
	return enc.Encode(i)
}

// Deserialize reads a JSON from a request body and converts it into an interface.
func (d JSONIterSerializer) Deserialize(c echo.Context, i interface{}) error {
	err := jsoniter.NewDecoder(c.Request().Body).Decode(i)
	if ute, ok := err.(*json.UnmarshalTypeError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)).SetInternal(err)
	} else if se, ok := err.(*json.SyntaxError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", se.Offset, se.Error())).SetInternal(err)
	}
	return err
}

const HeaderAuthKey = "X-API-Token"

// HeaderAuthenticator returns header token validator
func HeaderAuthenticator(token string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get(HeaderAuthKey)
			if auth == token {
				return next(c)
			}
			return echo.ErrUnauthorized
		}
	}
}
