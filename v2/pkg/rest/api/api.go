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

	// /templates endpoints   middleware.JWT([]byte(handlers.JWT_KEY))
	apiGroup.GET("/templates", config.Server.GetTemplates, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.POST("/templates", config.Server.AddTemplate, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.PUT("/templates", config.Server.UpdateTemplate, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.DELETE("/templates", config.Server.DeleteTemplate, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/templates/raw", config.Server.GetTemplatesRaw, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.POST("/templates/execute", config.Server.ExecuteTemplate, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.POST("/templates/file", config.Server.FileUpload, middleware.JWT([]byte(handlers.JWT_KEY)))

	// /targets endpoints
	apiGroup.GET("/targets", config.Server.GetTargets, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.POST("/targets", config.Server.AddTarget, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.PUT("/targets/:id", config.Server.UpdateTarget, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.DELETE("/targets/:id", config.Server.DeleteTarget, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/targets/:id", config.Server.GetTargetContents, middleware.JWT([]byte(handlers.JWT_KEY)))

	// /settings endpoints
	apiGroup.GET("/settings", config.Server.GetSettings, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.POST("/settings", config.Server.SetSetting, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/settings/:name", config.Server.GetSettingByName, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.PUT("/settings/:name", config.Server.UpdateSettingByName, middleware.JWT([]byte(handlers.JWT_KEY)))

	// /scans endpoints
	apiGroup.GET("/scans", config.Server.GetScans, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.POST("/scans", config.Server.AddScan, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/scans/progress", config.Server.GetScanProgress, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/scans/:id", config.Server.GetScan, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.PUT("/scans/:id", config.Server.UpdateScan, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.DELETE("/scans/:id", config.Server.DeleteScan, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/scans/:id/execute", config.Server.ExecuteScan, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/scans/:id/matches", config.Server.GetScanMatches, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/scans/:id/errors", config.Server.GetScanErrors, middleware.JWT([]byte(handlers.JWT_KEY)))
	//获取模板执行进度
	apiGroup.GET("/scans/:id/progress", config.Server.GetScanTmpStatus, middleware.JWT([]byte(handlers.JWT_KEY)))
	//获取当前或上一次执行的某个模板的时间轴
	apiGroup.GET("/scans/:tid/stamp", config.Server.GetScanTmpStamp, middleware.JWT([]byte(handlers.JWT_KEY)))

	// /issues endpoints
	apiGroup.GET("/issues", config.Server.GetIssues, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.POST("/issues", config.Server.AddIssue, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.GET("/issues/:id", config.Server.GetIssue, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.PUT("/issues/:id", config.Server.UpdateIssue, middleware.JWT([]byte(handlers.JWT_KEY)))
	apiGroup.DELETE("/issues/:id", config.Server.DeleteIssue, middleware.JWT([]byte(handlers.JWT_KEY)))

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
