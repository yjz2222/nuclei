package handlers

import (
	"context"
	"github.com/golang-jwt/jwt"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

const JWT_KEY = "mypoc.jt.key"

type loginStruct struct {
	UserName string `json:"user_name"`
	Password string `json:"password"`
	NewPwd   string `json:"new_pwd"`
}

func (s *Server) Login(ctx echo.Context) error {
	var ls loginStruct
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&ls); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	if ls.UserName == "" || ls.Password == "" {
		return echo.NewHTTPError(401, "用户名或密码不能为空")
	}
	pwdInDb := ""
	if err := s.scans.Dbraw.Pool.QueryRow(context.Background(), "select password from users where user_name=$1 limit 1", ls.UserName).Scan(&pwdInDb); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not check pwd").Error())
	}
	if pwdInDb != ls.Password {
		return echo.NewHTTPError(401, "用户名或密码错误")
	}
	t := jwt.New(jwt.SigningMethodHS256)
	token, err := t.SignedString([]byte(JWT_KEY))
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not sign token").Error())
	}
	m := make(map[string]string)
	m["token"] = token
	return ctx.JSON(200, m)
}

func (s *Server) ModPwd(ctx echo.Context) error {
	var ls loginStruct
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&ls); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	if ls.UserName == "" || ls.Password == "" || ls.NewPwd == "" {
		return echo.NewHTTPError(401, "用户名或密码不能为空")
	}
	pwdInDb := ""
	if err := s.scans.Dbraw.Pool.QueryRow(context.Background(), "select password from users where user_name=$1 limit 1", ls.UserName).Scan(&pwdInDb); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not check pwd").Error())
	}
	if pwdInDb != ls.Password {
		return echo.NewHTTPError(401, "用户名或密码错误")
	}
	if _, err := s.scans.Dbraw.Pool.Exec(context.Background(), "update users set password=$1 where user_name=$2", ls.NewPwd, ls.UserName); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not modify pwd").Error())
	}
	return ctx.JSON(200, nil)
}
