package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db/dbsql"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

// GetTemplatesResponse is a response for /templates listing
type GetTemplatesResponse struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Folder    string    `json:"folder"`
	Path      string    `json:"path"`
	Createdat time.Time `json:"createdAt"`
	Updatedat time.Time `json:"updatedAt"`
}

// GetTemplates handlers /templates listing route
func (s *Server) GetTemplates(ctx echo.Context) error {
	if folder := ctx.QueryParam("folder"); folder != "" {
		return s.getTemplatesWithFolder(ctx, folder)
	}
	if search := ctx.QueryParam("search"); search != "" {
		return s.getTemplatesWithSearchKey(ctx, search)
	}
	return s.getTemplates(ctx)
}

// getTemplates handles getting templates
func (s *Server) getTemplates(ctx echo.Context) error {
	page, size := paginationDataFromContext(ctx)

	rows, err := s.db.GetTemplates(context.Background(), dbsql.GetTemplatesParams{
		SqlOffset: page * size,
		SqlLimit:  size,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get templates from db").Error())
	}
	response := make([]GetTemplatesResponse, 0, len(rows))
	for _, row := range rows {
		response = append(response, GetTemplatesResponse{
			ID:        row.ID,
			Name:      row.Name,
			Folder:    row.Folder,
			Path:      row.Path,
			Createdat: row.Createdat,
			Updatedat: row.Updatedat,
		})
	}
	var totalCount int
	s.scans.Dbraw.Pool.QueryRow(context.Background(), "select count(id) from \"public\".templates where templates.path like '%.yaml'").Scan(&totalCount)
	m := make(map[string]interface{})
	m["total"] = totalCount
	m["data"] = response
	return ctx.JSON(200, m)
}

// getTemplatesWithFolder handles getting templates by a folder
func (s *Server) getTemplatesWithFolder(ctx echo.Context, folder string) error {
	rows, err := s.db.GetTemplatesByFolder(context.Background(), folder)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get templates from db").Error())
	}
	response := make([]GetTemplatesResponse, 0, len(rows))
	for _, row := range rows {
		response = append(response, GetTemplatesResponse{
			ID:        row.ID,
			Name:      row.Name,
			Folder:    folder,
			Path:      row.Path,
			Createdat: row.Createdat,
			Updatedat: row.Updatedat,
		})
	}
	return ctx.JSON(200, response)
}

// getTemplatesWithSearchKey handles getting templates by a search key for path
func (s *Server) getTemplatesWithSearchKey(ctx echo.Context, searchKey string) error {
	page, size := paginationDataFromContext(ctx)

	rows, err := s.db.GetTemplatesBySearchKey(context.Background(), dbsql.GetTemplatesBySearchKeyParams{
		Column1:   sql.NullString{String: searchKey, Valid: true},
		SqlOffset: page * size,
		SqlLimit:  size,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get templates from db").Error())
	}
	response := make([]GetTemplatesResponse, 0, len(rows))
	for _, row := range rows {
		response = append(response, GetTemplatesResponse{
			ID:        row.ID,
			Name:      row.Name,
			Folder:    row.Folder,
			Path:      row.Path,
			Createdat: row.Createdat,
			Updatedat: row.Updatedat,
		})
	}
	var totalCount int
	s.scans.Dbraw.Pool.QueryRow(context.Background(), "select count(id) from \"public\".templates where path LIKE '%'||$1||'%' and  templates.path like '%.yaml'", searchKey).Scan(&totalCount)
	m := make(map[string]interface{})
	m["total"] = totalCount
	m["data"] = response
	return ctx.JSON(200, m)
}

// UpdateTemplateRequest is a request for /templates update
type UpdateTemplateRequest struct {
	Contents string `json:"contents"`
	Path     string `json:"path"`
}

// UpdateTemplate handles /templates updating route
func (s *Server) UpdateTemplate(ctx echo.Context) error {
	var body UpdateTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	if _, err := templates.Parse(strings.NewReader(body.Contents), "", nil, *testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{})); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse template").Error())
	}
	err := s.db.UpdateTemplate(context.Background(), dbsql.UpdateTemplateParams{
		Contents:  body.Contents,
		Updatedat: time.Now(),
		Path:      body.Path,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not update template to db").Error())
	}
	return nil
}

// AddTemplateRequest is a request for /templates addition
type AddTemplateRequest struct {
	Contents string `json:"contents"`
	Path     string `json:"path"`
	Folder   string `json:"folder"`
}

// AddTemplate handles /templates addition route
func (s *Server) AddTemplate(ctx echo.Context) error {
	var body AddTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("反序列化失败，原始错误信息：%s", err.Error()))
	}
	//if tpl, err := templates.Parse(strings.NewReader(body.Contents), "", nil, *testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{})); err != nil {
	//	return echo.NewHTTPError(400, errors.Wrap(err, "could not parse template").Error())
	//} else if err = parsers.ValidateTemplateFields(tpl); err != nil {
	//	return echo.NewHTTPError(400, errors.Wrap(err, "could not parse template").Error())
	//}
	tpl, err := parsers.CheckTemplate(body.Contents)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse template").Error())
	} else if err = parsers.ValidateTemplateFields(tpl); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("POC模板校验失败，原始错误信息：%s", err.Error()))
	}

	id, err := s.db.AddTemplate(context.Background(), dbsql.AddTemplateParams{
		Contents: body.Contents,
		Folder:   body.Folder,
		Path:     body.Path,
		Name:     tpl.ID,
	})
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("POC数据库持久化失败，原始错误信息：%s", err.Error()))
	}
	return ctx.JSON(200, map[string]int64{"id": id})
}

// DeleteTemplateRequest is a request for /templates deletion
type DeleteTemplateRequest struct {
	Ids []int `json:"ids"`
}

// DeleteTemplate handles /templates deletion route
func (s *Server) DeleteTemplate(ctx echo.Context) error {
	var body DeleteTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("反序列化失败，原始错误信息：%s", err.Error()))
	}
	err := s.db.DeleteTemplate(context.Background(), body.Ids)
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("数据库处理失败，原始错误信息：%s", err.Error()))
	}
	return err
}

// GetTemplatesRaw handlers /templates content retrieval route
func (s *Server) GetTemplatesRaw(ctx echo.Context) error {
	templatePath := ctx.QueryParam("path")
	if templatePath == "" {
		return echo.NewHTTPError(500, "no path specified for template")
	}
	contents, err := s.db.GetTemplateContents(context.Background(), templatePath)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get template from db").Error())
	}
	return ctx.String(200, contents)
}

// ExecuteTemplateRequest is a request for /templates execution
type ExecuteTemplateRequest struct {
	Content string `json:"content"`
	Target  string `json:"target"`
}

// ExecuteTemplateResponse is a response for /templates execution
type ExecuteTemplateResponse struct {
	Output []*output.ResultEvent `json:"output,omitempty"`
	Debug  map[string]string     `json:"debug"` // Contains debug request response kv pairs
}

// ExecuteTemplate handles /templates execution route
func (s *Server) ExecuteTemplate(ctx echo.Context) error {
	var body ExecuteTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	template, err := templates.Parse(strings.NewReader(body.Content), "", nil, *testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{}))
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not parse template").Error())
	}
	var results []*output.ResultEvent
	debugData := make(map[string]string)

	err = template.Executer.ExecuteWithResults(body.Target, func(event *output.InternalWrappedEvent) {
		results = append(results, event.Results...)
		if event.Debug != nil {
			debugData[event.Debug.Request] = event.Debug.Response
		}
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not execute template").Error())
	}
	resp := &ExecuteTemplateResponse{Debug: debugData, Output: results}
	return ctx.JSON(200, resp)
}

// File Upload handlers /file upload route
func (s *Server) FileUpload(ctx echo.Context) error {
	form, err := ctx.MultipartForm()
	if err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("读取FORM信息失败，原始错误信息：%s", err.Error()))
	}

	files := form.File["files"]
	ids := make([]int64, 0, len(files))
	errFiles := make([]string, 0, len(files))
	for i := range files {
		src, err := files[i].Open()
		if err != nil {
			errFiles = append(errFiles, files[i].Filename+fmt.Sprintf("打开文件失败，原始错误信息：%s", err.Error()))
			continue
		}
		defer src.Close()

		buf := new(bytes.Buffer)
		buf.ReadFrom(src)
		FileContents := buf.String()

		tpl, err := parsers.CheckTemplate(FileContents)
		if err != nil {
			errFiles = append(errFiles, files[i].Filename+fmt.Sprintf("转换失败：%s", err.Error()))
			continue
		} else if err = parsers.ValidateTemplateFields(tpl); err != nil {
			errFiles = append(errFiles, files[i].Filename+fmt.Sprintf("校验失败：%s", err.Error()))
			continue
		}

		id, err := s.db.AddTemplate(context.Background(), dbsql.AddTemplateParams{
			Contents: FileContents,
			Folder:   ctx.FormValue("folder"),
			Path:     fmt.Sprintf("%v/%v.yaml", ctx.FormValue("path"), files[i].Filename),
			Name:     files[i].Filename,
		})

		if err != nil {
			errFiles = append(errFiles, files[i].Filename+"添加POC数据库失败,重复文件名")
			continue
		} else {
			ids = append(ids, id)
		}

	}
	if len(errFiles) > 0 {
		errMsg := fmt.Sprintf("成功保存%d条，失败%d条：\n", len(ids), len(errFiles))
		for i := range errFiles {
			errMsg += errFiles[i] + "\n"
		}
		return echo.NewHTTPError(500, errMsg)
	}
	return ctx.JSON(200, ids)

}
