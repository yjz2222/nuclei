package parsers

import (
	"fmt"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/cache"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
)

const (
	mandatoryFieldMissingTemplate = "必要字段 '%s' 缺失"
	invalidFieldFormatTemplate    = "无效的字段格式 '%s' (允许的字段格式为 %s)"
)

// LoadTemplate returns true if the template is valid and matches the filtering criteria.
func LoadTemplate(templatePath string, tagFilter *filter.TagFilter, extraTags []string) (bool, error) {

	template, templateParseError := ParseTemplate(templatePath)
	if templateParseError != nil {
		return false, templateParseError
	}
	core.TemplateTimestamp.Store(template.ID, make([]core.Stamp, 0, 8))
	core.SetTemplateStatus(template.ID, 1)
	core.AddTemplateTimestamp(template.ID, "开始时间", "#409EFF", "", 0)
	if len(template.Workflows) > 0 {
		core.SetTemplateStatus(template.ID, 4)
		core.AddTemplateTimestamp(template.ID, "结束时间", "#409EFF", "", 0)
		return false, nil
	}

	if validationError := ValidateTemplateFields(template); validationError != nil {
		stats.Increment(SyntaxErrorStats)
		return false, validationError
	}

	templateId := strings.ToLower(template.ID)

	return isTemplateInfoMetadataMatch(tagFilter, &template.Info, extraTags, template.Type(), templateId)
}

// LoadWorkflow returns true if the workflow is valid and matches the filtering criteria.
func LoadWorkflow(templatePath string) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath)
	if templateParseError != nil {
		return false, templateParseError
	}

	if len(template.Workflows) > 0 {
		if validationError := ValidateTemplateFields(template); validationError != nil {
			return false, validationError
		}
		return true, nil
	}

	return false, nil
}

func isTemplateInfoMetadataMatch(tagFilter *filter.TagFilter, templateInfo *model.Info, extraTags []string, templateType types.ProtocolType, templateId string) (bool, error) {
	templateTags := templateInfo.Tags.ToSlice()
	templateAuthors := templateInfo.Authors.ToSlice()
	templateSeverity := templateInfo.SeverityHolder.Severity

	match, err := tagFilter.Match(templateTags, templateAuthors, templateSeverity, extraTags, templateType, templateId)

	if err == filter.ErrExcluded {
		return false, filter.ErrExcluded
	}

	return match, err
}

func ValidateTemplateFields(template *templates.Template) error {
	info := template.Info

	var errors []string

	if utils.IsBlank(info.Name) {
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "name"))
	}

	if info.Authors.IsEmpty() {
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "author"))
	}

	if template.ID == "" {
		errors = append(errors, fmt.Sprintf(mandatoryFieldMissingTemplate, "id"))
	} else if !templateIDRegexp.MatchString(template.ID) {
		errors = append(errors, fmt.Sprintf(invalidFieldFormatTemplate, "id", templateIDRegexp.String()))
	}

	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, ", "))
	}

	return nil
}

var (
	parsedTemplatesCache *cache.Templates
	NoCacheUsage         bool
	ShouldValidate       bool
	fieldErrorRegexp     = regexp.MustCompile(`not found in`)
	templateIDRegexp     = regexp.MustCompile(`^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$`)
)

const (
	SyntaxWarningStats   = "syntax-warnings"
	SyntaxErrorStats     = "syntax-errors"
	RuntimeWarningsStats = "runtime-warnings"
)

func init() {
	NoCacheUsage = false
	parsedTemplatesCache = cache.New()

	stats.NewEntry(SyntaxWarningStats, "Found %d templates with syntax warning (use -validate flag for further examination)")
	stats.NewEntry(SyntaxErrorStats, "Found %d templates with syntax error (use -validate flag for further examination)")
	stats.NewEntry(RuntimeWarningsStats, "Found %d templates with runtime error (use -validate flag for further examination)")
}

// ParseTemplate parses a template and returns a *templates.Template structure
func ParseTemplate(templatePath string) (*templates.Template, error) {
	if value, err := parsedTemplatesCache.Has(templatePath); value != nil && !NoCacheUsage {
		return value.(*templates.Template), err
	}
	data, err := utils.ReadFromPathOrURL(templatePath)
	if err != nil {
		return nil, err
	}

	template := &templates.Template{}
	if err := yaml.UnmarshalStrict(data, template); err != nil {
		errString := err.Error()
		if !fieldErrorRegexp.MatchString(errString) {
			stats.Increment(SyntaxErrorStats)
			return nil, err
		}
		stats.Increment(SyntaxWarningStats)
		if ShouldValidate {
			gologger.Error().Msgf("Syntax warnings for template %s: %s", templatePath, err)
		} else {
			gologger.Warning().Msgf("Syntax warnings for template %s: %s", templatePath, err)
		}
	}
	if !NoCacheUsage {
		parsedTemplatesCache.Store(templatePath, template, nil)
	}
	return template, nil
}

func CheckTemplate(content string) (*templates.Template, error) {
	template := &templates.Template{}
	if err := yaml.UnmarshalStrict([]byte(content), template); err != nil {
		errString := err.Error()
		if !fieldErrorRegexp.MatchString(errString) {
			stats.Increment(SyntaxErrorStats)
			return nil, err
		}
		stats.Increment(SyntaxWarningStats)
		if ShouldValidate {
			gologger.Error().Msgf("Syntax warnings check for template : %s", err)
		} else {
			gologger.Warning().Msgf("Syntax warnings check for template : %s", err)
		}
		return nil, err
	}
	return template, nil
}
