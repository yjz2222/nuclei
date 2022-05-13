package core

import (
	"context"
	"log"
	"sync"

	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	generalTypes "github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Execute takes a list of templates/workflows that have been compiled
// and executes them based on provided concurrency options.
//
// All the execution logic for the templates/workflows happens in this part
// of the engine.
func (e *Engine) Execute(ctx context.Context, templates []*templates.Template, target InputProvider) *atomic.Bool {
	return e.ExecuteWithOpts(ctx, templates, target, false)
}

// ExecuteWithOpts executes with the full options
func (e *Engine) ExecuteWithOpts(ctx context.Context, templatesList []*templates.Template, target InputProvider, noCluster bool) *atomic.Bool {
	var finalTemplates []*templates.Template
	if !noCluster {
		finalTemplates, _ = templates.ClusterTemplates(templatesList, e.executerOpts)
	} else {
		finalTemplates = templatesList
	}

	tsAny := ctx.Value("ts")
	if tsAny == nil {
		log.Fatal("load fail~~!!!")
	}
	ts, ok := tsAny.(*sync.Map)
	if !ok {
		log.Fatal("断言失败~~!!!")
	}

	results := &atomic.Bool{}
	for _, template := range finalTemplates {
		if ctx.Err() != nil {
			break
		}
		templateType := template.Type()

		var wg *sizedwaitgroup.SizedWaitGroup
		if templateType == types.HeadlessProtocol {
			wg = e.workPool.Headless
		} else {
			wg = e.workPool.Default
		}

		wg.Add()
		go func(tpl *templates.Template, tsVar *sync.Map) {
			tsVar.Store(tpl.ID, "running")
			defer tsVar.Delete(tpl.ID)
			switch {
			case tpl.SelfContained:
				// Self Contained requests are executed here separately
				e.executeSelfContainedTemplateWithInput(tpl, results)
			default:
				// All other request types are executed here
				e.executeModelWithInput(ctx, templateType, tpl, target, results)
			}
			wg.Done()
		}(template, ts)
	}
	e.workPool.Wait()
	return results
}

// processSelfContainedTemplates execute a self-contained template.
func (e *Engine) executeSelfContainedTemplateWithInput(template *templates.Template, results *atomic.Bool) {
	match, err := template.Executer.Execute("")
	if err != nil {
		gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
	}
	results.CAS(false, match)
}

// executeModelWithInput executes a type of template with input
func (e *Engine) executeModelWithInput(ctx context.Context, templateType types.ProtocolType, template *templates.Template, target InputProvider, results *atomic.Bool) {
	wg := e.workPool.InputPool(templateType)

	var index uint32
	var currentInfoData *generalTypes.ResumeInfo
	var cleanupInFlight func(index uint32)
	var resumeFromInfoData *generalTypes.ResumeInfo

	if e.executerOpts.ResumeCfg != nil {
		e.executerOpts.ResumeCfg.Lock()
		currentInfo, ok := e.executerOpts.ResumeCfg.Current[template.ID]
		if !ok {
			currentInfo = &generalTypes.ResumeInfo{}
			e.executerOpts.ResumeCfg.Current[template.ID] = currentInfo
		}
		if currentInfo.InFlight == nil {
			currentInfo.InFlight = make(map[uint32]struct{})
		}
		resumeFromInfo, ok := e.executerOpts.ResumeCfg.ResumeFrom[template.ID]
		if !ok {
			resumeFromInfo = &generalTypes.ResumeInfo{}
			e.executerOpts.ResumeCfg.ResumeFrom[template.ID] = resumeFromInfo
		}
		e.executerOpts.ResumeCfg.Unlock()

		// track progression
		cleanupInFlight = func(index uint32) {
			currentInfo.Lock()
			delete(currentInfo.InFlight, index)
			currentInfo.Unlock()
		}
		currentInfoData = currentInfo
		resumeFromInfoData = resumeFromInfo
	}

	target.Scan(func(scannedValue string) bool {
		var skip bool

		// Best effort to track the host progression
		// skips indexes lower than the minimum in-flight at interruption time
		if resumeFromInfoData != nil {
			if resumeFromInfoData.Completed { // the template was completed
				gologger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Template already completed\n", template.ID, scannedValue)
				skip = true
			} else if index < resumeFromInfoData.SkipUnder { // index lower than the sliding window (bulk-size)
				gologger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Target already processed\n", template.ID, scannedValue)
				skip = true
			} else if _, isInFlight := resumeFromInfoData.InFlight[index]; isInFlight { // the target wasn't completed successfully
				gologger.Debug().Msgf("[%s] Repeating \"%s\": Resume - Target wasn't completed\n", template.ID, scannedValue)
				// skip is already false, but leaving it here for clarity
				skip = false
			} else if index > resumeFromInfoData.DoAbove { // index above the sliding window (bulk-size)
				// skip is already false - but leaving it here for clarity
				skip = false
			}

			currentInfoData.Lock()
			currentInfoData.InFlight[index] = struct{}{}
			currentInfoData.Unlock()
		}

		// Skip if the host has had errors
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(scannedValue) {
			return true
		}
		if ctx.Err() != nil {
			return false
		}

		wg.WaitGroup.Add()
		go func(index uint32, skip bool, value string) {
			defer wg.WaitGroup.Done()
			if cleanupInFlight != nil {
				defer cleanupInFlight(index)
			}
			if skip {
				return
			}

			var match bool
			var err error
			switch templateType {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(value, template.CompiledWorkflow)
			default:
				match, err = template.Executer.Execute(value)
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CAS(false, match)
		}(index, skip, scannedValue)

		index++
		return true
	})
	wg.WaitGroup.Wait()

	// on completion marks the template as completed
	if currentInfoData != nil {
		currentInfoData.Lock()
		currentInfoData.Completed = true
		currentInfoData.Unlock()
	}
}
