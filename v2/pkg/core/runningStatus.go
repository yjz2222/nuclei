package core

import (
	"github.com/spf13/cast"
	"sync"
	"time"
)

/*
临时处理
*/
var RunningStatus []map[string]interface{}

func SetTemplateStatus(tplID string, status int) {
	for i := range RunningStatus {
		if cast.ToString(RunningStatus[i]["templateId"]) == tplID {
			RunningStatus[i]["status"] = status
			return
		}
	}
	m := make(map[string]interface{})
	m["templateId"] = tplID
	m["status"] = status
	RunningStatus = append(RunningStatus, m)
}

func CleanRunningStatus() {
	for i := range RunningStatus {
		if cast.ToInt(RunningStatus[i]["status"]) != 4 {
			RunningStatus[i]["status"] = 4
			AddTemplateTimestamp(cast.ToString(RunningStatus[i]["templateId"]), "结束时间", "#409EFF", "", 0)
		}
	}
}

//var TemplateTimestamp map[string][]Stamp
var TemplateTimestamp *sync.Map

type Stamp struct {
	Content   string
	Timestamp string
	Color     string
	Status    int
	Msg       string
}

func AddTemplateTimestamp(tplId, ct, color, msg string, status int) {
	s := Stamp{
		Content:   ct,
		Color:     color,
		Status:    status,
		Timestamp: time.Now().Format("2006-01-02 15:04:05.000000000"),
		Msg:       msg,
	}
	v := []Stamp{}
	TemplateTimestamp.Range(func(key, value interface{}) bool {
		if cast.ToString(key) == tplId {
			v = value.([]Stamp)
			return false
		}
		return true
	})
	v = append(v, s)
	TemplateTimestamp.Store(tplId, v)
}
