package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

const baseDir = "data"

func main() {
	err := os.MkdirAll(filepath.Join(baseDir, "ID"), 0750)
	if err != nil {
		log.Fatalf("failed to create folders: %q", err)
	}

	index, err := http.DefaultClient.Get("https://vuln.go.dev/index.json")
	if err != nil {
		log.Fatalf("failed to get index: %q", err)
	}

	defer index.Body.Close()
	body, err := io.ReadAll(index.Body)
	if err != nil {
		log.Fatalf("failed to read index body: %q", err)
	}

	err = os.WriteFile(filepath.Join(baseDir, "index.json"), body, 0660)
	if err != nil {
		log.Fatalf("failed to save index: %q", err)
	}

	var indexDB map[string]time.Time
	err = json.Unmarshal(body, &indexDB)
	if err != nil {
		log.Fatalf("failed to parse index body: %q", err)
	}

	vc, err := client.NewClient([]string{"https://vuln.go.dev"}, client.Options{})
	if err != nil {
		log.Fatalf("failed to init Vuln Client: %q", err)
	}

	var wg sync.WaitGroup

	reports := make(chan []*osv.Entry, 100)
	for modulePath, updated := range indexDB {
		wg.Add(1)
		go func(m string, u time.Time) {
			defer wg.Done()
			reports <- getVulnReport(vc, m, u)
		}(modulePath, updated)
	}

	go func() {
		ids := make(map[string]struct{})
		for batch := range reports {
			for i := range batch {
				if _, ok := ids[batch[i].ID]; !ok {
					ids[batch[i].ID] = struct{}{}
					entData, err := json.MarshalIndent(batch[i], "", "  ")
					if err != nil {
						log.Printf("warn: failed to marshal %s - %q", batch[i].ID, err)
						continue
					}

					err = os.WriteFile(filepath.Join(baseDir, "ID", batch[i].ID + ".json"), entData, 0640)
					if err != nil {
						log.Printf("warn: failed to save %s - %q", batch[i].ID, err)
						continue
					}
				}
			}
		}
	}()

	wg.Wait()
	close(reports)
}

func getVulnReport(vc client.Client, modulePath string, updated time.Time) []*osv.Entry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fsPath, err := client.EscapeModulePath(modulePath)
	if err != nil {
		log.Printf("warn: invalid go module path: %s - %q", fsPath, err)
		return nil
	}

	reports, err := vc.GetByModule(ctx, modulePath)
	if err != nil {
		log.Printf("warn: failed to get reports for %s - %q", modulePath, err)
		return nil
	}

	reportsBytes, err := json.MarshalIndent(&reports, "", "  ")
	if err != nil {
		log.Printf("warn: failed to get parse for %s - %q", modulePath, err)
		return nil
	}

	dir := filepath.Dir(fsPath)
	dir = filepath.Join(baseDir, dir)
	filename := filepath.Base(fsPath) + ".json"

	err = os.MkdirAll(dir, 0755)
	if err != nil {
		log.Printf("warn: failed to create %s - %q", dir, err)
		return nil
	}

	err = os.WriteFile(filepath.Join(dir, filename), reportsBytes, 0640)
	if err != nil {
		log.Printf("warn: failed to save %s - %q", filename, err)
		return nil
	}

	return reports
}
