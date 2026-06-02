package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	ismCatalogURL = "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/main/ISM_E8_ML1-baseline-resolved-profile_catalog.yaml"
	cacheFile     = ".ism-catalog-cache.json"
	userAgent     = "cicd-gate-ism-diff/0.3.3"
)

// ismDiffCmd represents the ism-diff command
var ismDiffCmd = &cobra.Command{
	Use:   "ism-diff",
	Short: "Monitor ASD ISM catalog for changes",
	Long: `Downloads the latest ISM E8 ML1 catalog from ASD's GitHub OSCAL repository
and compares it against a cached snapshot. Reports when ASD adds, changes,
or removes controls.

The cache is stored at ~/.hermes/.ism-catalog-cache.json.

Use --force to reset the cache and re-download.`,
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")

		usr, _ := user.Current()
		cachePath := filepath.Join(usr.HomeDir, ".hermes", cacheFile)

		// Load cached snapshot
		cached := loadISMCache(cachePath)

		// Fetch latest catalog
		fmt.Println("Fetching ISM E8 ML1 catalog from ASD OSCAL repository...")
		latest, err := fetchISMCatalog()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if cached == nil || force {
			// Baseline
			saveISMCache(cachePath, latest)
			fmt.Printf("\n✓ ISM catalog baseline saved. %d controls, %d groups.\n",
				latest.ControlCount, latest.GroupCount)
			fmt.Println("  Run again later to check for changes.")
			return
		}

		// Compare
		changes := compareISMCatalogs(cached, latest)
		now := time.Now().UTC().Format(time.RFC3339)

		if len(changes) == 0 {
			fmt.Println("\n✓ No changes detected since last check.")
			fmt.Printf("  Last checked: %s\n", cached.FetchedAt)
		} else {
			var news, changed, deprecated int
			for _, c := range changes {
				switch c.Type {
				case "NEW":
					news++
				case "CHANGED":
					changed++
				case "DEPRECATED":
					deprecated++
				}
			}

			fmt.Printf("\n⚠  %d change(s) detected since %s:\n", len(changes), cached.FetchedAt)
			if news > 0 {
				fmt.Printf("   %d new controls\n", news)
			}
			if changed > 0 {
				fmt.Printf("   %d changed controls\n", changed)
			}
			if deprecated > 0 {
				fmt.Printf("   %d deprecated controls\n", deprecated)
			}
			fmt.Println()

			for _, c := range changes {
				fmt.Printf("  %s %s\n", c.Type, c.ID)
				if c.OldTitle != "" {
					fmt.Printf("    Was: %s\n", c.OldTitle)
				}
				if c.NewTitle != "" {
					fmt.Printf("    Now: %s\n", c.NewTitle)
				}
				fmt.Println()
			}
		}

		latest.FetchedAt = now
		saveISMCache(cachePath, latest)
		fmt.Println("(cache updated)")
	},
}

// ISM catalog structures
type ismCacheEntry struct {
	ControlCount int                    `json:"control_count"`
	GroupCount   int                    `json:"group_count"`
	Controls     map[string]ismControl `json:"controls"`
	Hash         string                 `json:"hash"`
	FetchedAt    string                 `json:"fetched_at"`
}

type ismControl struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type ismChange struct {
	Type     string // "NEW", "DEPRECATED", "CHANGED"
	ID       string
	OldTitle string
	NewTitle string
}

func fetchISMCatalog() (*ismCacheEntry, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", ismCatalogURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading catalog: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	content := string(body)
	hash := fmt.Sprintf("%x", sha256.Sum256(body))

	// Parse YAML to extract control IDs and titles
	// Structure: groups -> groups -> controls [{id, title, parts}]
	controls := make(map[string]ismControl)
	groupCount := 0

	lines := strings.Split(content, "\n")
	var currentGroupTitle string

	for _, line := range lines {
		// Outer groups: "  - title:" (indent 2)
		if strings.HasPrefix(line, "  - title:") {
			groupCount++
		}

		// Subgroups: "    - title:" (indent 4)
		if strings.HasPrefix(line, "    - title:") {
			title := strings.TrimSpace(strings.TrimPrefix(line, "    - title:"))
			currentGroupTitle = strings.Trim(title, "\"'")
		}

		// Controls: "      - id:" (indent 8)
		if strings.HasPrefix(line, "        - id:") {
			ctrlID := strings.TrimSpace(strings.TrimPrefix(line, "        - id:"))
			ctrlID = strings.Trim(ctrlID, "\"' ")
			if ctrlID != "" && !strings.HasPrefix(ctrlID, "#") {
				if _, exists := controls[ctrlID]; !exists {
					controls[ctrlID] = ismControl{ID: ctrlID, Title: currentGroupTitle}
				}
			}
		}
	}

	entry := &ismCacheEntry{
		ControlCount: len(controls),
		GroupCount:   groupCount,
		Controls:     controls,
		Hash:         hash,
		FetchedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	return entry, nil
}

func loadISMCache(path string) *ismCacheEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cached ismCacheEntry
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil
	}
	return &cached
}

func saveISMCache(path string, entry *ismCacheEntry) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to create cache directory: %v\n", err)
		return
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to serialize cache: %v\n", err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write cache: %v\n", err)
	}
}

func compareISMCatalogs(old, new *ismCacheEntry) []ismChange {
	var changes []ismChange

	// New or changed
	for id, newCtrl := range new.Controls {
		if oldCtrl, exists := old.Controls[id]; !exists {
			changes = append(changes, ismChange{Type: "NEW", ID: id, NewTitle: newCtrl.Title})
		} else if oldCtrl.Title != newCtrl.Title {
			changes = append(changes, ismChange{
				Type: "CHANGED", ID: id,
				OldTitle: oldCtrl.Title, NewTitle: newCtrl.Title,
			})
		}
	}

	// Deprecated
	for id, oldCtrl := range old.Controls {
		if _, exists := new.Controls[id]; !exists {
			changes = append(changes, ismChange{Type: "DEPRECATED", ID: id, OldTitle: oldCtrl.Title})
		}
	}

	return changes
}

func init() {
	ismDiffCmd.Flags().BoolP("force", "f", false, "Force re-download and reset cache")
	rootCmd.AddCommand(ismDiffCmd)
}
