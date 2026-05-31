package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// ANSI escape sequence matcher for stripping conftest colour codes
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// ANSI colour codes
const (
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
	colorBold   = "\x1b[1m"
	colorDim    = "\x1b[2m"
	colorReset  = "\x1b[0m"
)

// Patterns for parsing conftest output lines
var (
	// Conftest failure line: "FAIL - path - package - message"
	failLineRe = regexp.MustCompile(`^(FAIL|FAILED)\s*-\s*(.+?)\s*-\s*(.+?)\s*-\s*(.+)$`)

	// Patterns for extracting framework metadata from Rego messages
	ruleIDRe    = regexp.MustCompile(`^([\w]+(?:-[\w]+)?-\d+):\s*`)
	ismRe       = regexp.MustCompile(`\[ISM-\d+\]`)
	e8Re        = regexp.MustCompile(`\[E8:\s*([^\]]+)\]`)
	tierRe      = regexp.MustCompile(`\[Tier:\s*(L[1-4])\]`)
	frameworkRe = regexp.MustCompile(`\[(ISM-\d+|E8:\s*[^\]]+)\]`)
)

// Remediation hints keyed by rule ID prefix
var remediationHints = map[string]string{
	"K8S-SEC-001": "Set securityContext.privileged: false in the container spec",
	"K8S-SEC-002": "Set securityContext.allowPrivilegeEscalation: false",
	"K8S-SEC-003": "Set securityContext.runAsNonRoot: true",
	"K8S-SEC-004": "Set securityContext.runAsUser to a non-zero UID (e.g., 1000)",
	"K8S-SEC-005": "Remove hostNetwork: true unless the pod requires host network access",
	"K8S-SEC-006": "Remove hostPID: true unless process isolation is not needed",
	"K8S-SEC-007": "Remove hostIPC: true unless IPC isolation is not needed",
	"K8S-SEC-008": "Add resources.limits to the container spec",
	"K8S-SEC-009": "Add resources.requests to the container spec",
	"K8S-SEC-010": "Add livenessProbe and readinessProbe to the container spec",
	"K8S-SEC-011": "Replace :latest tag with a pinned digest (@sha256:...)",
	"K8S-SEC-012": "Change imagePullPolicy to IfNotPresent or Never",
	"K8S-IAM-001": "Create a dedicated serviceAccount instead of using 'default'",
	"K8S-IAM-002": "Set automountServiceAccountToken: false if the pod doesn't need API access",
	"K8S-IAM-003": "Add a pod-level securityContext to the deployment spec",
	"K8S-IAM-004": "Set securityContext.runAsUser to a non-zero UID",
	"K8S-IAM-005": "Add nodeSelector or affinity rules to control pod scheduling",
	"K8S-IAM-006": "Create a PodDisruptionBudget for deployments with >1 replica",
	"K8S-IAM-007": "Drop ALL capabilities, then add only the ones needed",
	"K8S-IAM-008": "Add capabilities.drop: [\"ALL\"] and add back only what's needed",
	"K8S-IAM-009": "Restrict tolerations to specific values instead of using 'Exists'",
	"K8S-NET-001": "Configure TLS in the Ingress spec under spec.tls",
	"K8S-NET-002": "Use ClusterIP or NodePort instead of LoadBalancer unless external access is required",
	"K8S-NET-003": "Remove SSH port (22) from container ports — use kubectl exec instead",
	"K8S-NET-004": "Ensure PostgreSQL port (5432) is behind a firewall or use Cloud SQL proxy",
	"K8S-STO-001": "Avoid hostPath volumes — use PVCs or CSI drivers instead",
	"K8S-STO-002": "Set a sizeLimit on the emptyDir volume when using memory medium",
	"K8S-STO-003": "Mount secrets as volumes instead of environment variables",
	"DKR-001":   "Replace :latest tag with a pinned digest (@sha256:...)",
	"DKR-002":   "Use a non-privileged port (>=1024) and map it via the host",
	"DKR-003":   "Use a non-privileged container port and map it via the host",
	"SEC-001":   "Use a secrets manager (e.g., AWS Secrets Manager, Vault) instead of hardcoding keys",
	"SEC-002":   "Add sensitive = true to the variable definition",
}

const legalHeader = "" +
	colorBold + "CI/CD Gate — Compliance Posture Monitor" + colorReset + "\n" +
	colorDim + "Frameworks: ISM | E8 | SOCI" + colorReset + "\n" +
	colorDim + "Tier: L1 (Machine-Verified) | L2 (Evidence-Assisted) | L3 (Process-Mapped) | L4 (Advisory)" + colorReset + "\n\n" +
	colorYellow + "IMPORTANT:" + colorReset + " This tool monitors compliance posture.\n" +
	"It does " + colorBold + "NOT" + colorReset + " certify compliance. See " + colorCyan + "cicd-gate init" + colorReset + " for full disclaimer.\n\n"

const legalFooter = "\n" +
	colorDim + "---" + colorReset + "\n" +
	colorYellow + "Legal:" + colorReset + " Compliance posture monitoring — " + colorBold + "not" + colorReset + " a certification.\n" +
	"        Consult a qualified assessor for formal audit or certification.\n"

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run compliance policies against infrastructure-as-code files",
	Long: `Scan runs the configured Rego policies against infrastructure-as-code files
in the specified directory (or current directory if not specified).
It wraps conftest to evaluate policies and provides remediation hints.

Each violation includes:
  - Rule ID (e.g., K8S-SEC-001)
  - Framework mapping (ISM, E8, SOCI) embedded in the message
  - Verification tier (L1-L4) embedded in the message
  - Remediation hint (in Socratic mode)`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		socratic, _ := cmd.Flags().GetBool("socratic")
		policyPath, _ := cmd.Flags().GetString("policy")
		pack, _ := cmd.Flags().GetString("pack")

		conftestArgs := []string{"test", target}
		if policyPath != "" {
			conftestArgs = append(conftestArgs, "--policy", policyPath)
		}

		c := exec.Command("conftest", conftestArgs...)

		if socratic {
			var stdout, stderr bytes.Buffer
			c.Stdout = &stdout
			c.Stderr = &stderr

			// Print pack-specific header
			if pack == "essential-eight" {
				fmt.Print(colorBold + "Essential Eight Compliance Posture — Machine-Verified (L1)" + colorReset + "\n\n")
			} else {
				fmt.Print(legalHeader)
			}

			err := c.Run()

			if stdout.Len() > 0 {
				formatSocraticOutput(stdout.String(), pack)
			}
			if stderr.Len() > 0 {
				fmt.Print(colorDim)
				fmt.Print(stderr.String())
				fmt.Print(colorReset)
			}

			fmt.Print(legalFooter)

			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				return fmt.Errorf("conftest failed: %w", err)
			}
		} else {
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr

			if err := c.Run(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				return fmt.Errorf("conftest failed: %w", err)
			}
		}
		return nil
	},
}

// formatSocraticOutput parses conftest output and renders it with colours,
// framework IDs, tier labels, and remediation hints.
// If pack is set (e.g. "essential-eight"), only violations matching that pack are shown.
func formatSocraticOutput(output string, pack string) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var failCount, passCount, warnCount, skipCount int

	for scanner.Scan() {
		line := ansiRe.ReplaceAllString(scanner.Text(), "")

		// Try to match a conftest failure line
		if matches := failLineRe.FindStringSubmatch(line); len(matches) > 0 {
			msg := matches[4]
			file := matches[2]
			ruleID := extractRuleID(msg)

			// Skip if pack filter is active and this violation isn't in the pack
			if pack == "essential-eight" && !strings.Contains(msg, "[E8:") {
				skipCount++
				continue
			}

			failCount++

			// Extract framework and tier info
			frameworks := extractFrameworks(msg)
			tier := extractTier(msg)

			// Clean the message — remove tags already extracted
			cleanMsg := cleanupMessage(msg, ruleID)

			// Get remediation hint
			hint := remediationHints[ruleID]

			// Print failure
			fmt.Printf("  %s✖ %s%s\n", colorRed, ruleID, colorReset)
			fmt.Printf("    %sDescription:%s %s\n", colorBold, colorReset, cleanMsg)
			fmt.Printf("    %sFile:%s        %s\n", colorBold, colorReset, file)
			if len(frameworks) > 0 {
				fmt.Printf("    %sFrameworks:%s  %s\n", colorBold, colorReset, frameworks)
			}
			if tier != "" {
				fmt.Printf("    %sTier:%s        %s\n", colorBold, colorReset, tier)
			}
			if hint != "" {
				fmt.Printf("    %sFix:%s         %s\n", colorBold, colorReset, hint)
			}
			fmt.Println()

			continue
		}

		// Pass lines
		if strings.HasPrefix(line, "PASS") || strings.HasPrefix(line, "PASSED") {
			passCount++
			msg := strings.TrimSpace(strings.TrimPrefix(line, "PASS"))
			msg = strings.TrimPrefix(msg, "ED")
			msg = strings.TrimSpace(msg)
			// Remove leading " - path - package -" if present
			if parts := strings.SplitN(msg, "-", 3); len(parts) == 3 {
				msg = strings.TrimSpace(parts[2])
			}
			ruleID := extractRuleID(msg)
			if ruleID != "" {
				fmt.Printf("  %s✓ %s%s\n", colorGreen, ruleID, colorReset)
			} else {
				fmt.Printf("  %s✓ %s%s\n", colorGreen, "PASS", colorReset)
			}
			continue
		}

		// Warning lines
		if strings.HasPrefix(line, "WARN") {
			warnCount++
			fmt.Printf("  %s⚠ %s%s\n", colorYellow, line, colorReset)
			continue
		}

		// Skip conftest summary line — we'll print our own
		if strings.Contains(line, "failures") || strings.Contains(line, "tests") {
			continue
		}
	}

	// Print enriched summary
	fmt.Printf("  %s═══════════════════════════════════════%s\n", colorDim, colorReset)
	fmt.Printf("  %sSummary:%s\n", colorBold, colorReset)
	fmt.Printf("    %sFailed:%s  %s%d%s\n", colorRed, colorReset, colorBold, failCount, colorReset)
	if passCount > 0 {
		fmt.Printf("    %sPassed:%s  %s%d%s\n", colorGreen, colorReset, colorBold, passCount, colorReset)
	}
	if warnCount > 0 {
		fmt.Printf("    %sWarnings:%s %d\n", colorYellow, colorReset, warnCount)
	}
	fmt.Printf("    %sTotal:%s   %d\n", colorBold, colorReset, failCount+passCount)
}

// extractRuleID pulls the rule ID prefix from a Rego message
func extractRuleID(msg string) string {
	if match := ruleIDRe.FindStringSubmatch(msg); len(match) > 1 {
		return match[1]
	}
	return ""
}

// extractFrameworks pulls ISM and E8 tags from a message
func extractFrameworks(msg string) string {
	var parts []string
	if match := ismRe.FindString(msg); match != "" {
		parts = append(parts, match)
	}
	if match := e8Re.FindStringSubmatch(msg); len(match) > 1 {
		parts = append(parts, fmt.Sprintf("E8: %s", match[1]))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}

// extractTier pulls the tier label from a message
func extractTier(msg string) string {
	if match := tierRe.FindStringSubmatch(msg); len(match) > 1 {
		return match[1]
	}
	return ""
}

// cleanupMessage removes rule ID and framework tags from a message for display
func cleanupMessage(msg, ruleID string) string {
	result := msg
	// Remove rule ID prefix
	if ruleID != "" {
		result = strings.TrimPrefix(result, ruleID+": ")
	}
	// Remove framework tags
	result = frameworkRe.ReplaceAllString(result, "")
	result = tierRe.ReplaceAllString(result, "")
	result = strings.TrimSpace(result)
	// Clean up double spaces
	result = strings.Join(strings.Fields(result), " ")
	return result
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolP("socratic", "s", false, "Verbose output with colours, framework IDs, tier labels, and remediation hints")
	scanCmd.Flags().StringP("policy", "p", "", "Path to policy directory (default: ./policies)")
	scanCmd.Flags().StringP("pack", "", "", "Compliance pack filter (e.g. essential-eight)")
}
