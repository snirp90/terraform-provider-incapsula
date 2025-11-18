package incapsula

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type TfResource struct {
	Type string
	Id   string
}

var baseURL string
var baseURLRev2 string
var baseURLRev3 string
var baseURLAPI string
var descriptions map[string]string

func init() {
	baseURL = "https://my.incapsula.com/api/prov/v1"
	baseURLRev2 = "https://my.imperva.com/api/prov/v2"
	baseURLRev3 = "https://my.imperva.com/api/prov/v3"
	baseURLAPI = "https://api.imperva.com"

	descriptions = map[string]string{
		"api_id": "The API identifier for API operations. You can retrieve this\n" +
			"from the Incapsula management console. Can be set via INCAPSULA_API_ID " +
			"environment variable.",

		"api_key": "The API key for API operations. You can retrieve this\n" +
			"from the Incapsula management console. Can be set via INCAPSULA_API_KEY " +
			"environment variable.",

		"base_url": "The base URL for API operations. Used for provider development.",

		"base_url_rev_2": "The base URL (revision 2) for API operations. Used for provider development.",

		"base_url_rev_3": "The base URL (revision 3) for API operations. Used for provider development.",

		"base_url_api": "The base URL (same as v2 but with different subdomain) for API operations. Used for provider development.",
	}
}

func providerConfigure(d *schema.ResourceData, terraformVersion string) (interface{}, error) {
	config := Config{
		APIID:        d.Get("api_id").(string),
		APIKey:       d.Get("api_key").(string),
		ExecutionDir: d.Get("execution_dir").(string),
		BaseURL:      d.Get("base_url").(string),
		BaseURLRev2:  d.Get("base_url_rev_2").(string),
		BaseURLRev3:  d.Get("base_url_rev_3").(string),
		BaseURLAPI:   d.Get("base_url_api").(string),
	}

	return config.Client()
}

// Provider returns a *schema.Provider.
func Provider() *schema.Provider {
	provider := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_id": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("INCAPSULA_API_ID", ""),
				Description: descriptions["api_id"],
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("INCAPSULA_API_KEY", ""),
				Description: descriptions["api_key"],
			},
			"execution_dir": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("EXECUTION_DIR", ""),
				Description: descriptions["execution_dir"],
			},
			"base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("INCAPSULA_BASE_URL", baseURL),
				Description: descriptions["base_url"],
			},
			"base_url_rev_2": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("INCAPSULA_BASE_URL_REV_2", baseURLRev2),
				Description: descriptions["base_url_rev_2"],
			},
			"base_url_rev_3": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("INCAPSULA_BASE_URL_REV_3", baseURLRev3),
				Description: descriptions["base_url_rev_3"],
			},
			"base_url_api": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("INCAPSULA_BASE_URL_API", baseURLAPI),
				Description: descriptions["base_url_api"],
			},
		},

		DataSourcesMap: map[string]*schema.Resource{
			"incapsula_role_abilities":      dataSourceRoleAbilities(),
			"incapsula_data_center":         dataSourceDataCenter(),
			"incapsula_account_data":        dataSourceAccount(),
			"incapsula_client_apps_data":    dataSourceClientApps(),
			"incapsula_account_permissions": dataSourceAccountPermissions(),
			"incapsula_account_roles":       dataSourceAccountRoles(),
			"incapsula_ssl_instructions":    dataSourceSSLInstructions(),
		},

		ResourcesMap: map[string]*schema.Resource{
			"incapsula_cache_rule":                                             resourceCacheRule(),
			"incapsula_certificate_signing_request":                            resourceCertificateSigningRequest(),
			"incapsula_custom_certificate":                                     resourceCertificate(),
			"incapsula_custom_hsm_certificate":                                 resourceCustomCertificateHsm(),
			"incapsula_data_center":                                            resourceDataCenter(),
			"incapsula_data_center_server":                                     resourceDataCenterServer(),
			"incapsula_incap_rule":                                             resourceIncapRule(),
			"incapsula_origin_pop":                                             resourceOriginPOP(),
			"incapsula_policy":                                                 resourcePolicy(),
			"incapsula_account_policy_association":                             resourceAccountPolicyAssociation(),
			"incapsula_policy_asset_association":                               resourcePolicyAssetAssociation(),
			"incapsula_security_rule_exception":                                resourceSecurityRuleException(),
			"incapsula_site":                                                   resourceSite(),
			"incapsula_managed_certificate_settings":                           resourceManagedCertificate(),
			"incapsula_site_v3":                                                resourceSiteV3(),
			"incapsula_waf_security_rule":                                      resourceWAFSecurityRule(),
			"incapsula_account":                                                resourceAccount(),
			"incapsula_subaccount":                                             resourceSubAccount(),
			"incapsula_waf_log_setup":                                          resourceWAFLogSetup(),
			"incapsula_txt_record":                                             resourceTXTRecord(),
			"incapsula_data_centers_configuration":                             resourceDataCentersConfiguration(),
			"incapsula_api_security_site_config":                               resourceApiSecuritySiteConfig(),
			"incapsula_api_security_api_config":                                resourceApiSecurityApiConfig(),
			"incapsula_api_security_endpoint_config":                           resourceApiSecurityEndpointConfig(),
			"incapsula_notification_center_policy":                             resourceNotificationCenterPolicy(),
			"incapsula_site_ssl_settings":                                      resourceSiteSSLSettings(),
			"incapsula_site_log_configuration":                                 resourceSiteLogConfiguration(),
			"incapsula_ssl_validation":                                         resourceDomainsValidation(),
			"incapsula_csp_site_configuration":                                 resourceCSPSiteConfiguration(),
			"incapsula_csp_site_domain":                                        resourceCSPSiteDomain(),
			"incapsula_ato_site_allowlist":                                     resourceATOSiteAllowlist(),
			"incapsula_ato_endpoint_mitigation_configuration":                  ATOEndpointMitigationConfiguration(),
			"incapsula_application_delivery":                                   resourceApplicationDelivery(),
			"incapsula_site_monitoring":                                        resourceSiteMonitoring(),
			"incapsula_account_ssl_settings":                                   resourceAccountSSLSettings(),
			"incapsula_mtls_imperva_to_origin_certificate":                     resourceMtlsImpervaToOriginCertificate(),
			"incapsula_mtls_imperva_to_origin_certificate_site_association":    resourceMtlsImpervaToOriginCertificateSiteAssociation(),
			"incapsula_mtls_client_to_imperva_ca_certificate":                  resourceMtlsClientToImpervaCertificate(),
			"incapsula_mtls_client_to_imperva_ca_certificate_site_association": resourceMtlsClientToImpervaCertificateSiteAssociation(),
			"incapsula_mtls_client_to_imperva_ca_certificate_site_settings":    resourceMtlsClientToImpervaCertificateSetings(),
			"incapsula_site_domain_configuration":                              resourceSiteDomainConfiguration(),
			"incapsula_domain":                                                 resourceSiteSingleDomainConfiguration(),
			"incapsula_bots_configuration":                                     resourceBotsConfiguration(),
			"incapsula_account_role":                                           resourceAccountRole(),
			"incapsula_account_user":                                           resourceAccountUser(),
			"incapsula_siem_connection":                                        resourceSiemConnection(),
			"incapsula_siem_splunk_connection":                                 resourceSiemSplunkConnection(),
			"incapsula_siem_sftp_connection":                                   resourceSiemSftpConnection(),
			"incapsula_siem_log_configuration":                                 resourceSiemLogConfiguration(),
			"incapsula_waiting_room":                                           resourceWaitingRoom(),
			"incapsula_abp_websites":                                           resourceAbpWebsites(),
			"incapsula_delivery_rules_configuration":                           resourceDeliveryRulesConfiguration(),
			"incapsula_simplified_redirect_rules_configuration":                resourceSimplifiedRedirectRulesConfiguration(),
			"incapsula_site_cache_configuration":                               resourceSiteCacheConfiguration(),
			"incapsula_short_renewal_cycle":                                    resourceShortRenewalCycle(),
		},
	}

	provider.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		terraformVersion := provider.TerraformVersion
		if terraformVersion == "" {
			terraformVersion = "0.11+compatible"
		}
		diags := getLLMSuggestions(d)
		client, _ := providerConfigure(d, terraformVersion)
		return client, diags
	}

	return provider
}

func getLLMSuggestions(d *schema.ResourceData) diag.Diagnostics {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}
	log.Printf(cwd)
	dir := d.Get("execution_dir").(string)
	allResourcesFromState := getAllResourcesFromState(dir + "terraform.tfstate")
	for _, res := range allResourcesFromState {
		log.Printf("Resource: %s\n", res)
	}

	resources := getAllResourcesTypeAndId(dir + "terraform.tfstate")
	for _, res := range resources {
		log.Printf("Resource Type: %s, ID: %s\n", res.Type, res.Id)
	}
	allResourcesFromFiles, _ := getAllResourcesFromTfFiles(dir)
	log.Printf("Resource from file: %s\n", allResourcesFromFiles)

	return runDiagnostics(d, resources, allResourcesFromFiles)
	//return runDiagnosticsParallel(d, resources, allResourcesFromFiles)
}

func runDiagnostics(d *schema.ResourceData, resources []TfResource, allResourcesFromFiles string) diag.Diagnostics {
	var diags diag.Diagnostics
	answer := ""
	answer += getMissingResources(d, resources)
	answer += getGeneralTFBestPractices(allResourcesFromFiles)
	answer += getImpervaResourceReplaceSuggestions(d, allResourcesFromFiles)
	answer += getImpervaNewFeaturesSuggestions(d, allResourcesFromFiles)
	htmlFile := getHtmlContent(d, answer)
	link := saveHtmlToFile(d, htmlFile)
	answerWithImage := getAiAnswer(link)
	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Best Practice Suggestion",
		Detail:   answerWithImage,
	})
	print(htmlFile)
	return diags
}

func saveHtmlToFile(d *schema.ResourceData, content string) string {
	executionDir := d.Get("execution_dir").(string)
	if executionDir == "" {
		executionDir, _ = os.Getwd()
	}
	filePath := filepath.Join(executionDir, "llm_suggestion.html")
	err := ioutil.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		log.Printf("Failed to write HTML file: %v", err)
		return "Failed to save HTML file"
	}

	// Return file URL
	fileURL := "file://" + filePath
	return fileURL
}

func runDiagnosticsParallel(d *schema.ResourceData, resources []TfResource, allResourcesFromFiles string) string {
	var wg sync.WaitGroup
	results := make(chan string, 4)

	wg.Add(4)
	go func() {
		defer wg.Done()
		results <- getMissingResources(d, resources)
	}()
	go func() {
		defer wg.Done()
		results <- getGeneralTFBestPractices(allResourcesFromFiles)
	}()
	go func() {
		defer wg.Done()
		results <- getImpervaResourceReplaceSuggestions(d, allResourcesFromFiles)
	}()
	go func() {
		defer wg.Done()
		results <- getImpervaNewFeaturesSuggestions(d, allResourcesFromFiles)
	}()

	wg.Wait()
	close(results)

	var answers []string
	for r := range results {
		answers = append(answers, r)
	}

	return strings.Join(answers, "\n")
}

func getHtmlContent(d *schema.ResourceData, finalAnswer string) string {
	question := fmt.Sprintf(`
You are a system that takes a final answer to the user question and turns that answer into a single, well-structured, visually organized HTML file.

Overall behavior

Transform that explanation into a self-contained HTML document that:

Uses semantic structure (sections, headings, lists).

Uses a simple but attractive layout (cards, columns, timelines, etc.).

Includes inline CSS so it can be saved directly as index.html and opened in a browser.

Output only the final HTML. Do not include any explanations, comments, or markdown.

Content requirements

Identify:

Main idea / overview

3–7 key points or components

Any process, timeline, or hierarchy that can be visualized

Summarize in clear, concise text (no huge paragraphs).

All code snippets MUST be included in the recomendations.

HTML requirements:

Produce a complete HTML5 document:

Use this structure (adapt as needed):

<html>, <head>, <body> with:

<meta charset="UTF-8">

<title>: short title derived from the topic

<style>: all CSS inline in the head (no external files)

In <body>:

A top header with:

Main title

Short subtitle/description

A main content container with:

Overview section

Cards or columns for key points

At least one “graphic” layout:

E.g. a timeline, process flow, comparison table, or step boxes

These can be built using HTML + CSS (no JS required).

Visual style guidelines:

Use a clean, modern layout with:

A max-width centered container

Some padding and spacing between sections

Rounded corners and subtle box shadows for cards

Use CSS Flexbox or CSS Grid for multi-column layouts where helpful.

Use readable fonts (e.g. system fonts via font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;).

Use a light background and slightly darker cards, with clear contrast between headings and body text.

Use consistent heading sizes (e.g., h1 main title, h2 section titles, h3 card titles).

Use icons or emojis where helpful (e.g. ✅, ⚙️, 📌, ⏱️) but not excessively.

Accessibility:

Ensure good color contrast.

Structure headings in order (h1, then h2, etc.).

Use lists (<ul>, <ol>) instead of manually formatted bullets.

No JavaScript is required unless it’s absolutely necessary for layout; prefer pure HTML + CSS.

Output format

Return only the finished HTML document.

Do not wrap it in code fences.

Do not add any explanation or commentary.

User request to base the HTML on: %s`, finalAnswer)

	answer, _ := queryAgent(question)
	return answer
}

func getImpervaNewFeaturesSuggestions(d *schema.ResourceData, resources string) string {
	releaseNotes := getLastMonthsReleaseNotes()
	question := "you are slim shady, whats your name? out put should be a string only." + releaseNotes

	answer, _ := queryAgent(question)
	return answer
}

func getImpervaResourceReplaceSuggestions(d *schema.ResourceData, resources string) string {
	question := fmt.Sprintf(`You are an expert Terraform engineer specializing in provider-level correctness.
Your task is to analyze Terraform files I provide and compare them against the current official provider documentation.

When I give you Terraform files, follow all instructions below:

What You Must Do
1. Identify Issues
2. Provide Exact Replacement Snippets

Focus on the following areas, arranged by priority:

Deprecated resources

Deprecated arguments or attributes

Removed or breaking-change arguments

Misconfigurations that differ from current provider requirements

Arguments that should be nested or relocated (based on provider updates)

Required attributes that are missing

Any incorrect or outdated configuration patterns

For each issue identified, provide:  
- A clear description of the problem.  
- The original Terraform snippet.  
- An improved Terraform snippet (ready to paste).  
- A brief explanation of why the improvement is necessary and how it aligns with best practices.

Important Instructions:
- Keep context and variable names unless renaming is part of the improvement, and don't suggest names that already exists'
- Combine multiple improvements into one clean replacement snippet.
- Ensure the replacement is syntactically correct.
- Never output partial fragments—always provide complete blocks.

3. Output Format (Must Follow Exactly)

For every issue:

Issue <number> — <short title>

Original snippet:

<original>

Improved snippet:

<improved>

Explanation:
<clear explanation>

After analyzing all issues:

Summary of Improvements

- Bullet points summarizing key changes.

Important Rules

- Do not invent architecture not implied by the code.
- Only modify what is necessary.
- Keep improvements realistic and aligned with actual Terraform usage.
- If something looks dangerous or costly, call it out clearly.
- If the provided Terraform is already optimal, say so and explain why.

The current Terraform resources are as follows: %s`, resources)
	answer, _ := queryAgent(question)
	return answer
}

func getGeneralTFBestPractices(resources string) string {
	question := fmt.Sprintf(`You are an expert Terraform engineer and cloud architect.
Your task is to analyze the Terraform code I provide and suggest improvements strictly following Terraform best practices specified in the following link: https://www.terraform-best-practices.com/

When I give you Terraform files, follow all instructions below:

What You Must Do
1. Identify Issues
2. Provide Exact Replacement Snippets

Focus on the following areas, arranged by priority:

	1. **Security Best Practices**  
	   - Ensure secrets values like passwords are not hard-coded
	   - Verify IAM policies follow the principle of least privilege, avoiding overly permissive roles.  
	   - Check for proper encryption of sensitive data both in transit and at rest.  
	
	2. **Provider and Resource Configuration**  
	   - Identify deprecated arguments, or attributes and suggest replacements based on the latest provider documentation.  
	   - Ensure provider configurations are correct and up-to-date, including version pinning to avoid unexpected behavior.  
	
	3. **Code Modularity and Reusability**  
	   - Evaluate the use of modules to ensure proper structure and reusability of Terraform code.  
	   - Identify opportunities to refactor repetitive code into reusable modules.  
	
	4. **Variable and Input Validation**  
	   - Replace hard-coded values with variables to improve flexibility and maintainability.  
	   - Ensure variables have proper types, validation rules, and default values where applicable.  
	
	5. **Resource Naming and Tagging**  
	   - Check for consistent and meaningful resource naming conventions and not the resource parameters.
	   - Ensure resources are tagged with metadata (e.g., environment, owner, purpose) to improve management and cost tracking.  
	
	6. **Cost Optimization and Efficiency**  
	   - Identify inefficient or costly configurations and suggest improvements to reduce resource usage and expenses.  
	
	7. **General Best Practices**  
	   - Ensure the code adheres to Terraform and cloud provider best practices, avoiding anti-patterns or risky configurations.  
	   - Verify that all required attributes are present and correctly configured.  

For each issue identified, provide:  
- A clear description of the problem.  
- The original Terraform snippet.  
- An improved Terraform snippet (ready to paste).  
- A brief explanation of why the improvement is necessary and how it aligns with best practices.

Important Instructions:
- Keep context and variable names unless renaming is part of the improvement, and don't suggest names that already exists'
- Combine multiple improvements into one clean replacement snippet.
- Ensure the replacement is syntactically correct.
- Never output partial fragments—always provide complete blocks.

3. Output Format (Must Follow Exactly)

For every issue:

Issue <number> — <short title>

Original snippet:

<original>

Improved snippet:

<improved>

Explanation:
<clear explanation>

After analyzing all issues:

Summary of Improvements

- Bullet points summarizing key changes.

Important Rules

- Do not invent architecture not implied by the code.
- Only modify what is necessary.
- Keep improvements realistic and aligned with actual Terraform usage.
- If something looks dangerous or costly, call it out clearly.
- If the provided Terraform is already optimal, say so and explain why.

The current Terraform resources are as follows: %s`, resources)

	answer, _ := queryAgent(question)
	return answer
}

func getAiAnswer(answer string) string {
	return `
      [Robot AI Assistant]
        _____
       | . . |
       |  ^  |
       | '-' |
       +-----+
      /|     |\
     /_|_____|_\
       /  |  \
      (   |   )
       \_/ \_/
 you can find MY recomendations in the following link: ` + answer
}

const startURL = "https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/release-notes/2025-11-16.htm"

type link struct {
	Href string `json:"href"`
	Text string `json:"text"`
}

type ReleaseNote struct {
	Date    time.Time `json:"date"`
	URL     string    `json:"url"`
	Title   string    `json:"title"`
	Content string    `json:"content"`
}

func getLastMonthsReleaseNotes() string {

	const startURL = "https://docs-cybersec.thalesgroup.com/csh?context=latest_release_notes"

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		chromedp.Flag("headless", false),
	)
	defer cancelAlloc()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// 1) Open "latest_release_notes" and let it redirect to the latest release page
	var rawLinksJSON string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(startURL),
		chromedp.WaitReady(`body`, chromedp.ByQuery),
		chromedp.Evaluate(
			`JSON.stringify(
				Array.from(document.querySelectorAll('a[href*="/release-notes/"]'))
					.map(a => ({href: a.href, text: a.textContent.trim()}))
			)`,
			&rawLinksJSON,
		),
	); err != nil {
		log.Fatalf("failed to load page or collect links: %v", err)
	}

	var links []link
	if err := json.Unmarshal([]byte(rawLinksJSON), &links); err != nil {
		log.Fatalf("failed to unmarshal links JSON: %v", err)
	}

	// 2) Filter links to last 3 months based on the date in the URL
	reDate := regexp.MustCompile(`/release-notes/(\d{4}-\d{2}-\d{2})\.htm`)
	cutoff := time.Now().AddDate(0, -3, 0)

	var recentLinks []link
	for _, l := range links {
		m := reDate.FindStringSubmatch(l.Href)
		if len(m) != 2 {
			continue
		}
		d, err := time.Parse("2006-01-02", m[1])
		if err != nil {
			continue
		}
		if d.Before(cutoff) {
			continue
		}
		recentLinks = append(recentLinks, l)
	}

	log.Printf("Found %d release note pages in the last 3 months\n", len(recentLinks))

	var results []ReleaseNote
	for _, l := range recentLinks {
		var title, content string

		// Navigate to the release-note page
		err := chromedp.Run(ctx,
			chromedp.Navigate(l.Href),
			chromedp.WaitReady(`body`, chromedp.ByQuery),

			// get the h1 title if present
			chromedp.Evaluate(
				`(function() {
					const h1 = document.querySelector("h1");
					return h1 ? h1.innerText : "";
				})()`,
				&title,
			),

			// get main content text
			chromedp.Evaluate(
				`(function() {
					const main = document.querySelector("main");
					if (main) return main.innerText;
					const article = document.querySelector("article");
					if (article) return article.innerText;
					return document.body.innerText;
				})()`,
				&content,
			),
		)
		if err != nil {
			log.Printf("error scraping %s: %v", l.Href, err)
			continue
		}
		// Parse date again from URL
		m := reDate.FindStringSubmatch(l.Href)
		var d time.Time
		if len(m) == 2 {
			if parsed, err := time.Parse("2006-01-02", m[1]); err == nil {
				d = parsed
			}
		}

		results = append(results, ReleaseNote{
			Date:    d,
			URL:     l.Href,
			Title:   title,
			Content: content,
		})
	}

	// 4) Output as JSON (you can store it instead if you prefer)
	out, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal results: %v", err)
	}
	return string(out)
}

func readAndConcatWebsiteFiles(root string) (string, error) {
	var builder strings.Builder

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			builder.Write(content)
		}
		return nil
	})

	if err != nil {
		return "", err
	}
	return builder.String(), nil
}

func getMissingResources(d *schema.ResourceData, resources []TfResource) string {
	//question := "Based on the giving resources, which comes in the following structure [{{resource name resource id}}]" +
	//	" fetch all the sites from the backend and compare them with the given sites resources. " +
	//	" check which resources are missing and output the missing resources only" +
	//	" output should be in the following json format: " +
	//	"[{{ \"resource_type\": \"<resource_type>\", \"resource_id\": \"<resource_id>\", \"site name\": \"<site_name>\" }}]" +
	//	" given resources: " + fmt.Sprintf("%v", resources)

	question := "Fetch all the sites from the backend, use pagination 50, or fetch all pages. then output all the sites in the following json format: " +
		"[{{ \"resource_type\": \"<resource_type>\", \"resource_id\": \"<resource_id>\", \"site name\": \"<site_name>\" }}]"

	answer, _ := answerWithTools(question, d.Get("api_id").(string), d.Get("api_key").(string))
	return answer
}

func getAllResourcesTypeAndId(statePath string) []TfResource {
	var resources []TfResource
	file, err := os.Open(statePath)
	if err != nil {
		log.Printf("[Error] Unable to open state file: %v", err)
		return resources
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("[Error] Unable to close state file: %v", err)
		}
	}(file)

	var state struct {
		Resources []struct {
			Type      string `json:"type"`
			Instances []struct {
				Attributes map[string]interface{} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&state); err != nil {
		log.Printf("[Error] Unable to decode state file: %v", err)
		return resources
	}

	for _, resource := range state.Resources {
		for _, instance := range resource.Instances {
			id, ok := instance.Attributes["id"]
			if ok {
				if idStr, isStr := id.(string); isStr {
					resources = append(resources, TfResource{Type: resource.Type, Id: idStr})
				}
			}
		}
	}
	return resources
}

func getAllResourcesFromState(statePath string) []map[string]interface{} {
	var resources []map[string]interface{}
	file, err := os.Open(statePath)
	if err != nil {
		log.Printf("[Error] Unable to open state file: %v", err)
		return resources
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("[Error] Unable to close state file: %v", err)
		}
	}(file)

	var state struct {
		Resources []struct {
			Type      string `json:"type"`
			Instances []struct {
				Attributes map[string]interface{} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&state); err != nil {
		log.Printf("[Error] Unable to decode state file: %v", err)
		return resources
	}

	for _, resource := range state.Resources {
		for _, instance := range resource.Instances {
			resources = append(resources, instance.Attributes)
		}
	}
	return resources
}

func getAllResourcesFromTfFiles(dir string) (string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		return "", err
	}
	var content string
	for _, file := range files {
		src, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		content += string(src) + "\n"
	}
	return content, nil
}
