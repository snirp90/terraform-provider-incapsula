package incapsula

import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
	docs, _ := readAndConcatWebsiteFiles("website")
	rowAnswer := runDiagnostics(d, resources, docs, allResourcesFromFiles)
	//rowAnswer := runDiagnosticsParallel(d, resources, docs, allResourcesFromFiles)
	//return createHtmlReport(d, rowAnswer)
	return createResponse(d, rowAnswer)
}

func createResponse(d *schema.ResourceData, answer string) diag.Diagnostics {
	var diags diag.Diagnostics
	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Best Practice Suggestion",
		Detail:   answer,
	})
	print(answer)
	return diags
}

func runDiagnostics(d *schema.ResourceData, resources []TfResource, docs string, allResourcesFromFiles string) string {
	answer := ""
	answer = answer + "\n" + getMissingResources(d, resources)
	answer = answer + "\n" + getGeneralTFBestPractices(allResourcesFromFiles)
	//answer = answer + "\n" +  getImpervaResourceReplaceSuggestions(d, allResourcesFromFiles, docs)
	answer = answer + "\n" + getImpervaNewFeaturesSuggestions(d, allResourcesFromFiles, docs)
	return answer
}

func createHtmlReport(d *schema.ResourceData, finalAnswer string) diag.Diagnostics {
	var diags diag.Diagnostics
	answer := escapeBraces(finalAnswer)
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

func escapeBraces(answer string) string {
	answer = strings.ReplaceAll(answer, "{", "{{")
	answer = strings.ReplaceAll(answer, "}", "}}")
	return answer
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

func runDiagnosticsParallel(d *schema.ResourceData, resources []TfResource, docs string, allResourcesFromFiles string) string {
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
		results <- getImpervaResourceReplaceSuggestions(d, allResourcesFromFiles, docs)
	}()
	go func() {
		defer wg.Done()
		results <- getImpervaNewFeaturesSuggestions(d, allResourcesFromFiles, docs)
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

include BOTH original snippets and improved snippets. (if exists)

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

func getImpervaNewFeaturesSuggestions(d *schema.ResourceData, resources string, docs string) string {
	newFeatures := getNewFeatures()
	question := fmt.Sprintf(`You are an infrastructure-as-code assistant that helps upgrade a customer's Terraform configuration to use new features of a specific Terraform provider.

You will receive three kinds of inputs:
1) A list of NEW FEATURES for the provider (high level description, changelog, release notes, etc.).
2) The PROVIDER DOCUMENTATION (resources, data sources, arguments, example configs).
3) The CUSTOMER TERRAFORM FILE(S) (current .tf configuration).

Your goals:
- Understand what each new feature does and which provider resources / data sources / arguments are related to it.
- Inspect the customer’s existing Terraform configuration.
- Identify which new features are NOT yet used in the customer’s config.
- Propose concrete Terraform changes (new resources, data sources, arguments, or blocks) that would enable those missing features.

====================
WORKFLOW
====================

1. Parse the new features
- For each new feature:
  - Give it a short identifier (e.g., "Feature 1 – Enhanced logging").
  - Summarize what it does in 1–2 sentences.
  - Map it to specific provider documentation elements:
    - Resource types
    - Data sources
    - Arguments / nested blocks
    - Any version constraints

2. Map features to provider documentation
- For each feature:
  - Find the most relevant resource(s) and/or data source(s).
  - Note the required and important optional arguments.
  - Capture any limitations or prerequisites from the docs.
- Do not invent arguments or resources that are not present in the docs.
  - If something is unclear or ambiguous, explicitly say so.

3. Analyze the customer Terraform files
- Build a mental model of the configuration:
  - Which provider is used and what version constraints exist.
  - Which resources and data sources are already present.
  - Common naming patterns, tags, variable naming, modules, and conventions.
- For each new feature:
  - Check if it is already used in any resource, data source, or argument.
  - If it is used, briefly note where and how.
  - If it is NOT used, mark the feature as "missing".

4. Suggest additions/changes for missing features
For every feature marked as “missing”:
- Propose one or more Terraform changes that would enable the feature:
  - New resource blocks, data sources, or nested blocks.
  - New arguments on existing resources (if clearly safe and backwards-compatible).
- Follow these rules:
  - Preserve the customer’s style:
    - Naming conventions for resources and variables.
    - Tagging conventions.
    - Module structure and layout.
  - Minimize disruptions:
    - Prefer adding new blocks or arguments over refactoring everything.
    - Avoid destructive or breaking changes unless clearly required and explicitly flagged as such.
  - Be explicit about any assumptions you make about the environment.

5. Validate and annotate your suggestions
- For each suggested change:
  - Reference the relevant section(s) of the provider docs (resource name, argument names, behavior).
  - Explain briefly how this change activates the new feature.
  - Note any potential side effects, risks, or prerequisites (e.g., "requires provider version >= X.Y").

====================
OUTPUT FORMAT
====================

Respond using this structure:

1) Feature Coverage Summary
   - For each feature:
     - Feature ID:
     - Used in current config?: (Yes/No/Partial)
     - Short reasoning (1–2 sentences).

2) Proposed Terraform Changes
   For each feature with "No" or "Partial" usage:
   - Feature ID:
   - Rationale:
   - Suggested change type: (New resource / New data source / New arguments / Other)
   - Terraform snippet:
     "hcl
	# Your suggested HCL code here
	"
   - Notes:
     - Relevant provider resources/data sources/arguments:
     - Version requirements:
     - Risks or side effects:
     - Assumptions:

3) Optional Refactoring / Improvements (if applicable)
   - Only include if there are clearly beneficial and low-risk refactors.
   - List them as bullet points, each with:
     - What to change.
     - Why it’s beneficial.
     - Whether it is backwards-compatible.

====================
STYLE & CONSTRAINTS
====================

- Use valid HCL syntax in all snippets.
- Do NOT invent undocumented arguments, blocks, or resources.
- If you are unsure about something due to ambiguous docs or missing context, clearly say "UNCERTAIN" and explain why.
- Keep explanations concise but clear.
- Do not change or remove existing resources unless it is clearly necessary for the new feature; if you propose such a change, highlight it as potentially breaking.

The Imperva provider docs are: %s

The new features are: %s

The current Terraform code is as follows: %s

`, docs, newFeatures, resources)

	answer, _ := queryAgent(question)
	return answer
}

func getNewFeatures() string {
	return "site level managed certificate"
}

func getImpervaResourceReplaceSuggestions(d *schema.ResourceData, resources string, docs string) string {
	question := fmt.Sprintf(`
You are an expert Terraform engineer specializing in provider-level correctness.
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

	question := "Your task is to gather the full list of sites using the available MCP tool and compare it against the configuration provided in the user message." +
		" Fetch all sites using the tool with a page size of 100." +
		" After retrieving the remote sites, compare them to the sites defined in the provided configuration. " +
		" Produce a JSON array containing only the differences between the two sets. " +
		" Your output must contain only the following two sections, with no additional words, explanations, or text:\n" +
		" add these resources to your configuration:\nresource \"incapsula_site_v3\" \"<site_name>\" {{ name = \"<site_name>\" }}" +
		" run this import commands \nterraform import incapsula_site_v3.<site_name> <resource_id>" +
		" Output only these blocks with no additional words, explanations, or text." +
		" Only include sites that exist in one source but not the other." +
		" If a tool call is required to obtain the data, call it." +
		" this is the provided configuration: " + fmt.Sprintf("%v", resources)

	sitesAnswer, _ := answerWithTools(question, d.Get("api_id").(string), d.Get("api_key").(string))

	//question := "Your task is to gather the full list of rules using the available MCP tool and compare it against the configuration provided in the user message." +
	//	" Fetch all the account rules using the tool with a page size of 100." +
	//	" After retrieving the remote rules, compare them to the rules defined in the provided configuration. " +
	//	" Produce a JSON array containing only the differences between the two sets. " +
	//	" Your output must contain only the following two sections, with no additional words, explanations, or text. replace the all the spaces in the rule name with _:\n" +
	//	" add these resources to your configuration:" +
	//	" \nresource \"incapsula_incap_rule\" \"<rule_name>\" {{ name = \"<rule_name>\" site_id = \"<site_id>\" action = \"<action>\" filter = \"<filter>\" enabled = \"<enabled>\"  }}" +
	//	" run this import commands \nterraform import incapsula_incap_rule.<rule_name> <resource_id>" +
	//	" Output only these blocks with no additional words, explanations, or text." +
	//	" Only include sites that exist in one source but not the other." +
	//	" If a tool call is required to obtain the data, call it." +
	//	" this is the provided configuration: " + fmt.Sprintf("%v", resources)
	//
	//rulesAnswer, _ := answerWithTools(question, d.Get("api_id").(string), d.Get("api_key").(string))

	return sitesAnswer
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
