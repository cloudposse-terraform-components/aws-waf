package test

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	awshelper "github.com/cloudposse/test-helpers/pkg/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ComponentSuite struct {
	helper.TestSuite
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)

	suite.AddDependency(t, "vpc", "default-test", nil)

	subdomain := strings.ToLower(random.UniqueId())
	inputs := map[string]interface{}{
		"zone_config": []map[string]interface{}{
			{
				"subdomain": subdomain,
				"zone_name": "components.cptest.test-automation.app",
			},
		},
	}
	suite.AddDependency(t, "dns-delegated", "default-test", &inputs)
	suite.AddDependency(t, "acm", "default-test", nil)
	suite.AddDependency(t, "alb/basic", "default-test", nil)
	suite.AddDependency(t, "alb/by-name", "default-test", nil)

	uniquesuffix := strings.ToLower(random.UniqueId())
	tagValue := "use-" + uniquesuffix
	albByTagsInput := map[string]interface{}{
		"tags": map[string]interface{}{
			"waf": tagValue,
		},
	}

	suite.AddDependency(t, "alb/by-tags", "default-test", &albByTagsInput)
	suite.AddDependency(t, "alb/by-component", "default-test", nil)
	helper.Run(t, suite)
}

func (s *ComponentSuite) TestBasic() {
	const component = "waf/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	client := awshelper.NewWAFClient(s.T(), awsRegion)

	uniquesuffix := strings.ToLower(random.UniqueId())

	albOptions := s.GetAtmosOptions("alb/basic", "default-test", nil)
	albArn := atmos.Output(s.T(), albOptions, "alb_arn")

	inputs := map[string]interface{}{
		"ssm_path_prefix": fmt.Sprintf("/waf/%s", uniquesuffix),
		"attributes": []string{
			uniquesuffix,
		},
		"association_resource_arns": []string{
			albArn,
		},
		"managed_rule_group_statement_rules": []map[string]interface{}{
			{
				"name":     "OWASP-10",
				"priority": 1,
				"statement": map[string]interface{}{
					"name":        "AWSManagedRulesCommonRuleSet",
					"vendor_name": "AWS",
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "OWASP-10",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"byte_match_statement_rules": []map[string]interface{}{
			{
				"name":     "block-specific-uri-" + uniquesuffix,
				"priority": 2,
				"action":   "block",
				"statement": map[string]interface{}{
					"field_to_match": map[string]interface{}{
						"uri_path": map[string]interface{}{},
					},
					"positional_constraint": "STARTS_WITH",
					"search_string":         "/admin",
					"text_transformation": []map[string]interface{}{
						{
							"priority": 1,
							"type":     "NONE",
						},
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-specific-uri",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"geo_allowlist_statement_rules": []map[string]interface{}{
			{
				"name":     "allow-us-traffic-" + uniquesuffix,
				"priority": 3,
				"action":   "block",
				"statement": map[string]interface{}{
					"country_codes": []string{"US"},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "allow-us-traffic",
					"sampled_requests_enabled":   false,
				},
			},
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	id := atmos.Output(s.T(), options, "id")
	assert.NotEmpty(s.T(), id)

	arn := atmos.Output(s.T(), options, "arn")
	assert.NotEmpty(s.T(), arn)

	webACL := getWebACLByIDAndName(s.T(), client, id, arn)
	require.NotNil(s.T(), webACL)
	require.NotEmpty(s.T(), webACL.Rules)

	assertOWASPRule(s.T(), webACL.Rules[0])
	assertBlockSpecificURIRule(s.T(), inputs["byte_match_statement_rules"].([]map[string]interface{})[0], webACL.Rules[1])
	assertAllowUSTrafficRule(s.T(), inputs["geo_allowlist_statement_rules"].([]map[string]interface{})[0], webACL.Rules[2])

	// Assert custom response body
	require.NotNil(s.T(), webACL.CustomResponseBodies)
	defaultResponse, exists := webACL.CustomResponseBodies["default_response"]
	require.True(s.T(), exists)
	assert.Equal(s.T(), "Access denied by WAF rules", *defaultResponse.Content)
	assert.Equal(s.T(), types.ResponseContentTypeTextPlain, defaultResponse.ContentType)

	// Assert default block response
	require.NotNil(s.T(), webACL.DefaultAction.Block)
	require.NotNil(s.T(), webACL.DefaultAction.Block.CustomResponse)
	// TODO: Uncomment when issue https://github.com/cloudposse-terraform-components/aws-waf/issues/15 is fixed
	// assert.Equal(t, "default_response", *webACL.DefaultAction.Block.CustomResponse.CustomResponseBodyKey)
	assert.EqualValues(s.T(), 403, *webACL.DefaultAction.Block.CustomResponse.ResponseCode)

	// Assert ALB association with WAF ACL
	listResourcesOutput, err := client.ListResourcesForWebACL(context.Background(), &wafv2.ListResourcesForWebACLInput{
		ResourceType: types.ResourceTypeApplicationLoadBalancer,
		WebACLArn:    &arn,
	})
	require.NoError(s.T(), err)
	require.NotNil(s.T(), listResourcesOutput.ResourceArns)
	assert.Len(s.T(), listResourcesOutput.ResourceArns, 1)
	assert.Contains(s.T(), listResourcesOutput.ResourceArns, albArn)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestByName() {
	const component = "waf/by-name"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	client := awshelper.NewWAFClient(s.T(), awsRegion)

	uniquesuffix := strings.ToLower(random.UniqueId())

	albOptions := s.GetAtmosOptions("alb/by-name", "default-test", nil)
	albArn := atmos.Output(s.T(), albOptions, "alb_arn")

	inputs := map[string]interface{}{
		"ssm_path_prefix": fmt.Sprintf("/waf/%s", uniquesuffix),
		"attributes": []string{
			uniquesuffix,
		},
		"geo_match_statement_rules": []map[string]interface{}{
			{
				"name":     "block-non-us-traffic-" + uniquesuffix,
				"priority": 1,
				"action":   "block",
				"statement": map[string]interface{}{
					"country_codes": []string{
						"CA",
						"MX",
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-non-us-traffic",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"ip_set_reference_statement_rules": []map[string]interface{}{
			{
				"name":     "block-ip-ranges-" + uniquesuffix,
				"priority": 2,
				"action":   "block",
				"statement": map[string]interface{}{
					"ip_set": map[string]interface{}{
						"description":        "Block specific IP addresses",
						"addresses":          []string{"192.0.2.0/24", "198.51.100.0/24"},
						"ip_address_version": "IPV4",
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-ip-ranges",
					"sampled_requests_enabled":   false,
				},
			},
			{
				"name":     "allow-trusted-ips-" + uniquesuffix,
				"priority": 3,
				"action":   "allow",
				"statement": map[string]interface{}{
					"ip_set": map[string]interface{}{
						"description":        "Allow trusted IP addresses",
						"addresses":          []string{"203.0.113.0/24", "198.51.100.128/25"},
						"ip_address_version": "IPV4",
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "allow-trusted-ips",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"rate_based_statement_rules": []map[string]interface{}{
			{
				"name":     "rate-limit-requests-" + uniquesuffix,
				"priority": 4,
				"action":   "block",
				"statement": map[string]interface{}{
					"limit":              2000,
					"aggregate_key_type": "IP",
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "rate-limit-requests",
					"sampled_requests_enabled":   false,
				},
			},
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	id := atmos.Output(s.T(), options, "id")
	assert.NotEmpty(s.T(), id)

	arn := atmos.Output(s.T(), options, "arn")
	assert.NotEmpty(s.T(), arn)

	webACL := getWebACLByIDAndName(s.T(), client, id, arn)
	require.NotNil(s.T(), webACL)
	require.NotEmpty(s.T(), webACL.Rules)

	assertBlockNonUSTrafficRule(s.T(), inputs["geo_match_statement_rules"].([]map[string]interface{})[0], webACL.Rules[0])
	assertBlockIPRangesRule(s.T(), inputs["ip_set_reference_statement_rules"].([]map[string]interface{})[0], webACL.Rules[1], client)
	assertAllowTrustedIPsRule(s.T(), inputs["ip_set_reference_statement_rules"].([]map[string]interface{})[1], webACL.Rules[2], client)
	assertRateLimitRequestsRule(s.T(), inputs["rate_based_statement_rules"].([]map[string]interface{})[0], webACL.Rules[3])

	// Assert ALB association with WAF ACL
	listResourcesOutput, err := client.ListResourcesForWebACL(context.Background(), &wafv2.ListResourcesForWebACLInput{
		ResourceType: types.ResourceTypeApplicationLoadBalancer,
		WebACLArn:    &arn,
	})
	require.NoError(s.T(), err)
	require.NotNil(s.T(), listResourcesOutput.ResourceArns)
	assert.Len(s.T(), listResourcesOutput.ResourceArns, 1)
	assert.Contains(s.T(), listResourcesOutput.ResourceArns, albArn)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestByTags() {
	const component = "waf/by-tags"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	client := awshelper.NewWAFClient(s.T(), awsRegion)

	uniquesuffix := strings.ToLower(random.UniqueId())

	albOptions := s.GetAtmosOptions("alb/by-tags", "default-test", nil)
	albArn := atmos.Output(s.T(), albOptions, "alb_arn")
	assert.NotEmpty(s.T(), albArn)


	albClient := awshelper.NewElbV2Client(s.T(), awsRegion)
	tags, err := albClient.DescribeTags(context.Background(), &elasticloadbalancingv2.DescribeTagsInput{
		ResourceArns: []string{albArn},
	})
	assert.NoError(s.T(), err)

	var tagValue string

	for _, tag := range tags.TagDescriptions[0].Tags {
		if strings.Contains(*tag.Key, "waf") {
			tagValue = *tag.Value
		}
	}

	// Create WAFv2 regexp set
	patternSet, err := awshelper.WafCreateRegexPatternSet(client,
		"test-regex-set-"+uniquesuffix,
		"Test regex pattern set",
		[]string{".*admin.*", ".*password.*"},
	)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), patternSet)
	regexpSetArn := *patternSet.ARN

	// Clean up regex set after test
	defer func() {
		err := deleteRegexPatternSet(client, patternSet)
		require.NoError(s.T(), err)
	}()

	ruleGroupName := "test-rule-group-" + uniquesuffix
	// Create WAFv2 rule group
	ruleGroup, err := createRuleGroup(client,
		ruleGroupName,
		"Test rule group",
		1000,
		"test-rule-group-metric",
	)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), ruleGroup)
	assert.Equal(s.T(), ruleGroupName, *ruleGroup.Name)
	ruleGroupArn := *ruleGroup.ARN

	// Clean up rule group after test
	defer func() {
		err := deleteRuleGroup(client, ruleGroup)
		require.NoError(s.T(), err)
	}()

	inputs := map[string]interface{}{
		"ssm_path_prefix": fmt.Sprintf("/waf/%s", uniquesuffix),
		"alb_tags": []map[string]interface{}{
			{
				"waf": tagValue,
			},
		},
		"regex_pattern_set_reference_statement_rules": []map[string]interface{}{
			{
				"name":     "block-regexp-patterns-" + uniquesuffix,
				"priority": 1,
				"action":   "block",
				"statement": map[string]interface{}{
					"arn": regexpSetArn,
					"field_to_match": map[string]interface{}{
						"uri_path": true,
					},
					"text_transformation": []map[string]interface{}{
						{
							"priority": 1,
							"type":     "NONE",
						},
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-regexp-patterns",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"regex_match_statement_rules": []map[string]interface{}{
			{
				"name":     "block-bad-pattern-" + uniquesuffix,
				"priority": 2,
				"action":   "block",
				"statement": map[string]interface{}{
					"regex_string": ".*user.*",
					"field_to_match": map[string]interface{}{
						"uri_path": true,
					},
					"text_transformation": []map[string]interface{}{
						{
							"priority": 1,
							"type":     "NONE",
						},
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-bad-patterns",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"rule_group_reference_statement_rules": []map[string]interface{}{
			{
				"name":     "block-rule-group-" + uniquesuffix,
				"priority": 3,
				"action":   "block",
				"statement": map[string]interface{}{
					"arn": ruleGroupArn,
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-rule-group",
					"sampled_requests_enabled":   false,
				},
			},
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	id := atmos.Output(s.T(), options, "id")
	assert.NotEmpty(s.T(), id)

	arn := atmos.Output(s.T(), options, "arn")
	assert.NotEmpty(s.T(), arn)

	webACL := getWebACLByIDAndName(s.T(), client, id, arn)
	require.NotNil(s.T(), webACL)
	require.NotEmpty(s.T(), webACL.Rules)

	assertBlockBadPatternsRule(s.T(), inputs["regex_pattern_set_reference_statement_rules"].([]map[string]interface{})[0], webACL.Rules[0], regexpSetArn)
	assertBlockBadPatternRule(s.T(), inputs["regex_match_statement_rules"].([]map[string]interface{})[0], webACL.Rules[1])
	assertBlockRuleGroupRule(s.T(), inputs["rule_group_reference_statement_rules"].([]map[string]interface{})[0], webACL.Rules[2], ruleGroupArn)

	// Assert ALB association with WAF ACL
	listResourcesOutput, err := client.ListResourcesForWebACL(context.Background(), &wafv2.ListResourcesForWebACLInput{
		ResourceType: types.ResourceTypeApplicationLoadBalancer,
		WebACLArn:    &arn,
	})
	require.NoError(s.T(), err)
	require.NotNil(s.T(), listResourcesOutput.ResourceArns)
	assert.Len(s.T(), listResourcesOutput.ResourceArns, 1)
	assert.Contains(s.T(), listResourcesOutput.ResourceArns, albArn)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestByComponent() {
	const component = "waf/by-component"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	client := awshelper.NewWAFClient(s.T(), awsRegion)

	uniquesuffix := strings.ToLower(random.UniqueId())

	albOptions := s.GetAtmosOptions("alb/by-component", "default-test", nil)
	albArn := atmos.Output(s.T(), albOptions, "alb_arn")

	inputs := map[string]interface{}{
		"ssm_path_prefix": fmt.Sprintf("/waf/%s", uniquesuffix),
		"size_constraint_statement_rules": []map[string]interface{}{
			{
				"name":     "block-large-body-" + uniquesuffix,
				"priority": 1,
				"action":   "block",
				"statement": map[string]interface{}{
					"size":                8192,
					"comparison_operator": "GT",
					"field_to_match": map[string]interface{}{
						"body": map[string]interface{}{},
					},
					"text_transformation": []map[string]interface{}{
						{
							"priority": 1,
							"type":     "NONE",
						},
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-large-body",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"sqli_match_statement_rules": []map[string]interface{}{
			{
				"name":     "block-sql-injection-" + uniquesuffix,
				"priority": 2,
				"action":   "block",
				"statement": map[string]interface{}{
					"field_to_match": map[string]interface{}{
						"body": map[string]interface{}{},
					},
					"text_transformation": []map[string]interface{}{
						{
							"priority": 1,
							"type":     "NONE",
						},
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-sql-injection",
					"sampled_requests_enabled":   false,
				},
			},
		},
		"xss_match_statement_rules": []map[string]interface{}{
			{
				"name":     "block-xss-" + uniquesuffix,
				"priority": 3,
				"action":   "block",
				"statement": map[string]interface{}{
					"field_to_match": map[string]interface{}{
						"body": map[string]interface{}{},
					},
					"text_transformation": []map[string]interface{}{
						{
							"priority": 1,
							"type":     "NONE",
						},
					},
				},
				"visibility_config": map[string]interface{}{
					"cloudwatch_metrics_enabled": false,
					"metric_name":                "block-xss",
					"sampled_requests_enabled":   false,
				},
			},
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	id := atmos.Output(s.T(), options, "id")
	assert.NotEmpty(s.T(), id)

	arn := atmos.Output(s.T(), options, "arn")
	assert.NotEmpty(s.T(), arn)

	webACL := getWebACLByIDAndName(s.T(), client, id, arn)
	require.NotNil(s.T(), webACL)
	require.NotEmpty(s.T(), webACL.Rules)

	assertBlockLargeBodyRule(s.T(), inputs["size_constraint_statement_rules"].([]map[string]interface{})[0], webACL.Rules[0])
	assertBlockSQLInjectionRule(s.T(), inputs["sqli_match_statement_rules"].([]map[string]interface{})[0], webACL.Rules[1])
	assertBlockXSSRule(s.T(), inputs["xss_match_statement_rules"].([]map[string]interface{})[0], webACL.Rules[2])
	// Assert ALB association with WAF ACL
	listResourcesOutput, err := client.ListResourcesForWebACL(context.Background(), &wafv2.ListResourcesForWebACLInput{
		ResourceType: types.ResourceTypeApplicationLoadBalancer,
		WebACLArn:    &arn,
	})
	require.NoError(s.T(), err)
	require.NotNil(s.T(), listResourcesOutput.ResourceArns)
	assert.Len(s.T(), listResourcesOutput.ResourceArns, 1)
	assert.Contains(s.T(), listResourcesOutput.ResourceArns, albArn)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestDisabled() {
	const component = "waf/disabled"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	s.VerifyEnabledFlag(component, stack, nil)
}

func getWebACLByIDAndName(t *testing.T, client *wafv2.Client, id string, arn string) *types.WebACL {
	arnParts := strings.Split(arn, "/")
	name := arnParts[len(arnParts)-2]
	wafACLOutput, err := client.GetWebACL(context.Background(), &wafv2.GetWebACLInput{
		Id:    &id,
		Name:  &name,
		Scope: types.ScopeRegional,
	})
	require.NoError(t, err)
	return wafACLOutput.WebACL
}

func assertOWASPRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "OWASP-10", *rule.Name)
	assert.EqualValues(t, 1, rule.Priority)
	assert.Equal(t, "AWS", *rule.Statement.ManagedRuleGroupStatement.VendorName)
	assert.Equal(t, "AWSManagedRulesCommonRuleSet", *rule.Statement.ManagedRuleGroupStatement.Name)
	require.Nil(t, rule.Action)
}

func assertBlockSpecificURIRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.Nil(t, rule.Action.Allow)
	assert.NotNil(t, rule.Action.Block)

	statement := rule.Statement.ByteMatchStatement
	require.NotNil(t, statement)
	assert.Equal(t, types.PositionalConstraintStartsWith, statement.PositionalConstraint)
	assert.Equal(t, "/admin", string(statement.SearchString))

	require.NotNil(t, statement.FieldToMatch.UriPath)
	require.Equal(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func assertAllowUSTrafficRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.NotStatement.Statement.GeoMatchStatement
	require.NotNil(t, statement)
	assert.EqualValues(t, "US", statement.CountryCodes[0])
}

func assertBlockNonUSTrafficRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.GeoMatchStatement
	require.NotNil(t, statement)
	assert.EqualValues(t, "CA", statement.CountryCodes[0])
	assert.EqualValues(t, "MX", statement.CountryCodes[1])
}

func assertBlockIPRangesRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule, client *wafv2.Client) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.IPSetReferenceStatement
	require.NotNil(t, statement)

	ipSet := awshelper.WafGetIPSetByARN(t, client, *statement.ARN)
	assert.Equal(t, "198.51.100.0/24", ipSet.IPSet.Addresses[0])
	assert.Equal(t, "192.0.2.0/24", ipSet.IPSet.Addresses[1])
}

func assertAllowTrustedIPsRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule, client *wafv2.Client) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Allow)
	assert.Nil(t, rule.Action.Block)

	statement := rule.Statement.IPSetReferenceStatement
	require.NotNil(t, statement)

	ipSet := awshelper.WafGetIPSetByARN(t, client, *statement.ARN)
	assert.Equal(t, "198.51.100.128/25", ipSet.IPSet.Addresses[1])
	assert.Equal(t, "203.0.113.0/24", ipSet.IPSet.Addresses[0])
}

func assertRateLimitRequestsRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.RateBasedStatement
	require.NotNil(t, statement)
	assert.EqualValues(t, 2000, *statement.Limit)
	assert.Equal(t, types.RateBasedStatementAggregateKeyTypeIp, statement.AggregateKeyType)
}

func assertBlockBadPatternsRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule, regexpSetArn string) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.RegexPatternSetReferenceStatement
	require.NotNil(t, statement)
	assert.Equal(t, regexpSetArn, *statement.ARN)
	assert.Equal(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func assertBlockBadPatternRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.RegexMatchStatement
	require.NotNil(t, statement)
	assert.Equal(t, ".*user.*", *statement.RegexString)
	assert.Equal(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func assertBlockRuleGroupRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule, ruleGroupArn string) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.Nil(t, rule.Action)
	assert.NotNil(t, rule.OverrideAction)

	statement := rule.Statement.RuleGroupReferenceStatement
	require.NotNil(t, statement)
	assert.Equal(t, ruleGroupArn, *statement.ARN)
}

func assertBlockLargeBodyRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)
	assert.Nil(t, rule.OverrideAction)

	statement := rule.Statement.SizeConstraintStatement
	require.NotNil(t, statement)
	assert.EqualValues(t, 8192, statement.Size)
	assert.Equal(t, types.ComparisonOperatorGt, statement.ComparisonOperator)
	assert.Equal(t, types.Body{OversizeHandling: "CONTINUE"}, *statement.FieldToMatch.Body)
	assert.EqualValues(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func assertBlockSQLInjectionRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)
	assert.Nil(t, rule.OverrideAction)

	statement := rule.Statement.SqliMatchStatement
	require.NotNil(t, statement)
	assert.Equal(t, types.Body{OversizeHandling: "CONTINUE"}, *statement.FieldToMatch.Body)
	assert.EqualValues(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func assertBlockXSSRule(t *testing.T, expectedRule map[string]interface{}, rule types.Rule) {
	assert.Equal(t, expectedRule["name"], *rule.Name)
	assert.EqualValues(t, expectedRule["priority"], rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)
	assert.Nil(t, rule.OverrideAction)

	statement := rule.Statement.XssMatchStatement
	require.NotNil(t, statement)
	assert.Equal(t, types.Body{OversizeHandling: "CONTINUE"}, *statement.FieldToMatch.Body)
	assert.EqualValues(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func deleteRegexPatternSet(client *wafv2.Client, patternSet *types.RegexPatternSetSummary) error {
	_, err := client.DeleteRegexPatternSet(context.Background(), &wafv2.DeleteRegexPatternSetInput{
		Id:        patternSet.Id,
		Name:      patternSet.Name,
		Scope:     types.ScopeRegional,
		LockToken: patternSet.LockToken,
	})
	return err
}

func createRuleGroup(client *wafv2.Client, name string, description string, capacity int64, metricName string) (*types.RuleGroupSummary, error) {
	ruleName := "rule-1"
	ruleRegexString := ".*test.*"
	ruleMetricName := "rule-1-metric"

	ruleGroupInput := &wafv2.CreateRuleGroupInput{
		Name:        &name,
		Scope:       types.ScopeRegional,
		Description: &description,
		Capacity:    &capacity,
		Rules: []types.Rule{
			{
				Name:     &ruleName,
				Priority: 1,
				Statement: &types.Statement{
					RegexMatchStatement: &types.RegexMatchStatement{
						RegexString: &ruleRegexString,
						FieldToMatch: &types.FieldToMatch{
							UriPath: &types.UriPath{},
						},
						TextTransformations: []types.TextTransformation{
							{
								Priority: 1,
								Type:     types.TextTransformationTypeNone,
							},
						},
					},
				},
				Action: &types.RuleAction{
					Block: &types.BlockAction{},
				},
				VisibilityConfig: &types.VisibilityConfig{
					CloudWatchMetricsEnabled: false,
					MetricName:               &ruleMetricName,
					SampledRequestsEnabled:   false,
				},
			},
		},
		VisibilityConfig: &types.VisibilityConfig{
			CloudWatchMetricsEnabled: false,
			MetricName:               &metricName,
			SampledRequestsEnabled:   false,
		},
	}

	ruleGroupOutput, err := client.CreateRuleGroup(context.Background(), ruleGroupInput)
	if err != nil {
		return nil, err
	}

	return ruleGroupOutput.Summary, nil
}

func deleteRuleGroup(client *wafv2.Client, ruleGroup *types.RuleGroupSummary) error {
	_, err := client.DeleteRuleGroup(context.Background(), &wafv2.DeleteRuleGroupInput{
		Id:        ruleGroup.Id,
		Name:      ruleGroup.Name,
		Scope:     types.ScopeRegional,
		LockToken: ruleGroup.LockToken,
	})
	return err
}
