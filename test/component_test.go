package test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponent(t *testing.T) {
	awsRegion := "us-east-2"

	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		suite.AddDependency("vpc", "default-test")

		// Setup phase: Create DNS zones for testing
		suite.Setup(t, func(t *testing.T, atm *helper.Atmos) {
			basicDomain := "components.cptest.test-automation.app"

			// Deploy the delegated DNS zone
			inputs := map[string]interface{}{
				"zone_config": []map[string]interface{}{
					{
						"subdomain": suite.GetRandomIdentifier(),
						"zone_name": basicDomain,
					},
				},
			}
			atm.GetAndDeploy("dns-delegated", "default-test", inputs)
			atm.GetAndDeploy("acm", "default-test", map[string]interface{}{})
			atm.GetAndDeploy("alb/a", "default-test", map[string]interface{}{})
			atm.GetAndDeploy("alb/b", "default-test", map[string]interface{}{})
			atm.GetAndDeploy("alb/c", "default-test", map[string]interface{}{})
			atm.GetAndDeploy("alb/d", "default-test", map[string]interface{}{})
		})

		// Teardown phase: Destroy the DNS zones created during setup
		suite.TearDown(t, func(t *testing.T, atm *helper.Atmos) {
			atm.GetAndDestroy("alb/d", "default-test", map[string]interface{}{})
			atm.GetAndDestroy("alb/c", "default-test", map[string]interface{}{})
			atm.GetAndDestroy("alb/b", "default-test", map[string]interface{}{})
			atm.GetAndDestroy("alb/a", "default-test", map[string]interface{}{})
			atm.GetAndDestroy("acm", "default-test", map[string]interface{}{})

			// Deploy the delegated DNS zone
			inputs := map[string]interface{}{
				"zone_config": []map[string]interface{}{
					{
						"subdomain": suite.GetRandomIdentifier(),
						"zone_name": "components.cptest.test-automation.app",
					},
				},
			}
			atm.GetAndDestroy("dns-delegated", "default-test", inputs)
		})

		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			client := NeWAFClient(t, awsRegion)

			// Create WAFv2 regexp set
			patternSet, err := createRegexPatternSet(client, "test-regex-set", "Test regex pattern set", []string{".*admin.*", ".*password.*"})
			require.NoError(t, err)
			require.NotNil(t, patternSet)
			regexpSetArn := *patternSet.ARN

			// Clean up regex set after test
			defer func() {
				err := deleteRegexPatternSet(client, patternSet)
				require.NoError(t, err)
			}()

			// Create WAFv2 rule group
			ruleGroup, err := createRuleGroup(client, "test-rule-group", "Test rule group", 1000, "test-rule-group-metric")
			require.NoError(t, err)
			require.NotNil(t, ruleGroup)
			assert.Equal(t, "test-rule-group", *ruleGroup.Name)
			ruleGroupArn := *ruleGroup.ARN

			// Clean up rule group after test
			defer func() {
				err := deleteRuleGroup(client, ruleGroup)
				require.NoError(t, err)
			}()

			albCComponent := helper.NewAtmosComponent("alb/c", "default-test", map[string]interface{}{})
			albCArn := atm.Output(albCComponent, "alb_arn")

			inputs := map[string]interface{}{
				"name": "vpc-terraform",
				"association_resource_arns": []string{
					albCArn,
				},
				"regex_pattern_set_reference_statement_rules": []map[string]interface{}{
					{
						"name":     "block-bad-patterns",
						"priority": 8,
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
							"metric_name":                "block-bad-patterns",
							"sampled_requests_enabled":   false,
						},
					},
				},
				"rule_group_reference_statement_rules": []map[string]interface{}{
					{
						"name":            "block-rule-group",
						"priority":        10,
						"override_action": "none",
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

			defer atm.GetAndDestroy("waf/basic", "default-test", inputs)
			component := atm.GetAndDeploy("waf/basic", "default-test", inputs)
			assert.NotNil(t, component)

			id := atm.Output(component, "id")
			assert.NotEmpty(t, id)

			arn := atm.Output(component, "arn")
			assert.NotEmpty(t, arn)

			name := "eg-default-ue2-test-vpc-terraform-bd14af-3ebefc"
			wafACLOutput, err := client.GetWebACL(context.Background(), &wafv2.GetWebACLInput{
				Id:    &id,
				Name:  &name,
				Scope: types.ScopeRegional,
			})
			require.NoError(t, err)
			webACL := wafACLOutput.WebACL
			require.NotNil(t, webACL)
			require.NotEmpty(t, webACL.Rules)

			assertOWASPRule(t, webACL.Rules[0])
			assertBlockSpecificURIRule(t, webACL.Rules[1])
			assertAllowUSTrafficRule(t, webACL.Rules[2])
			assertBlockNonUSTrafficRule(t, webACL.Rules[3])
			assertBlockIPRangesRule(t, webACL.Rules[4], client)
			assertAllowTrustedIPsRule(t, webACL.Rules[5], client)
			assertRateLimitRequestsRule(t, webACL.Rules[6])
			assertBlockBadPatternsRule(t, webACL.Rules[7], regexpSetArn)
			assertBlockBadPatternRule(t, webACL.Rules[8])
			assertBlockRuleGroupRule(t, webACL.Rules[9], ruleGroupArn)
			assertBlockLargeBodyRule(t, webACL.Rules[10])
			assertBlockSQLInjectionRule(t, webACL.Rules[11])
			assertBlockXSSRule(t, webACL.Rules[12])

			// Assert custom response body
			require.NotNil(t, webACL.CustomResponseBodies)
			defaultResponse, exists := webACL.CustomResponseBodies["default_response"]
			require.True(t, exists)
			assert.Equal(t, "Access denied by WAF rules", *defaultResponse.Content)
			assert.Equal(t, types.ResponseContentTypeTextPlain, defaultResponse.ContentType)

			// Assert default block response
			require.NotNil(t, webACL.DefaultAction.Block)
			require.NotNil(t, webACL.DefaultAction.Block.CustomResponse)
			// TODO: Uncomment when issue https://github.com/cloudposse-terraform-components/aws-waf/issues/15 is fixed
			// assert.Equal(t, "default_response", *webACL.DefaultAction.Block.CustomResponse.CustomResponseBodyKey)
			assert.EqualValues(t, 403, *webACL.DefaultAction.Block.CustomResponse.ResponseCode)

			albAComponent := helper.NewAtmosComponent("alb/a", "default-test", map[string]interface{}{})
			albAArn := atm.Output(albAComponent, "alb_arn")

			albBComponent := helper.NewAtmosComponent("alb/b", "default-test", map[string]interface{}{})
			albBArn := atm.Output(albBComponent, "alb_arn")

			albDComponent := helper.NewAtmosComponent("alb/d", "default-test", map[string]interface{}{})
			albDArn := atm.Output(albDComponent, "alb_arn")

			// Assert ALB association with WAF ACL
			listResourcesOutput, err := client.ListResourcesForWebACL(context.Background(), &wafv2.ListResourcesForWebACLInput{
				ResourceType: types.ResourceTypeApplicationLoadBalancer,
				WebACLArn:    &arn,
			})
			require.NoError(t, err)
			require.NotNil(t, listResourcesOutput.ResourceArns)
			assert.Len(t, listResourcesOutput.ResourceArns, 4)
			assert.Contains(t, listResourcesOutput.ResourceArns, albAArn)
			assert.Contains(t, listResourcesOutput.ResourceArns, albBArn)
			assert.Contains(t, listResourcesOutput.ResourceArns, albCArn)
			assert.Contains(t, listResourcesOutput.ResourceArns, albDArn)

		})
	})
}

func assertOWASPRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "OWASP-10", *rule.Name)
	assert.EqualValues(t, 1, rule.Priority)
	assert.Equal(t, "AWS", *rule.Statement.ManagedRuleGroupStatement.VendorName)
	assert.Equal(t, "AWSManagedRulesCommonRuleSet", *rule.Statement.ManagedRuleGroupStatement.Name)
	require.Nil(t, rule.Action)
}

func assertBlockSpecificURIRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "block-specific-uri", *rule.Name)
	assert.EqualValues(t, 2, rule.Priority)
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

func assertAllowUSTrafficRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "allow-us-traffic", *rule.Name)
	assert.EqualValues(t, 3, rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.NotStatement.Statement.GeoMatchStatement
	require.NotNil(t, statement)
	assert.EqualValues(t, "US", statement.CountryCodes[0])
}

func assertBlockNonUSTrafficRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "block-non-us-traffic", *rule.Name)
	assert.EqualValues(t, 4, rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.GeoMatchStatement
	require.NotNil(t, statement)
	assert.EqualValues(t, "CA", statement.CountryCodes[0])
	assert.EqualValues(t, "MX", statement.CountryCodes[1])
}

func assertBlockIPRangesRule(t *testing.T, rule types.Rule, client *wafv2.Client) {
	assert.Equal(t, "block-ip-ranges", *rule.Name)
	assert.EqualValues(t, 5, rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.IPSetReferenceStatement
	require.NotNil(t, statement)

	ipSet := getIPSetByARN(t, client, *statement.ARN)
	assert.Equal(t, "198.51.100.0/24", ipSet.IPSet.Addresses[0])
	assert.Equal(t, "192.0.2.0/24", ipSet.IPSet.Addresses[1])
}

func assertAllowTrustedIPsRule(t *testing.T, rule types.Rule, client *wafv2.Client) {
	assert.Equal(t, "allow-trusted-ips", *rule.Name)
	assert.EqualValues(t, 6, rule.Priority)
	assert.NotNil(t, rule.Action.Allow)
	assert.Nil(t, rule.Action.Block)

	statement := rule.Statement.IPSetReferenceStatement
	require.NotNil(t, statement)

	ipSet := getIPSetByARN(t, client, *statement.ARN)
	assert.Equal(t, "198.51.100.128/25", ipSet.IPSet.Addresses[1])
	assert.Equal(t, "203.0.113.0/24", ipSet.IPSet.Addresses[0])
}

func assertRateLimitRequestsRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "rate-limit-requests", *rule.Name)
	assert.EqualValues(t, 7, rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.RateBasedStatement
	require.NotNil(t, statement)
	assert.EqualValues(t, 2000, *statement.Limit)
	assert.Equal(t, types.RateBasedStatementAggregateKeyTypeIp, statement.AggregateKeyType)
}

func assertBlockBadPatternsRule(t *testing.T, rule types.Rule, regexpSetArn string) {
	assert.Equal(t, "block-bad-patterns", *rule.Name)
	assert.EqualValues(t, 8, rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.RegexPatternSetReferenceStatement
	require.NotNil(t, statement)
	assert.Equal(t, regexpSetArn, *statement.ARN)
	assert.Equal(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func assertBlockBadPatternRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "block-bad-pattern", *rule.Name)
	assert.EqualValues(t, 9, rule.Priority)
	assert.NotNil(t, rule.Action.Block)
	assert.Nil(t, rule.Action.Allow)

	statement := rule.Statement.RegexMatchStatement
	require.NotNil(t, statement)
	assert.Equal(t, ".*user.*", *statement.RegexString)
	assert.Equal(t, 1, len(statement.TextTransformations))
	assert.Equal(t, types.TextTransformationTypeNone, statement.TextTransformations[0].Type)
	assert.EqualValues(t, 1, statement.TextTransformations[0].Priority)
}

func assertBlockRuleGroupRule(t *testing.T, rule types.Rule, ruleGroupArn string) {
	assert.Equal(t, "block-rule-group", *rule.Name)
	assert.EqualValues(t, 10, rule.Priority)
	assert.Nil(t, rule.Action)
	assert.NotNil(t, rule.OverrideAction)

	statement := rule.Statement.RuleGroupReferenceStatement
	require.NotNil(t, statement)
	assert.Equal(t, ruleGroupArn, *statement.ARN)
}

func assertBlockLargeBodyRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "block-large-body", *rule.Name)
	assert.EqualValues(t, 11, rule.Priority)
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

func assertBlockSQLInjectionRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "block-sql-injection", *rule.Name)
	assert.EqualValues(t, 12, rule.Priority)
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

func assertBlockXSSRule(t *testing.T, rule types.Rule) {
	assert.Equal(t, "block-xss", *rule.Name)
	assert.EqualValues(t, 13, rule.Priority)
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

func createRegexPatternSet(client *wafv2.Client, name string, description string, patterns []string) (*types.RegexPatternSetSummary, error) {
	regexSetInput := &wafv2.CreateRegexPatternSetInput{
		Name:        &name,
		Scope:       types.ScopeRegional,
		Description: &description,
		RegularExpressionList: []types.Regex{
			{RegexString: &patterns[0]},
			{RegexString: &patterns[1]},
		},
	}

	output, err := client.CreateRegexPatternSet(context.Background(), regexSetInput)
	if err != nil {
		return nil, err
	}

	return output.Summary, nil
}

func getIPSetByARN(t *testing.T, client *wafv2.Client, arn string) *wafv2.GetIPSetOutput {
	ipSets, err := client.ListIPSets(context.Background(), &wafv2.ListIPSetsInput{
		Scope: types.ScopeRegional,
	})

	var ipSetId string
	var ipSetName string
	for _, ipSet := range ipSets.IPSets {
		if *ipSet.ARN == arn {
			ipSetId = *ipSet.Id
			ipSetName = *ipSet.Name
			break
		}
	}

	ipSet, err := client.GetIPSet(context.Background(), &wafv2.GetIPSetInput{
		Id:    &ipSetId,
		Name:  &ipSetName,
		Scope: types.ScopeRegional,
	})
	require.NoError(t, err)
	require.NotNil(t, ipSet)
	require.NotNil(t, ipSet.IPSet)
	return ipSet
}

func NeWAFClient(t *testing.T, region string) *wafv2.Client {
	client, err := NeWAFClientE(t, region)
	require.NoError(t, err)

	return client
}

func NeWAFClientE(t *testing.T, region string) (*wafv2.Client, error) {
	sess, err := aws.NewAuthenticatedSession(region)
	if err != nil {
		return nil, err
	}
	return wafv2.NewFromConfig(*sess), nil
}
