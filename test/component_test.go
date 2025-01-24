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
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			client := NeWAFClient(t, awsRegion)

			// Create WAFv2 regexp set
			regexSetName := "test-regex-set"
			regexSetDescription := "Test regex pattern set"
			regexPatterns := []string{
				".*admin.*",
				".*password.*",
			}

			regexSetInput := &wafv2.CreateRegexPatternSetInput{
				Name:        &regexSetName,
				Scope:       types.ScopeRegional,
				Description: &regexSetDescription,
				RegularExpressionList: []types.Regex{
					{RegexString: &regexPatterns[0]},
					{RegexString: &regexPatterns[1]},
				},
			}

			regexSetOutput, err := client.CreateRegexPatternSet(context.Background(), regexSetInput)
			regexpSetArn := *regexSetOutput.Summary.ARN
			require.NoError(t, err)
			require.NotNil(t, regexSetOutput.Summary)
			assert.Equal(t, regexSetName, *regexSetOutput.Summary.Name)

			// Clean up regex set after test
			defer func() {
				_, err := client.DeleteRegexPatternSet(context.Background(), &wafv2.DeleteRegexPatternSetInput{
					Id:        regexSetOutput.Summary.Id,
					Name:      regexSetOutput.Summary.Name,
					Scope:     types.ScopeRegional,
					LockToken: regexSetOutput.Summary.LockToken,
				})
				require.NoError(t, err)
			}()

			// Create WAFv2 rule group
			ruleGroupName := "test-rule-group"
			ruleGroupDescription := "Test rule group"
			ruleGroupCapacity := int64(1000)
			ruleGroupMetricName := "test-rule-group-metric"

			ruleName := "rule-1"
			ruleRegexString := ".*test.*"
			ruleMetricName := "rule-1-metric"

			ruleGroupInput := &wafv2.CreateRuleGroupInput{
				Name:        &ruleGroupName,
				Scope:       types.ScopeRegional,
				Description: &ruleGroupDescription,
				Capacity:    &ruleGroupCapacity,
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
					MetricName:               &ruleGroupMetricName,
					SampledRequestsEnabled:   false,
				},
			}

			ruleGroupOutput, err := client.CreateRuleGroup(context.Background(), ruleGroupInput)
			ruleGroupArn := *ruleGroupOutput.Summary.ARN
			require.NoError(t, err)
			require.NotNil(t, ruleGroupOutput.Summary)
			assert.Equal(t, ruleGroupName, *ruleGroupOutput.Summary.Name)

			// Clean up rule group after test
			defer func() {
				_, err := client.DeleteRuleGroup(context.Background(), &wafv2.DeleteRuleGroupInput{
					Id:        ruleGroupOutput.Summary.Id,
					Name:      ruleGroupOutput.Summary.Name,
					Scope:     types.ScopeRegional,
					LockToken: ruleGroupOutput.Summary.LockToken,
				})
				require.NoError(t, err)
			}()

			inputs := map[string]interface{}{
				"name": "vpc-terraform",
				"regex_pattern_set_reference_statement_rules": []map[string]interface{}{
					{
						"name":     "block-bad-patterns",
						"priority": 8,
						"action":   "block",
						"statement": map[string]interface{}{
							"arn": *regexSetOutput.Summary.ARN,
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

			// limit := int32(10)
			// wafACLs, err := client.ListWebACLs(context.Background(), &wafv2.ListWebACLsInput{
			// 	Limit: &limit,
			// 	Scope: types.ScopeRegional,
			// })
			name := "eg-default-ue2-test-vpc-terraform-bd14af-3ebefc"
			wafACL, err := client.GetWebACL(context.Background(), &wafv2.GetWebACLInput{
				Id:    &id,
				Name:  &name,
				Scope: types.ScopeRegional,
			})
			require.NoError(t, err)
			// assert.Equal(t, 1, len(wafACLs.WebACLs))
			require.NotNil(t, wafACL.WebACL)
			require.NotEmpty(t, wafACL.WebACL.Rules)

			rule := wafACL.WebACL.Rules[0]
			assert.Equal(t, "OWASP-10", *rule.Name)
			assert.EqualValues(t, 1, rule.Priority)
			assert.Equal(t, "AWS", *rule.Statement.ManagedRuleGroupStatement.VendorName)
			assert.Equal(t, "AWSManagedRulesCommonRuleSet", *rule.Statement.ManagedRuleGroupStatement.Name)

			require.Nil(t, rule.Action)

			rule = wafACL.WebACL.Rules[1]
			assert.Equal(t, "block-specific-uri", *rule.Name)
			assert.EqualValues(t, 2, rule.Priority)
			assert.Nil(t, rule.Action.Allow)
			assert.NotNil(t, rule.Action.Block)

			byteMatchStatement := rule.Statement.ByteMatchStatement
			require.NotNil(t, byteMatchStatement)
			assert.Equal(t, types.PositionalConstraintStartsWith, byteMatchStatement.PositionalConstraint)
			assert.Equal(t, "/admin", string(byteMatchStatement.SearchString))

			require.NotNil(t, byteMatchStatement.FieldToMatch.UriPath)
			require.Equal(t, 1, len(byteMatchStatement.TextTransformations))
			assert.Equal(t, types.TextTransformationTypeNone, byteMatchStatement.TextTransformations[0].Type)
			assert.EqualValues(t, 1, byteMatchStatement.TextTransformations[0].Priority)

			rule = wafACL.WebACL.Rules[2]
			assert.Equal(t, "allow-us-traffic", *rule.Name)
			assert.EqualValues(t, 3, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)

			geoMatchStatement := rule.Statement.NotStatement.Statement.GeoMatchStatement
			require.NotNil(t, geoMatchStatement)
			assert.EqualValues(t, "US", geoMatchStatement.CountryCodes[0])

			rule = wafACL.WebACL.Rules[3]
			assert.Equal(t, "block-non-us-traffic", *rule.Name)
			assert.EqualValues(t, 4, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)

			geoMatchStatement = rule.Statement.GeoMatchStatement
			require.NotNil(t, geoMatchStatement)
			assert.EqualValues(t, "CA", geoMatchStatement.CountryCodes[0])
			assert.EqualValues(t, "MX", geoMatchStatement.CountryCodes[1])

			rule = wafACL.WebACL.Rules[4]
			assert.Equal(t, "block-ip-ranges", *rule.Name)
			assert.EqualValues(t, 5, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)

			ipSetReferenceStatement := rule.Statement.IPSetReferenceStatement
			require.NotNil(t, ipSetReferenceStatement)

			ipSets, err := client.ListIPSets(context.Background(), &wafv2.ListIPSetsInput{
				Scope: types.ScopeRegional,
			})

			var ipSetId string
			var ipSetName string
			for _, ipSet := range ipSets.IPSets {
				if *ipSet.ARN == *ipSetReferenceStatement.ARN {
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
			assert.Equal(t, "198.51.100.0/24", ipSet.IPSet.Addresses[0])
			assert.Equal(t, "192.0.2.0/24", ipSet.IPSet.Addresses[1])

			rule = wafACL.WebACL.Rules[5]
			assert.Equal(t, "allow-trusted-ips", *rule.Name)
			assert.EqualValues(t, 6, rule.Priority)
			assert.NotNil(t, rule.Action.Allow)
			assert.Nil(t, rule.Action.Block)

			ipSetReferenceStatement = rule.Statement.IPSetReferenceStatement
			require.NotNil(t, ipSetReferenceStatement)

			ipSets, err = client.ListIPSets(context.Background(), &wafv2.ListIPSetsInput{
				Scope: types.ScopeRegional,
			})

			for _, ipSet := range ipSets.IPSets {
				if *ipSet.ARN == *ipSetReferenceStatement.ARN {
					ipSetId = *ipSet.Id
					ipSetName = *ipSet.Name
					break
				}
			}

			ipSet, err = client.GetIPSet(context.Background(), &wafv2.GetIPSetInput{
				Id:    &ipSetId,
				Name:  &ipSetName,
				Scope: types.ScopeRegional,
			})
			require.NoError(t, err)
			require.NotNil(t, ipSet)
			require.NotNil(t, ipSet.IPSet)
			assert.Equal(t, "198.51.100.128/25", ipSet.IPSet.Addresses[1])
			assert.Equal(t, "203.0.113.0/24", ipSet.IPSet.Addresses[0])

			rule = wafACL.WebACL.Rules[6]
			assert.Equal(t, "rate-limit-requests", *rule.Name)
			assert.EqualValues(t, 7, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)

			rateBasedStatement := rule.Statement.RateBasedStatement
			require.NotNil(t, rateBasedStatement)
			assert.EqualValues(t, 2000, *rateBasedStatement.Limit)
			assert.Equal(t, types.RateBasedStatementAggregateKeyTypeIp, rateBasedStatement.AggregateKeyType)

			rule = wafACL.WebACL.Rules[7]
			assert.Equal(t, "block-bad-patterns", *rule.Name)
			assert.EqualValues(t, 8, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)

			RegexPatternSet := rule.Statement.RegexPatternSetReferenceStatement
			require.NotNil(t, RegexPatternSet)
			assert.Equal(t, regexpSetArn, *RegexPatternSet.ARN)
			assert.Equal(t, 1, len(RegexPatternSet.TextTransformations))
			assert.Equal(t, types.TextTransformationTypeNone, RegexPatternSet.TextTransformations[0].Type)
			assert.EqualValues(t, 1, RegexPatternSet.TextTransformations[0].Priority)

			rule = wafACL.WebACL.Rules[8]
			assert.Equal(t, "block-bad-pattern", *rule.Name)
			assert.EqualValues(t, 9, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)

			regexpMatchStatement := rule.Statement.RegexMatchStatement
			require.NotNil(t, regexpMatchStatement)
			assert.Equal(t, ".*user.*", *regexpMatchStatement.RegexString)
			assert.Equal(t, 1, len(regexpMatchStatement.TextTransformations))
			assert.Equal(t, types.TextTransformationTypeNone, regexpMatchStatement.TextTransformations[0].Type)
			assert.EqualValues(t, 1, regexpMatchStatement.TextTransformations[0].Priority)

			rule = wafACL.WebACL.Rules[9]
			assert.Equal(t, "block-rule-group", *rule.Name)
			assert.EqualValues(t, 10, rule.Priority)
			assert.Nil(t, rule.Action)
			assert.NotNil(t, rule.OverrideAction)

			ruleGroupReferenceStatement := rule.Statement.RuleGroupReferenceStatement
			require.NotNil(t, ruleGroupReferenceStatement)
			assert.Equal(t, ruleGroupArn, *ruleGroupReferenceStatement.ARN)

			rule = wafACL.WebACL.Rules[10]
			assert.Equal(t, "block-large-body", *rule.Name)
			assert.EqualValues(t, 11, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)
			assert.Nil(t, rule.OverrideAction)

			sizeConstraintStatement := rule.Statement.SizeConstraintStatement
			require.NotNil(t, sizeConstraintStatement)
			assert.EqualValues(t, 8192, sizeConstraintStatement.Size)
			assert.Equal(t, types.ComparisonOperatorGt, sizeConstraintStatement.ComparisonOperator)
			assert.Equal(t, types.Body{OversizeHandling: "CONTINUE"}, *sizeConstraintStatement.FieldToMatch.Body)
			assert.EqualValues(t, 1, len(sizeConstraintStatement.TextTransformations))
			assert.Equal(t, types.TextTransformationTypeNone, sizeConstraintStatement.TextTransformations[0].Type)
			assert.EqualValues(t, 1, sizeConstraintStatement.TextTransformations[0].Priority)

			rule = wafACL.WebACL.Rules[11]
			assert.Equal(t, "block-sql-injection", *rule.Name)
			assert.EqualValues(t, 12, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)
			assert.Nil(t, rule.OverrideAction)

			sqliMatchStatement := rule.Statement.SqliMatchStatement
			require.NotNil(t, sqliMatchStatement)
			assert.Equal(t, types.Body{OversizeHandling: "CONTINUE"}, *sqliMatchStatement.FieldToMatch.Body)
			assert.EqualValues(t, 1, len(sqliMatchStatement.TextTransformations))
			assert.Equal(t, types.TextTransformationTypeNone, sqliMatchStatement.TextTransformations[0].Type)
			assert.EqualValues(t, 1, sqliMatchStatement.TextTransformations[0].Priority)

			rule = wafACL.WebACL.Rules[12]
			assert.Equal(t, "block-xss", *rule.Name)
			assert.EqualValues(t, 13, rule.Priority)
			assert.NotNil(t, rule.Action.Block)
			assert.Nil(t, rule.Action.Allow)
			assert.Nil(t, rule.OverrideAction)

			xssMatchStatement := rule.Statement.XssMatchStatement
			require.NotNil(t, xssMatchStatement)
			assert.Equal(t, types.Body{OversizeHandling: "CONTINUE"}, *xssMatchStatement.FieldToMatch.Body)
			assert.EqualValues(t, 1, len(xssMatchStatement.TextTransformations))
			assert.Equal(t, types.TextTransformationTypeNone, xssMatchStatement.TextTransformations[0].Type)
			assert.EqualValues(t, 1, xssMatchStatement.TextTransformations[0].Priority)

			// logginConfigId := atm.Output(component, "logging_config_id")
			// assert.NotEmpty(t, logginConfigId)
		})
	})
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
