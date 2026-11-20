"""Static checks: the Shield configuration role may change bucket policies only on the DRT log buckets, and main-ssm passes it that list."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import child_block, file_block, statements, template_parameters, values  # noqa: E402

TEMPLATES = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/shield_advanced/shield_advanced/templates"
ROLE = TEMPLATES / "sra-shield-advanced-configuration-role.yaml"
MAIN = TEMPLATES / "sra-shield-advanced-main-ssm.yaml"
CONFIGURATION = TEMPLATES / "sra-shield-advanced-configuration.yaml"
BUCKET_POLICY_ACTIONS = {"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"}
# One arn:*:s3:::<bucket> per name in pShieldDRTLogBuckets (a Join delimiter can't contain ${AWS::Partition}).
BUCKET_ARNS = [
    "Resource: !Split",
    "- ','",
    "- !Sub",
    "- 'arn:*:s3:::${Buckets}'",
    "- Buckets: !Join [',arn:*:s3:::', !Ref pShieldDRTLogBuckets]",
]


def role_statements() -> list:
    role = file_block(ROLE, "  rConfigurationRole:")
    return statements(child_block(role, role.index("      Policies:")))


def resource_lines(statement: list) -> list:
    index = next(i for i, line in enumerate(statement) if line.strip().startswith("Resource:"))
    return [statement[index].strip()] + [line.strip() for line in child_block(statement, index) if line.strip() and not line.strip().startswith("#")]


def test_bucket_policy_actions_are_limited_to_the_drt_log_buckets() -> None:
    found: set = set()
    for statement in role_statements():
        actions = BUCKET_POLICY_ACTIONS & set(values(statement, "Action"))
        if actions:
            found |= actions
            assert resource_lines(statement) == BUCKET_ARNS, f"{statement[0].strip()} allows {sorted(actions)} on {resource_lines(statement)}"
    assert found == BUCKET_POLICY_ACTIONS


def test_no_s3_action_except_listing_buckets_uses_a_wildcard_resource() -> None:
    for statement in role_statements():
        s3_actions = {action for action in values(statement, "Action") if action.startswith("s3:")}
        if "*" in values(statement, "Resource"):
            assert s3_actions <= {"s3:ListAllMyBuckets"}, f"{statement[0].strip()} allows {sorted(s3_actions)} on '*'"


def test_the_role_does_not_suppress_checkov_ckv_aws_109() -> None:
    assert "CKV_AWS_109" not in "\n".join(file_block(ROLE, "  rConfigurationRole:"))


def test_the_bucket_list_parameter_matches_main_ssm_and_the_configuration_template() -> None:
    definition = template_parameters(ROLE)["pShieldDRTLogBuckets"]
    assert definition == template_parameters(MAIN)["pShieldDRTLogBuckets"]
    assert definition == template_parameters(CONFIGURATION)["pShieldDRTLogBuckets"]


def test_main_ssm_passes_every_required_role_parameter_to_the_stackset_and_the_stack() -> None:
    required = {name for name, body in template_parameters(ROLE).items() if not any(line.strip().startswith("Default:") for line in body)}
    assert {"pManagementAccountId", "pShieldDRTLogBuckets"} <= required

    stackset = file_block(MAIN, "  rShieldConfigurationIAMRoleStackSet:")
    stackset_parameters = child_block(stackset, stackset.index("      Parameters:"))
    passed_to_stackset = {line.split("ParameterKey:")[1].strip() for line in stackset_parameters if "ParameterKey:" in line}

    stack = file_block(MAIN, "  rShieldConfigurationIAMRoleStack:")
    stack_parameters = child_block(stack, stack.index("      Parameters:"))
    passed_to_stack = {line.strip().split(":")[0] for line in stack_parameters if line.startswith("        p")}

    assert passed_to_stackset == required, f"StackSet passes {sorted(passed_to_stackset)}, role requires {sorted(required)}"
    assert passed_to_stack == required, f"nested stack passes {sorted(passed_to_stack)}, role requires {sorted(required)}"
    joined = "!Join\n- ','\n- !Ref pShieldDRTLogBuckets"
    assert joined in "\n".join(line.strip() for line in stackset_parameters)
    assert joined in "\n".join(line.strip() for line in stack_parameters)
