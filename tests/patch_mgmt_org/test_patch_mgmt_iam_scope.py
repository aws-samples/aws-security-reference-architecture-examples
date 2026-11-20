"""Static checks: patch_mgmt_org IAM roles are scoped to what the solution uses (no AWS calls are made)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/patch_mgmt/patch_mgmt_org/templates"
ROLE_TEMPLATE = TEMPLATES / "sra-patch_mgmt-configuration-role.yaml"
LAMBDA_TEMPLATE = TEMPLATES / "sra-patch_mgmt-configuration.yaml"
MAIN_TEMPLATE = TEMPLATES / "sra-patch_mgmt-org-main-ssm.yaml"


def _resource_block(template: Path, logical_id: str) -> str:
    """Return the text of one top-level resource (from '  <id>:' to the next top-level resource)."""
    text = template.read_text()
    start = text.index(f"\n  {logical_id}:\n")
    nxt = re.compile(r"\n  r[A-Za-z0-9]+:\n").search(text, start + 1)
    return text[start : nxt.start() if nxt else len(text)]


def _without_comments(text: str) -> str:
    """Drop YAML comment lines so a comment can neither satisfy nor break an assertion."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _statement(block: str, sid: str) -> str:
    start = block.index(f"- Sid: {sid}\n")
    nxt = re.compile(r"\n\s+- (Sid|PolicyName): ").search(block, start + 1)
    return _without_comments(block[start : nxt.start() if nxt else len(block)])


ROLES = [(ROLE_TEMPLATE, "rConfigurationRole"), (LAMBDA_TEMPLATE, "rPatchMgmtLambdaRole"), (ROLE_TEMPLATE, "rSSMAutomationRole")]
WINDOW_ROLES = [(ROLE_TEMPLATE, "rConfigurationRole")]  # the only role with maintenance window permissions; the Lambda assumes it in every account

# A wildcard action in any YAML form: "Action: ssm:*", "- ssm:*", "- '*'", "Action: '*'".
WILDCARD_ACTION = re.compile(r"""^\s*(?:-|Action:)\s*["']?(?:\*|ssm:\*)["']?\s*$""", re.M)
WINDOW_WRITE = re.compile(r"ssm:(?:Delete|Update|Register|Deregister)\w*MaintenanceWindow\w*|ssm:AddTagsToResource")
RESOURCE_EVERYTHING = re.compile(r"""Resource:\s*(?:\n\s*-\s*)?["']?\*["']?\s*$""", re.M)


def _statements(block: str) -> list[str]:
    """Split a role block into its policy statements (each starts with '- Sid:' or '- Effect:')."""
    return re.split(r"(?=\n\s+- (?:Sid|Effect): )", _without_comments(block))


@pytest.mark.parametrize(("template", "logical_id"), ROLES)
def test_no_wildcard_ssm_and_valid_action_names(template: Path, logical_id: str) -> None:
    block = _resource_block(template, logical_id)
    assert not WILDCARD_ACTION.search(_without_comments(block)), "no '*' or 'ssm:*' action in any form"
    assert not re.search(r"^\s*- [a-z0-9-]+:[A-Za-z]+,\s*$", block, re.M), "action names must not end with a comma"


@pytest.mark.parametrize(("template", "logical_id"), WINDOW_ROLES)
def test_window_changes_require_the_solution_tag(template: Path, logical_id: str) -> None:
    block = _resource_block(template, logical_id)
    create = _statement(block, "CreateTaggedMaintenanceWindows")
    assert "Action: ssm:CreateMaintenanceWindow" in create and "aws:RequestTag/createdBy: SRA_Patch_Management" in create
    manage = _statement(block, "ManageSolutionMaintenanceWindows")
    for action in ("DeleteMaintenanceWindow", "UpdateMaintenanceWindow", "RegisterTaskWithMaintenanceWindow"):
        assert f"- ssm:{action}" in manage
    assert "aws:ResourceTag/createdBy: SRA_Patch_Management" in manage
    assert ":maintenancewindow/*" in manage and 'Resource: "*"' not in manage
    setting = _statement(block, "DefaultHostManagementSetting")
    assert "servicesetting/ssm/managed-instance/default-ec2-instance-management-role" in setting
    for sid in ("ManageSolutionWindowTargetsAndTasks", "PatchDocuments", "ListMaintenanceWindowTags"):
        assert 'Resource: "*"' not in _statement(block, sid)


def test_automation_role_runs_only_the_patch_documents_in_this_account() -> None:
    block = _resource_block(ROLE_TEMPLATE, "rSSMAutomationRole")
    trust = block[block.index("AssumeRolePolicyDocument:") : block.index("Policies:")]
    assert "aws:SourceAccount: !Ref AWS::AccountId" in trust
    assert "aws:SourceArn: !Sub arn:${AWS::Partition}:ssm:*:${AWS::AccountId}:*" in trust
    send = _statement(block, "SendPatchCommandsToThisAccount")
    assert "Action: ssm:SendCommand" in send
    assert sorted(re.findall(r":document/([A-Za-z-]+)", send)) == ["AWS-RunPatchBaseline", "AWS-UpdateSSMAgent"]
    assert 'Resource: "*"' not in send
    for removed in ("ec2:RunInstances", "ec2:TerminateInstances", "cloudformation:CreateStack", "lambda:InvokeFunction", "sns:Publish"):
        assert removed not in block


@pytest.mark.parametrize(("template", "logical_id"), WINDOW_ROLES)
def test_tagging_is_limited_to_windows_being_created(template: Path, logical_id: str) -> None:
    block = _resource_block(template, logical_id)
    assert "ssm:AddTagsToResource" not in _statement(block, "CreateTaggedMaintenanceWindows")
    tag = _statement(block, "TagMaintenanceWindowsOnCreate")
    assert "Effect: Allow" in tag and "Action: ssm:AddTagsToResource" in tag
    assert tag.rstrip().endswith("aws:RequestTag/createdBy: SRA_Patch_Management")
    assert 'Resource: "*"' not in tag and ":maintenancewindow/*" in tag and "mw-" not in tag
    deny = _statement(block, "DenyTaggingExistingMaintenanceWindows")
    assert "Effect: Deny" in deny and "Action: ssm:AddTagsToResource" in deny
    assert ":maintenancewindow/mw-*" in deny and "Condition" not in deny


@pytest.mark.parametrize(("template", "logical_id"), ROLES)
def test_no_statement_on_everything_grants_window_writes_or_tagging(template: Path, logical_id: str) -> None:
    for statement in _statements(_resource_block(template, logical_id)):
        if "Effect: Allow" not in statement or not RESOURCE_EVERYTHING.search(statement):
            continue
        assert not WINDOW_WRITE.search(statement), f"window write or tagging action allowed on every resource:{statement}"
        if "ssm:CreateMaintenanceWindow" in statement:  # has no resource type, so it must be limited by the request tag
            assert "aws:RequestTag/createdBy: SRA_Patch_Management" in statement


def test_lambda_role_has_no_window_tagging_or_pass_role_permissions() -> None:
    """The Lambda makes every window call with the configuration role it assumes in each account (the management account included)."""
    block = _without_comments(_resource_block(LAMBDA_TEMPLATE, "rPatchMgmtLambdaRole"))
    for policy in ("sra-patch-mgmt-ssm-general", "sra-patch-mgmt-passrole"):
        assert f"PolicyName: {policy}" not in block
    assert not re.search(r"MaintenanceWindow|ssm:AddTagsToResource|iam:PassRole|ssm:UpdateServiceSetting", block)


@pytest.mark.parametrize(("template", "logical_id"), WINDOW_ROLES)
def test_pass_role_is_limited_to_ssm(template: Path, logical_id: str) -> None:
    passrole = _statement(_resource_block(template, logical_id), "AllowPassRoleSimple")
    assert "Action: iam:PassRole" in passrole
    assert "iam:PassedToService: ssm.amazonaws.com" in passrole


def test_automation_role_cannot_pass_itself() -> None:
    assert "iam:PassRole" not in _resource_block(ROLE_TEMPLATE, "rSSMAutomationRole")


def test_stackset_gets_a_template_revision_so_existing_deployments_update() -> None:
    stackset = _resource_block(MAIN_TEMPLATE, "rpatchmgmtConfigurationIAMRoleStackSet")
    assert re.search(r"ParameterKey: pTemplateRevision\n\s+ParameterValue: '?\d+'?", stackset), "main-ssm must pass pTemplateRevision to the StackSet"
    role = ROLE_TEMPLATE.read_text()
    assert re.search(
        r"^  pTemplateRevision:\n(?:    .*\n)*?    Default: '?\d+'?", role, re.M
    ), "the role template must declare pTemplateRevision with a default"
    for logical_id in ("rConfigurationRole", "rSSMAutomationRole"):
        assert "Value: !Ref pTemplateRevision" in _resource_block(ROLE_TEMPLATE, logical_id), f"{logical_id} must use pTemplateRevision"


@pytest.mark.parametrize(("template", "logical_id"), [(ROLE_TEMPLATE, "rConfigurationRole"), (LAMBDA_TEMPLATE, "rPatchMgmtLambdaRole")])
def test_scoped_roles_have_no_ckv_aws_111_suppression(template: Path, logical_id: str) -> None:
    assert "CKV_AWS_111" not in _resource_block(template, logical_id)
