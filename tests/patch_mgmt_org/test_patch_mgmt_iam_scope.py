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


@pytest.mark.parametrize(("template", "logical_id"), ROLES)
def test_no_wildcard_ssm_and_valid_action_names(template: Path, logical_id: str) -> None:
    block = _resource_block(template, logical_id)
    assert not re.search(r"Action:\s*ssm:\*", block)
    assert not re.search(r"^\s*- [a-z0-9-]+:[A-Za-z]+,\s*$", block, re.M), "action names must not end with a comma"


@pytest.mark.parametrize(("template", "logical_id"), ROLES[:2])
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


@pytest.mark.parametrize(("template", "logical_id"), ROLES[:2])
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
def test_no_allow_statement_grants_add_tags_on_everything(template: Path, logical_id: str) -> None:
    block = _without_comments(_resource_block(template, logical_id))
    for statement in re.split(r"(?=\n\s+- Sid: )", block):
        if "ssm:AddTagsToResource" in statement and "Effect: Allow" in statement:
            assert 'Resource: "*"' not in statement, "ssm:AddTagsToResource must not be allowed on every resource"


@pytest.mark.parametrize(("template", "logical_id"), ROLES[:2])
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
