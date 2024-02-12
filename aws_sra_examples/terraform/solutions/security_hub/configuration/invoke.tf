########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

resource "aws_lambda_invocation" "lambda_invoke" {
  function_name = aws_lambda_function.security_hub_lambda_function.function_name

  input = jsonencode({
    "RequestType" : "Update",
    "ResourceType" : "Custom::LambdaCustomResource",
    "ResourceProperties" : {
      "ServiceToken" : "${aws_lambda_function.security_hub_lambda_function.arn}",
      "LOG_LEVEL" : "${var.lambda_log_level}",
      "CIS_VERSION" : "${var.cis_standard_version}",
      "CONFIGURATION_ROLE_NAME" : "${var.security_hub_configuration_role_name}",
      "DISABLE_SECURITY_HUB" : "${var.disable_security_hub}",
      "ENABLED_REGIONS" : "${var.enabled_regions}",
      "ENABLE_CIS_STANDARD" : "${var.enable_cis_standard}",
      "ENABLE_PCI_STANDARD" : "${var.enable_pci_standard}",
      "ENABLE_NIST_STANDARD" : "${var.enable_nist_standard}",
      "ENABLE_SECURITY_BEST_PRACTICES_STANDARD" : "${var.enable_security_best_practices_standard}",
      "PCI_VERSION" : "${var.pci_standard_version}",
      "NIST_VERSION" : "${var.nist_standard_version}",
      "REGION_LINKING_MODE" : "${var.region_linking_mode}",
      "SECURITY_BEST_PRACTICES_VERSION" : "${var.security_best_practices_standard_version}",
    }
  })
}
