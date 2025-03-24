# Generative AI Solutions for AWS SRA

## Table of Contents
- [Introduction](#introduction)
- [Solutions](#solutions)
- [References](#references)

---

## Introduction

This directory contains security solutions for implementing generative AI capabilities in alignment with AWS Security Reference Architecture (SRA) recommendations. The solutions focus on securing Amazon Bedrock implementations and related generative AI workloads.

## Solutions

- [SRA Bedrock Organizations Solution](./bedrock_org/)
This solution provides an automated framework for deploying Bedrock organizational security controls.

- [SRA Bedrock Guardrails Solution](./bedrock_guardrails/)
This solution provides an automated framework for deploying Bedrock guardrails across multiple AWS accounts and regions in an organization.

- [SRA Amazon GuardDuty Malware Protection for S3](./../../solutions/guardduty/guardduty_malware_protection_for_s3)
This solution deploys Amazon GuardDuty Malware Protection for S3. A key use case for this solution is in the preparation of knowledge bases for Retrieval Augmented Generation (RAG) with Amazon Bedrock.

## References
- [AWS SRA Generative AI Deep-Dive](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/gen-ai-sra.html)