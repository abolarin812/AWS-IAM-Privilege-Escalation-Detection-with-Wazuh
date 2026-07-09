# AWS IAM Privilege Escalation Detection with Wazuh
This is a detection engineering project simulating a real IAM privilege escalation technique in AWS and building custom Wazuh detection logic to catch it, with a focus on understanding why the underlying misconfiguration is exploitable.

## Objective
The objective is to simulate a privilege escalation attack in AWS using a deliberately vulnerable environment (Rhino Security Lab Cloudgoat), ingest the activity into a SIEM (Wazuh) for full visibility, and build detection logic that catches the technique, including validating whether existing default detection coverage was sufficient before writing anything custom.

## Prerequisites
 - AWS account
 - Kali Linux (attacker workstation)
 - CloudGoat (Rhino Security Labs)
 - Wazuh, deployed on EC2 on AWS

## Architecture
CloudTrail logs all account activity to a dedicated S3 bucket. Wazuh, running on a separate EC2 instance with a least-privilege instance role (no static credentials), polls that bucket via its native AWS S3 module, decodes CloudTrail events, and evaluates them against both Wazuh's default ruleset and a custom detection rule built specifically for this technique.

## Environment Setup
**CloudTrail configuration** : multi-region trail, management events only, delivering to a dedicated S3 bucket with a scoped bucket policy restricted to the CloudTrail service principal.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/4a361a151fdd8e3da3d51d91d7b10bd81683be18/Images/cloudtrail-trail-configuration.png)

*Fig 1: Cloudtrail Configuration*

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/803ea60ba5e4fad1f5c4b2287a05ed6e4efdfcad/Images/cloudtrail-deployed.png)

*Fig 2: Cloudtrail Deployed*

**Least-privilege access for Wazuh** : a custom IAM policy granting only `s3:ListBucket` on the bucket ARN and `s3:GetObject` on the object ARN, attached via role, not static keys, to the Wazuh EC2 instance.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/b891006a2691ac59325687505f14b5f5e9fc2a55/Images/iam-policy-least-privilege.png)

*Fig 3: PoLP Policy*

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/b891006a2691ac59325687505f14b5f5e9fc2a55/Images/iam-role-policy-binding.png)

*Fig 4: Role Policy Binding*

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/b891006a2691ac59325687505f14b5f5e9fc2a55/Images/instance-profile-attachment.png)

*Fig 5: Instance Profile Attachment*

**Wazuh AWS S3 ingestion** : configured via the `aws-s3` wodle in `ossec.conf`, polling the CloudTrail bucket on a 5-minute interval.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/694028af2aa6a8fcc73c6c5040fb182bf9239a0a/Images/wazuh-aws-s3-wodle-config.png)

*Fig 6: Wazuh AWS S3 Wodle Config*

**CloudGoat Deployment** : installed and configured on Kali Linux, scenario deployed against the target AWS account under a dedicated named profile.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/681f3b06007e3e2958fe7dc0613675a1d9e604d9/Images/Cloudgoat%20Installation.png)

*Fig 7: Cloudgoat Installation*

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/681f3b06007e3e2958fe7dc0613675a1d9e604d9/Images/Cloudgoat%20Configuration.png)

*Fig 8: Cloudgoat Configuration*

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/681f3b06007e3e2958fe7dc0613675a1d9e604d9/Images/Cloudgoat%20Scenerio%20Deployed.png)

*Fig 9: Cloudgoat Scenerio Deployed*

## The Vulnerability
**Scenario:** `iam_privesc_by_rollback` (CloudGoat, Rhino Security Labs).
The attacker's identity, Raynor, holds an IAM policy with three permissions attached to a single statement, scoped to all resources: `iam:Get*, iam:List*, and iam:SetDefaultPolicyVersion`. The policy has five stored versions. One historical version that is no longer active grants full administrative access to user. Because IAM retains old policy versions by default and `SetDefaultPolicyVersion` allows any of them to be reactivated, an identity with only read and rollback permissions can restore a previous, more permissive version of its own policy without ever needing `iam:PutPolicy` or `iam:CreatePolicyVersion`.

### Attack path, reconstructed and verified against real CloudTrail output:

**1. Confirm identity and enumerate attached policy** : `aws iam get-user`

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/352fc980f94cd88800d28ddc4de27132faf34430/Images/Raynor-Identity-Check.png)

*Fig 10: Raynor Identity Check*

**2. Enumerate the attached policy and its current (default) version** : `aws iam list-attached-user-policies`, `aws iam get-policy`

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/58809aeb8974543607a4cac0584fde4457c00384/Images/raynor-policy-enumeration.png)

*Fig 11: Raynor Rolicy Enumeration*

**3. Inspect the currently active policy version's permissions** : `aws iam get-policy-version --version-id v1`. Confirms the active version grants only `Get*`, `List*`, and `SetDefaultPolicyVersion` on all resources.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/60858327ba9cb6ffe6339d5fbc93d2c8e0dccccd/Images/active-policy-version-permissions.png)

*Fig 12: Active Policy Version Permissions*

**4. List all stored policy versions** : five versions found.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/a187dcd6ae10872852f56d456e445f6a91de2425/Images/policy-version-listing.png)

**5. Inspect the remaining four versions individually** : version v3 identified as granting full administrative access.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/593cb6dc71c660051f644bbca30a06877598776a/Images/policy-version-inspection-admin-identified.png)

*Fig 13: Policy Version Inspection Admin Identified*

**6. Roll back to the administrative version** :  `aws iam set-default-policy-version --version-id v3`. Privilege escalation complete, Raynor now operates under an administrator-equivalent policy.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/593cb6dc71c660051f644bbca30a06877598776a/Images/privilege-escalation-execution.png) 

*Fig 14: Privilege Escalation Execution*







