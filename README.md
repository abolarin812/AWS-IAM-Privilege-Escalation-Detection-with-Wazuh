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

**Least-privilege access for Wazuh** : a custom IAM policy granting only s3:ListBucket on the bucket ARN and s3:GetObject on the object ARN, attached via role, not static keys, to the Wazuh EC2 instance.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/b891006a2691ac59325687505f14b5f5e9fc2a55/Images/iam-policy-least-privilege.png)

*Fig 3: PoLP Policy*

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/b891006a2691ac59325687505f14b5f5e9fc2a55/Images/iam-role-policy-binding.png)

*Fig 4: Role Policy Binding*

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/b891006a2691ac59325687505f14b5f5e9fc2a55/Images/instance-profile-attachment.png)

*Fig 5: Instance Profile Attachment*

**Wazuh AWS S3 ingestion** : configured via the aws-s3 wodle in ossec.conf, polling the CloudTrail bucket on a 5-minute interval.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/694028af2aa6a8fcc73c6c5040fb182bf9239a0a/Images/wazuh-aws-s3-wodle-config.png)

*Fig 6: Wazuh AWS S3 Wodle Config*

**CloudGoat Deployment** : installed and configured on Kali Linux, scenario deployed against the target AWS account under a dedicated named profile.






### Tools Used
[Bullet Points - Remove this afterwards]

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Network Diagram*
