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
