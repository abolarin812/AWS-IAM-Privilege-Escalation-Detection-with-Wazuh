# AWS IAM Privilege Escalation Detection with Wazuh
This is a detection engineering project simulating a real IAM privilege escalation technique in AWS and building custom Wazuh detection logic to catch it, with a focus on understanding why the underlying misconfiguration is exploitable.

## Table of Contents

- [Objective](#objective)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Environment Setup](#environment-setup)
- [The Vulnerability](#the-vulnerability)
- [Detection Engineering](#detection-engineering)
  - [Validating Existing Coverage Before Building Anything](#validating-existing-coverage-before-building-anything)
  - [Design Decision](#design-decision)
  - [Final Detection Rule](#final-detection-rule)
- [Detection Result](#detection-result)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [SOC Analyst Response Guidance](#soc-analyst-response-guidance)
- [Known Limitations](#known-limitations)
- [What a Production Deployment Would Need](#what-a-production-deployment-would-need)

## Objective
The objective is to simulate a privilege escalation attack in AWS using a deliberately vulnerable environment (Rhino Security Lab Cloudgoat), ingest the activity into a SIEM (Wazuh) for full visibility, and build detection logic that catches the technique, including validating whether existing default detection coverage was sufficient before writing anything custom.


## Prerequisites
 - AWS account
 - Kali Linux (attacker workstation)
 - CloudGoat (Rhino Security Labs)
 - Wazuh, deployed on EC2 on AWS

## Architecture
CloudTrail logs all account activity to a dedicated S3 bucket. Wazuh, running on a separate EC2 instance with a least-privilege instance role (no static credentials), polls that bucket via its native AWS S3 module, decodes CloudTrail events, and evaluates them against both Wazuh's default ruleset and a custom detection rule built specifically for this technique.

```
AWS Account (370361598235)
|
|-- IAM
|   |-- cg-raynor-policy-cgid5hqx5w9xak    (vulnerable policy, 5 versions, v3 = admin)
|   `-- Specific-S3-Cloudtrail-Bucket-Access   (Wazuh instance policy, least privilege)
|
|-- CloudTrail
|   `-- Trail (multi-region (us-east-1 and us-north-1), management events only) --> delivers to S3
|
|-- S3
|   `-- aws-cloudtrail-wazuh-logs-s3/
|       `-- AWSLogs/370361598235/CloudTrail/us-east-1/2026/07/09/*.json.gz
|       `-- AWSLogs/370361598235/CloudTrail/us-north-1/2026/07/09/*.json.gz
`-- EC2
    `-- Wazuh Manager Instance
        |-- IAM Instance Role (s3:ListBucket, s3:GetObject, scoped to bucket only)
        |-- ossec.conf: <wodle name="aws-s3"> (polls S3 every 5 min)
        |-- archives.json (decoded CloudTrail events)
        |-- local_rules.xml: rule 100013 (detects SetDefaultPolicyVersion, T1548.003)
        |-- alerts.json (rule matches: 80202 + 100013)
        `-- Wazuh Dashboard: Security Events -> rule.id: 100013 (confirmed alert)

Kali Linux (Attacker) --> CloudGoat --> Raynor identity --> AWS IAM API calls
```

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


## Detection Engineering

### Validating existing coverage before building anything

Before writing a custom rule, Wazuh's default AWS ruleset (`0350-amazon_rules.xml`) was tested directly against real, decoded CloudTrail events for each API call in the attack chain using `wazuh-logtest`. `ListPolicyVersions` and `GetPolicyVersion` matched only the generic parent rule (80200, level 0), confirming no dedicated detection exists for these calls, they are logged but never surfaced as an alert. `SetDefaultPolicyVersion` was separately confirmed present in Wazuh's aws-eventnames lookup list, meaning it does receive generic coverage under rule 80202 (level 3, no MITRE context, no severity weighting) even without any custom rule.

### Design decision

An earlier design attempted to detect the full three-step sequence (enumeration → inspection → rollback) using Wazuh's cross-event correlation directives `if_matched_sid`. This approach was abandoned after live testing revealed a structural mismatch between the mechanism and the use case. Wazuh's documentation specifies that `if_matched_sid` is designed to pair with frequency and timeframe, and that frequency has a hard minimum of two (2), meaning the correlated rule cannot fire until its match condition has been satisfied twice within the configured window. This directly conflicts with the threat model here (the privilege escalation technique only requires the attacker to execute the sequence once to fully succeed) so a rule built on Wazuh's documented correlation pattern would never fire against a real, single-occurrence attack. This was confirmed directly, a correctly sequenced, correctly timed live test with matching identity fields did not trigger the correlated rule, because the underlying pattern occurred once rather than twice. An earlier variant without frequency set at all was also tested and also failed to fire consistently, that variant's exact failure mode was not conclusively isolated, but given the confirmed frequency based limitation, cross event correlation via this mechanism was assessed as unsuitable for single occurrence attack detection and de-prioritized in favor of single event detection on the decisive action.

The final design detects the decisive action directly, treating `SetDefaultPolicyVersion` as the escalation event itself, rather than attempting to correlate the full behavioral sequence leading to it. This trades some context (the rule alone does not prove enumeration preceded it) for reliability.

### Final detection rule

```
<group name="iam_privesc,cloudgoat,aws">
  <rule id="100013" level="8">
    <if_sid>80200</if_sid>
    <field name="aws.eventName">^SetDefaultPolicyVersion$</field>
    <description>AWS IAM SetDefaultPolicyVersion called, potential privilege escalation via policy version rollback</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
  </rule>
</group>
```

This rule fires independently of, and in addition to, the default rule 80202 match on the same event, giving the analyst both a generic low-severity alert and a properly contextualized, higher-severity, MITRE-tagged one.

## Detection Result

Live simulation of the full attack chain, executed against the real deployed CloudGoat environment, produced a confirmed alert in the Wazuh dashboard under rule 100013 at the moment of privilege escalation.

![image alt](https://github.com/abolarin812/AWS-IAM-Privilege-Escalation-Detection-with-Wazuh/blob/6eee0a9469a791c94ece6462c85d17819e0ac7ee/Images/wazuh-alert-rule-100013-triggered.png)

## MITRE ATT&CK Mapping

| Stage | Technique | ID |
|-------|-----------|----|
| Enumeration | Permission Groups Discovery | `T1069` |
| Escalation | Abuse Elevation Control Mechanism | `T1548` |

## SOC Analyst Response Guidance
**Triage** : Confirm whether the identity that called SetDefaultPolicyVersion normally performs IAM policy management. A one-off call from an identity with no history of touching IAM policy versions warrants immediate escalation.

**Investigation** : Pull the full CloudTrail history for the calling identity across the preceding 15–30 minutes. Look specifically for **ListPolicyVersions** and **GetPolicyVersion** calls against the same policy ARN immediately prior, this is the enumeration pattern that precedes this technique, even though it is not captured by the automated rule itself.

**Containment** : If confirmed malicious, immediately roll the policy back to its prior (non-privileged) default version, rotate or disable the identity's credentials, and review CloudTrail for any actions taken under the elevated policy between the rollback and detection.

## Known Limitations

**Detection** is scoped to the decisive action only; Multi-stage correlation was not implemented because Wazuh's native `if_matched_sid` correlation requires a minimum frequency of two, whereas this attack succeeds with a single execution of each step.

**The** rule cannot distinguish a malicious rollback from a legitimate administrative one (e.g., a genuine policy revert during incident response). In a production deployment this would require either a known-identity allowlist or a broader behavioral baseline, neither of which was in scope here.

**Detection** latency is bound by S3 polling interval (5 minutes) plus CloudTrail's own delivery lag (typically 5–10 minutes). A production deployment would benefit from event-driven ingestion via SNS/SQS instead of polling, this removes wazuh S3 polling interval but not CloudTrail's own delivery lag.

## What a Production Deployment Would Need

**Event-driven log ingestion** (SNS → SQS → Wazuh) instead of interval polling, to reduce detection latency that might be caused by wazuh polling time.

**A CSPM-style process** to maintain an up-to-date inventory of which IAM roles/policies are actually privilege-equivalent, since CloudTrail alone cannot express "this specific role is dangerous," only "this action occurred"

**A custom correlation mechanism** external to Wazuh's native rule engine to detect the full attack sequence, as the native `if_matched_sid` correlation is unsuitable for single-occurrence attack chains.



