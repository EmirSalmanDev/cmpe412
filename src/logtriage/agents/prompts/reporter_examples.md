---
prompt_version: reporter-examples-1
---
# Examples
The two examples below are invented. Their hosts, addresses, users and events belong to no incident you will see. They show the form and the care of a good report, never its content: do not copy their facts, techniques or verdicts.

Each example is the whole saved report, as one json object. Code fills in `incident_id`, the technique `name`, `evidence`, `verifier_rounds`, `unsupported_claims_removed` and `meta`, so your own answer holds only the fields of the final answer format above. Here `evidence` stands for the evidence list you are given.

## Example 1: an archive job, the verdict is benign

```json
{
  "incident_id": "sample-0001",
  "summary": [
    {"text": "On host-a the vaultsync archive job nightly-docs began under operator user1 and finished with status ok.", "evidence": ["E1", "E3"]},
    {"text": "The job pushed 418 chunks, 2087 MiB in total, to 192.0.2.40.", "evidence": ["E2"]}
  ],
  "timeline": [
    {"ts": "2023-05-09T01:00:04Z", "claim": {"text": "vaultsync began job nightly-docs under operator user1.", "evidence": ["E1"]}},
    {"ts": "2023-05-09T01:22:41Z", "claim": {"text": "vaultsync pushed 418 chunks, 2087 MiB, to 192.0.2.40.", "evidence": ["E2"]}},
    {"ts": "2023-05-09T01:23:02Z", "claim": {"text": "vaultsync finished job nightly-docs with status ok.", "evidence": ["E3"]}}
  ],
  "techniques": [],
  "verdict": "benign",
  "confidence": 0.7,
  "recommended_actions": ["Check that 192.0.2.40 is on the list of archive targets of host-a."],
  "evidence": [
    {"eid": "E1", "line_id": "host-a|logs/vaultsync.log|3101", "ts": "2023-05-09T01:00:04Z", "host": "host-a", "log_type": "archive", "raw": "2023-05-09T01:00:04Z vaultsync[2210] job=nightly-docs state=begin operator=user1", "note": "start of the job"},
    {"eid": "E2", "line_id": "host-a|logs/vaultsync.log|3188", "ts": "2023-05-09T01:22:41Z", "host": "host-a", "log_type": "archive", "raw": "2023-05-09T01:22:41Z vaultsync[2210] job=nightly-docs pushed=418 chunks mib=2087 target=192.0.2.40", "note": "volume and target"},
    {"eid": "E3", "line_id": "host-a|logs/vaultsync.log|3190", "ts": "2023-05-09T01:23:02Z", "host": "host-a", "log_type": "archive", "raw": "2023-05-09T01:23:02Z vaultsync[2210] job=nightly-docs state=finish status=ok", "note": "end of the job"}
  ],
  "verifier_rounds": 0,
  "unsupported_claims_removed": [],
  "meta": {}
}
```

## Example 2: a relay setting, the verdict is uncertain

```json
{
  "incident_id": "sample-0002",
  "summary": [
    {"text": "On host-b relayd took a setting open_relay=yes from operator user2 at 14:02:10 UTC.", "evidence": ["E1"]},
    {"text": "relayd then accepted two messages with auth=none from client 198.51.100.23, both addressed to inbox@partner.example.", "evidence": ["E1", "E2", "E3"]}
  ],
  "timeline": [
    {"ts": "2023-05-09T14:02:10Z", "claim": {"text": "relayd took the setting open_relay=yes from operator user2.", "evidence": ["E1"]}},
    {"ts": "2023-05-09T14:10:12Z", "claim": {"text": "relayd accepted a message from ops@corp.example for inbox@partner.example, client 198.51.100.23, auth=none.", "evidence": ["E2"]}},
    {"ts": "2023-05-09T14:10:49Z", "claim": {"text": "relayd accepted a message from billing@corp.example for inbox@partner.example, client 198.51.100.23, auth=none.", "evidence": ["E3"]}}
  ],
  "techniques": [
    {"technique_id": "T1114.003", "name": "Email Forwarding Rule", "justification": {"text": "Two messages of corp.example senders went to one address of partner.example.", "evidence": ["E2", "E3"]}}
  ],
  "verdict": "uncertain",
  "confidence": 0.4,
  "recommended_actions": ["Ask user2 why open_relay was set.", "Check who controls 198.51.100.23 and inbox@partner.example."],
  "evidence": [
    {"eid": "E1", "line_id": "host-b|logs/relayd.log|812", "ts": "2023-05-09T14:02:10Z", "host": "host-b", "log_type": "relay", "raw": "2023-05-09T14:02:10Z relayd[880] setting open_relay=yes operator=user2", "note": "setting changed"},
    {"eid": "E2", "line_id": "host-b|logs/relayd.log|840", "ts": "2023-05-09T14:10:12Z", "host": "host-b", "log_type": "relay", "raw": "2023-05-09T14:10:12Z relayd[880] accepted from=ops@corp.example rcpt=inbox@partner.example client=198.51.100.23 auth=none", "note": "first message"},
    {"eid": "E3", "line_id": "host-b|logs/relayd.log|843", "ts": "2023-05-09T14:10:49Z", "host": "host-b", "log_type": "relay", "raw": "2023-05-09T14:10:49Z relayd[880] accepted from=billing@corp.example rcpt=inbox@partner.example client=198.51.100.23 auth=none", "note": "second message"}
  ],
  "verifier_rounds": 0,
  "unsupported_claims_removed": [],
  "meta": {}
}
```
