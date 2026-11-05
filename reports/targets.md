# Frozen targets

**Frozen on 2026-11-05 at commit `PENDING`** (tag `m3-done`). This file must not change after that commit to make results look better (plan §14.3). If a definition turns out to be buggy, fix it, log it in `status.md`, and report it in `reports/results.md`.

Evidence: `notebooks/01_eda.ipynb`. Nothing here uses a detection result: no window, feature or model existed at the freeze.

## Targets

Scored on the **santos evaluation period**. russellmitchell numbers are dev numbers and are reported separately.

| Target | Value | On santos |
|---|---|---|
| Phase recall | ≥ 80% of phases with traces | ≥ 8 of 9 phases |
| Incidents per day | ≤ 25 | ≤ 67 incidents in 2.697 days |
| Alert reduction | ≥ 90% fewer incidents than raw IDS alerts per day | 30,774 alerts per day, so ≤ 3,077 incidents per day |
| ATT&CK top-3, strict | ≥ 70% of malicious incidents | |
| Manual faithfulness | ≥ 90% with the Verifier, and higher than without | |

All preliminary targets of plan §10.5 are kept unchanged (D21). Each can be measured: every counted phase has labeled lines in a log type with a baseline, and the IDS data covers the evaluation period.

## Phases

Labeled lines in the evaluation period, in time order. *Counted* means the phase is in the primary denominator.

### santos

| Phase | Labeled lines | Log types | Baseline-capable log types | Counted |
|---|---|---|---|---|
| `dnsteal_exfil` | 16,773 (38,561 with training) | dns | dns | yes |
| `service_stop` | 2 | audit | audit | yes |
| `dnsteal` | 0 | | | no: no labeled lines |
| `network_scans` | 558 | dns, vpn | dns, vpn | yes |
| `service_scans` | 327 | apache_access, dns | apache_access, dns | yes |
| `dirb` | 4,485 | apache_access, apache_error | apache_access | yes |
| `wpscan` | 3,314 | apache_access, apache_error, dns | apache_access, dns | yes |
| `webshell` | 29 | apache_access | apache_access | yes |
| `cracking` | 16 | apache_access, dns | apache_access, dns | yes |
| `reverse_shell` | 0 | | | no: no labeled lines |
| `privilege_escalation` | 31 | audit, auth | audit, auth | yes |

### russellmitchell (dev)

| Phase | Labeled lines | Log types | Baseline-capable log types | Counted |
|---|---|---|---|---|
| `dnsteal_exfil` | 21,399 (53,006 with training) | dns | dns | yes |
| `network_scans` | 538 | dns, vpn | dns, vpn | yes |
| `service_scans` | 455 | apache_access, dns | apache_access, dns | yes |
| `dirb` | 4,493 | apache_access, apache_error, dns | apache_access, dns | yes |
| `wpscan` | 3,207 | apache_access, apache_error, dns | apache_access, dns | yes |
| `webshell` | 31 | apache_access | apache_access | yes |
| `cracking` | 16 | apache_access, dns | apache_access, dns | yes |
| `reverse_shell` | 0 | | | no: no labeled lines |
| `privilege_escalation` | 17 | audit, auth | audit, auth | yes |
| `service_stop` | 12 | audit, dns | audit, dns | yes |
| `dnsteal` | 38 | dns | dns | yes |

## Phases with traces

A phase has traces if the evaluation period holds at least one of its labeled lines. Plan §10 scores the evaluation period, so a phase seen only in training could not count; no phase is in that position today.

| Testbed | Variant | Phases | Needed for 80% |
|---|---|---|---|
| santos | primary: baseline-capable log types | 9 | 8 |
| santos | secondary: all parsed log types | 9 | 8 |
| santos | secondary: primary without `dnsteal_exfil` | 8 | 7 |
| russellmitchell | primary: baseline-capable log types | 10 | 8 |
| russellmitchell | secondary: all parsed log types | 10 | 8 |
| russellmitchell | secondary: primary without `dnsteal_exfil` | 9 | 8 |

Needed phases are the 80% share rounded up. The primary variant is the target; both secondary variants are reported beside it.

**Excluded phases.** `dnsteal` on santos and `reverse_shell` on both testbeds have no labeled line in any parsed log type, so they are not in any denominator (D18).

**Phases with traces only in log types without a baseline: none.** The two denominators are equal on both testbeds. `dirb` and `wpscan` have `apache_error` lines, but also lines in `apache_access`.

## Baseline-capable log types

A `(testbed, log_type)` needs at least 200 parsed fit-period lines and at least 50 parsed calib-period lines (D19). Lines are fit / calib.

| log_type | russellmitchell | santos | Baseline-capable |
|---|---|---|---|
| `apache_access` | 40,217 / 7,933 | 51,221 / 1,581 | yes, both |
| `apache_error` | 13 / 0 | 0 / 10 | **no, both** |
| `audit` | 8,372 / 1,384 | 5,956 / 1,001 | yes, both |
| `auth` | 2,283 / 544 | 1,375 / 352 | yes, both |
| `dns` | 231,943 / 34,904 | 146,692 / 17,898 | yes, both |
| `vpn` | 2,291 / 439 | 1,395 / 147 | yes, both |

`apache_error` is left out of ensemble and incidents, reported as "no baseline, not detectable", and stays in parsed data and agent tools.

## Label-ambiguous windows and incidents

`inet-dns` carries the same exfiltration as `inet-firewall`, but only `inet-firewall` is labeled (D17).

- **Window:** a window is label-ambiguous if its `log_type` is `dns` and its `host` is `inet-dns`. That covers the whole stream, in every period. Other log types of that host are not affected.
- **Incident:** an incident is label-ambiguous if it has at least one label-ambiguous window and no attack window. One attack window makes it malicious as usual.

| Metric | Primary | Secondary |
|---|---|---|
| Window precision, recall, F1, PR-AUC, false positives | leave out label-ambiguous windows | include them as normal |
| Verdict confusion matrix and F1 | leave out label-ambiguous incidents | include them as benign |
| Phase recall | unaffected: these windows hold no labeled lines | none needed |
| ATT&CK top-1 and top-3 | unaffected: scored on malicious incidents | none needed |
| Incidents per day, alert reduction | count every incident, because an analyst still reads them | none needed |

## DNS results

The training period holds exfiltration and is not cleaned (D16). The primary recall definition of plan §10.2 stands, so `dnsteal_exfil` is in the target denominator. M5 and M11 report `dns` results separately, and phase recall also without `dnsteal_exfil`.

| Exfiltration share of `inet-firewall` DNS lines | russellmitchell | santos |
|---|---|---|
| Training period | 21.6% | 26.0% |
| Fit | 20.1% | 23.9% |
| Calib | 31.1% | 47.8% |
| Hourly range in training | 7.1–45.5% | 8.6–90.2% |
| Training hours with exfiltration | 52 of 52 | 32 of 32 |

## Incidents per day budget

**The budget is 25 incidents per day** (D20), in `ml.incidents_per_day_budget`. Per-day rates divide by the length of the evaluation period: 1.874 days on russellmitchell and 2.697 on santos, so the limits are 46 and 67 incidents.

"≥ 90% fewer" needs incidents/day ≤ 0.1 × alerts/day. The alerts are all AIT-ADS alerts in the evaluation period (Wazuh, Suricata through Wazuh, and AMiner).

| Scope | russellmitchell alerts/day | Largest budget | santos alerts/day | Largest budget |
|---|---|---|---|---|
| **All raw alerts (the target)** | **15,704** | **1,570** | **30,774** | **3,077** |
| Without mirrored files | 11,678 | 1,167 | 18,989 | 1,898 |
| Suricata only | 5,306 | 530 | 18,166 | 1,816 |
| Wazuh only | 8,447 | 844 | 11,209 | 1,120 |
| AMiner only | 1,951 | 195 | 1,399 | 139 |

Mirrored files are `fast.log` and `mail.info`, which repeat `eve.json` and `mail.log`.

25 per day is feasible in every scope, so the default stands. At 25 the reduction is 99.84% on russellmitchell and 99.92% on santos. This also means the 90% target cannot fail if the budget holds: the budget is the binding target, and the 90% figure is an easy check on it. Plan §10.2 also compares incidents with alerts grouped by the gap rule, which needs `gap_minutes` from M5.

## Gold ATT&CK mapping

`configs/gold_attack_mapping.yaml` holds an entry for each of the 11 phases of the phases files. All 16 IDs exist and are neither revoked nor deprecated in ATT&CK 20.1. `dnsteal_exfil` has the set of `dnsteal`: T1048.003, T1048, T1071.004 (D18).

## Known limitations

Stated before any result exists, and not a reason to change the targets later.

- **Unlabeled exfiltration:** 53,052 lines on russellmitchell and 38,559 on santos, on `inet-dns`. Handled by the label-ambiguous rule.
- **Unlabeled attacker lines:** inside phase windows, between 50 and 513 lines on russellmitchell and between 2 and 625 on santos. The low end is the attacker's own address; the high end adds the VPN tunnel address, which ordinary users also get. The labels do not cover them, so primary metrics may count some true detections as false positives.
- **Unlabeled attacker output:** 3,847 stderr lines per testbed in `intranet_server` error logs, with unreliable timestamps. They stay out of windows (D14), so they can neither be detected nor count as false positives.
- **Small phases:** `service_stop` has 2 labeled lines on santos and `cracking` 16. Both are measurable, but the target allows only one missed phase.
- **VPN lines:** the 28 attacker VPN lines per testbed are in `network_scans`, whose gold set has no VPN technique, so a VPN-only incident is scored against scanning techniques.
- **Calibration:** the santos calib period holds quiet night hours; see the open question in `status.md`.
