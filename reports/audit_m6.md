# M6 audit

Read-only: no model was fit and santos was not scored.

## Windows per period

| testbed | log_type | period | windows | attack | ambiguous | exfil_only |
| --- | --- | --- | --- | --- | --- | --- |
| russellmitchell | apache_access | fit | 4172 | 0 | 0 | 0 |
| russellmitchell | apache_access | calib | 1264 | 0 | 0 | 0 |
| russellmitchell | apache_access | eval | 3458 | 4 | 0 | 0 |
| russellmitchell | audit | fit | 1393 | 0 | 0 | 0 |
| russellmitchell | audit | calib | 209 | 0 | 0 | 0 |
| russellmitchell | audit | eval | 1514 | 3 | 0 | 0 |
| russellmitchell | auth | fit | 1136 | 0 | 0 | 0 |
| russellmitchell | auth | calib | 272 | 0 | 0 | 0 |
| russellmitchell | auth | eval | 1249 | 2 | 0 | 0 |
| russellmitchell | dns | fit | 4896 | 2448 | 2448 | 2448 |
| russellmitchell | dns | calib | 1226 | 613 | 613 | 613 |
| russellmitchell | dns | eval | 4855 | 2092 | 2420 | 2083 |
| russellmitchell | vpn | fit | 119 | 0 | 0 | 0 |
| russellmitchell | vpn | calib | 24 | 0 | 0 | 0 |
| russellmitchell | vpn | eval | 157 | 1 | 0 | 0 |
| santos | apache_access | fit | 1832 | 0 | 0 | 0 |
| santos | apache_access | calib | 83 | 0 | 0 | 0 |
| santos | apache_access | eval | 5632 | 4 | 0 | 0 |
| santos | audit | fit | 993 | 0 | 0 | 0 |
| santos | audit | calib | 164 | 0 | 0 | 0 |
| santos | audit | eval | 2730 | 2 | 0 | 0 |
| santos | auth | fit | 692 | 0 | 0 | 0 |
| santos | auth | calib | 176 | 0 | 0 | 0 |
| santos | auth | eval | 1798 | 1 | 0 | 0 |
| santos | dns | fit | 3002 | 1501 | 1501 | 1501 |
| santos | dns | calib | 750 | 375 | 375 | 375 |
| santos | dns | eval | 5949 | 1446 | 2997 | 1441 |
| santos | vpn | fit | 77 | 0 | 0 | 0 |
| santos | vpn | calib | 7 | 0 | 0 | 0 |
| santos | vpn | eval | 227 | 1 | 0 | 0 |

## Attack windows per phase, russellmitchell eval

| phase | apache_access | audit | auth | dns | vpn |
| --- | --- | --- | --- | --- | --- |
| cracking | 1 | 0 | 0 | 1 | 0 |
| dirb | 1 | 0 | 0 | 1 | 0 |
| dnsteal | 0 | 0 | 0 | 3 | 0 |
| dnsteal_exfil | 0 | 0 | 0 | 2090 | 0 |
| network_scans | 0 | 0 | 0 | 3 | 1 |
| privilege_escalation | 0 | 2 | 2 | 0 | 0 |
| service_scans | 2 | 0 | 0 | 2 | 0 |
| service_stop | 0 | 1 | 0 | 1 | 0 |
| webshell | 2 | 0 | 0 | 0 | 0 |
| wpscan | 2 | 0 | 0 | 1 | 0 |

## Kept feature columns

| log_type | russellmitchell | santos | intersection | dropped |
| --- | --- | --- | --- | --- |
| apache_access | 19 | 18 | 18 | n_unseen_src_ip |
| audit | 9 | 9 | 9 |  |
| auth | 14 | 14 | 14 |  |
| dns | 15 | 15 | 15 |  |
| vpn | 11 | 11 | 11 |  |

## Unseen and rarity means, russellmitchell, no labels

| feature | log_type | fit | calib | eval |
| --- | --- | --- | --- | --- |
| n_unseen_templates | apache_access | 0.0 | 0.0032 | 2.2377 |
| ratio_unseen_templates | apache_access | 0.0 | 0.0003 | 0.0023 |
| mean_template_rarity | apache_access | 1.0123 | 0.6616 | 1.2638 |
| max_template_rarity | apache_access | 1.919 | 1.0037 | 2.4274 |
| ratio_unseen_paths | apache_access | 0.0 | 0.0009 | 0.0049 |
| ratio_unseen_ua | apache_access | 0.0 | 0.0 | 0.0014 |
| n_unseen_src_ip | apache_access | 0.0 | 0.0 | 0.0006 |
| n_unseen_templates | audit | 0.0 | 0.0 | 0.0046 |
| ratio_unseen_templates | audit | 0.0 | 0.0 | 0.001 |
| mean_template_rarity | audit | 2.0839 | 2.2684 | 2.0778 |
| max_template_rarity | audit | 2.3873 | 2.5737 | 2.3752 |
| n_unseen_exe | audit | 0.0 | 0.0 | 0.0013 |
| n_unseen_templates | auth | 0.0 | 0.0 | 0.0144 |
| ratio_unseen_templates | auth | 0.0 | 0.0 | 0.0096 |
| mean_template_rarity | auth | 0.8157 | 0.7259 | 0.8288 |
| max_template_rarity | auth | 0.8205 | 0.7259 | 0.8341 |
| n_unseen_users | auth | 0.0 | 0.0 | 0.0032 |
| n_unseen_templates | dns | 0.0 | 0.0 | 0.0004 |
| ratio_unseen_templates | dns | 0.0 | 0.0 | 0.0 |
| mean_template_rarity | dns | 1.5503 | 1.462 | 1.6033 |
| max_template_rarity | dns | 2.9978 | 2.2689 | 3.0979 |
| n_unseen_domains | dns | 0.0 | 0.0082 | 0.226 |
| n_unseen_templates | vpn | 0.0 | 0.0 | 0.051 |
| ratio_unseen_templates | vpn | 0.0 | 0.0 | 0.0175 |
| mean_template_rarity | vpn | 2.775 | 2.8222 | 3.0456 |
| max_template_rarity | vpn | 4.1597 | 4.1166 | 4.4164 |
| n_unseen_src_ip | vpn | 0.0 | 0.0 | 0.0191 |

## Classes in 5 equal-count time blocks, russellmitchell calib and eval

| log_type | windows | positives | negatives | positives_per_block | negatives_per_block |
| --- | --- | --- | --- | --- | --- |
| apache_access | 4722 | 4 | 4718 | 0/0/0/4/0 | 945/945/944/940/944 |
| audit | 1723 | 3 | 1720 | 0/0/0/3/0 | 345/345/345/341/344 |
| auth | 1521 | 2 | 1519 | 0/0/0/2/0 | 305/304/304/302/304 |
| dns | 3048 | 2705 | 343 | 610/610/610/609/266 | 0/0/0/0/343 |
| vpn | 181 | 1 | 180 | 0/0/0/1/0 | 37/36/36/35/36 |
