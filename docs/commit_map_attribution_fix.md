# Commit map: attribution fix (D95)

On 2026-11-09 the commit messages of `main` were rewritten to remove the line `Co-Authored-By: Claude <noreply@anthropic.com>`, and the blank line before it, from the 14 commits that carried it (`f05601b` to `16ec00a` in the old history). Nothing else changed: every rewritten commit has the same tree, subject, author, committer, dates and parents (mapped), and every other message byte is identical. The 125 commits up to `1df1830` keep their hashes, and so do the tags `m0-done` to `m10b-done` and `targets-frozen`. A later commit has a new hash only because a parent changed.

Use this map to resolve an old hash cited in `status.md`, `plan.md`, the ledger or any document. The old history is not part of `main` or the tags on GitHub: they contain only rewritten history. But four old commits were pushed before the rewrite and stay reachable on GitHub by hash until GitHub garbage-collects them: `ab21d4b`, `3e7ad33`, `e8ca2f7` and `16ec00a`. `16ec00a` carries the `Co-Authored-By` trailer itself, and the history of each of the four contains commits that carry it (`f05601b`, `73b7ced`, `bae2ee0`; under `16ec00a` all 14). Locally the old history is kept in the bundle `../cmpe412-before-attribution-fix.bundle` and the local branch `backup/pre-attribution-fix`.

## Rewritten tags

| Tag | Type | Old commit | New commit | Old tag object | New tag object |
|---|---|---|---|---|---|
| `m11-done` | lightweight | `ab21d4bcd93bca6993379c576baf29d01952e0d6` | `6761752768090a1870fdc61ef271766ca098b77f` | – | – |
| `m12-done` | annotated | `16ec00ab620b7de64769943c542f7de75108b13c` | `b4c514c8afd53b7a99548119d81df4953df890ca` | `be1586f5378134bacf1031df8009eb0d32e4ebbf` | `50a61ec8575670d7dae27a3e97a0718143a8262b` |
| `m13-done` | lightweight | `e8ca2f7e3eef2222d407c5f971cbd9af9671d866` | `f16b29211e03b375272356ef29bc890f3d86efd9` | – | – |
| `v1.0` | lightweight | `e8ca2f7e3eef2222d407c5f971cbd9af9671d866` | `f16b29211e03b375272356ef29bc890f3d86efd9` | – | – |
| `v2.0` | annotated | `16ec00ab620b7de64769943c542f7de75108b13c` | `b4c514c8afd53b7a99548119d81df4953df890ca` | `4e847cab1576f036245c4addeeeddafa12081bc8` | `760a8e3946b3be7f4765ba41f0171b900a74c6fa` |

Annotated tags keep their tagger, date and message; lightweight tags stay lightweight.

## Rewritten commits (58, oldest first; † = message changed)

| Old | New | Subject |
|---|---|---|
| `f05601b54855` † | `7f75f09a709f` | docs(eval): M11 design note before any new metric |
| `73b7cedec590` † | `e9f21b33ee82` | feat(eval): metric tables from saved outputs, IDS grouping and event labels |
| `bae2ee014797` † | `0332a408a6c9` | feat(eval): M11 metric tables from saved outputs, harrison dns explained |
| `5f964c5ce917` | `5beee52dcdf2` | docs: D64-D68 M11 decisions, CI facts, plan markers |
| `6d99cc6a6c60` | `fa5d29a2ed3e` | feat(agents): reporter examples for the few-shot ablation, with leak tests |
| `ac6d83ad3ff4` | `b7f392f3fd12` | feat(eval): logtriage ablate with cache-only replay, own outputs and own memory |
| `7dd31b4becc1` | `a18c0bb0d78e` | fix(eval): keep the ablation ledger file out of the report glob |
| `98ce31714af7` | `235592cffbdb` | chore(eval): base replay at 0 cost, verifier0 failed, session stopped |
| `4c30376ac980` | `bf9df67e9f06` | feat(agents): D69 retry rule, empty responses sent again, full tracebacks |
| `2a59f548c5d3` | `b152553978c7` | chore(eval): base replay exact after the llm.py fix, 24 of 24 hits |
| `66513ca6f182` | `d7dd67debd9a` | feat(eval): LLM-only baseline: draw, prompt, runner and metrics |
| `e13b4b896198` | `4e177fe1f1da` | chore(eval): ablations verifier0 (retry), rag0, few_shot1 on santos, once each |
| `b2bda0ae7b2b` | `b26e49d95108` | chore(eval): LLM-only sample keys, drawn with seed 42, before any call |
| `6890ef76d5b8` | `cafffc278038` | chore(eval): LLM-only output format checked on 2 dev windows |
| `90e265136878` | `2e4a79dec95d` | chore(eval): LLM-only baseline on 40 santos windows, once |
| `48abe0ac21b4` | `2893e040aade` | feat(eval): auto faithfulness and blind claims sheet, rubric before any rating |
| `5710e98fffce` | `d9a6d6f13657` | feat(eval): evaluate command and results.md generator, cache-only, ledger compared |
| `ee896069236c` | `75f55fad1af1` | chore(eval): labels of the two independent raters, as written |
| `4762d040d1c4` | `4235356bf21a` | feat(eval): M11 results: evaluate outputs, notebook 05, results.md, status |
| `294c94aa1df4` | `6325450e4ba9` | test: new tests use the UTC connection helper; status test count |
| `ab21d4bcd93b` | `676175276809` | merge: M11 Evaluation |
| `247790b5facc` | `6ec3cad7dcec` | fix(eval): rate faithfulness against the full Evidence of each cited line (D71) |
| `eb95454cb3b6` | `2a5ece81988c` | chore(eval): full-Evidence claims sheet and rubric, before any rating (D71) |
| `a755a1f8b75e` | `1c619939b6bb` | chore(eval): labels of the two fresh independent raters on the full-Evidence sheet (D71) |
| `863bff44d993` | `f593f2f3ed7b` | feat(eval): results.md section 6 with the corrected reading, D59 line, one Windows heading (D71) |
| `c395322a434f` | `a1c10f0d97d6` | docs(status): D71, corrected AI-annotated faithfulness readings |
| `3e7ad33dd2d9` | `2a2f2e060417` | merge: M11 fix, faithfulness against the full Evidence (D71) |
| `0c4efc685412` | `b06583f7b9b6` | fix(notebooks): 03 reads saved santos results instead of refitting (D72) |
| `c50e6a5c83da` | `cef2c272e5ac` | docs(notebooks): execute 01-05 from fresh kernels with saved outputs |
| `fb694ac4afe3` | `e6ab3b5c1f34` | docs(app): AI browser check screenshots of the dashboard on the test testbeds (D68) |
| `1812810cc344` | `43b3be74c020` | test(data): the prepare rerun check skips santos (D73) |
| `47ab2341acda` | `68e5f76ceac8` | docs(readme): complete README for v1.0 |
| `3a1f43da6b10` | `304332cd1b21` | docs(status): M13 complete, project complete, v1.0 |
| `e8ca2f7e3eef` | `f16b29211e03` | merge: M13 Finalize |
| `aed46f66cbce` | `e4cfbf9f5d37` | docs(plan): redefine M12 as v2 detection improvement, measured once on shaw (D74) |
| `a97fa6d6f5f8` | `112446f02acd` | docs(v2): dev diagnosis and pre-declared v2 plan, before any candidate is measured |
| `ea913750663b` | `1b33591374e4` | docs(status): M12 v2 session 1, diagnosis and plan |
| `d5886c2a76ba` | `82aabe8160f8` | docs(v2): log D75-D77, wheeler joins shaw as second unseen testbed |
| `e5143a886f69` | `87eea2a2bdbe` | feat(ml): v2 candidates (a), (b), (d) behind configs/v2.yaml |
| `87b6f607e59a` | `8900894863c9` | refactor(eval): v2 selection reads capable types from the feature report, so each configuration is scored once |
| `adeec52067f0` | `27de407cf8ef` | feat(v2): select on dev and freeze configs/v2.yaml (D78) |
| `746ebd0ee4e8` | `909ba32b1f5d` | docs(v2): log D79-D82, the user's decisions for session 3A |
| `2203a104154a` | `272ea4ba4e51` | fix(data): keep optional window features out of the agent tables (D79) |
| `21f635962385` | `a2af50f909ba` | feat(guards): shaw joins the test testbeds; prepare runs once per test testbed (D83, D84) |
| `80796a67de6f` | `31c81c50759a` | docs(v2): fox replaces wheeler as the second unseen testbed (D85) |
| `8255008fcb55` | `a0f2ad7d0084` | feat(eval): targets file of an unseen M12 testbed, from counts only |
| `4a85ce7a197e` † | `354d48073cf1` | feat(eval): freeze the shaw targets before any detection (D84) |
| `ebf9b37af005` † | `b3e41241f337` | feat(eval): freeze the fox targets before any detection (D85) |
| `f35ec1f6c163` † | `83f81d75ff06` | docs(status): v2 session 3A done, shaw and fox frozen; next 3B after the user's go |
| `843c21e778db` † | `08ea2ce6cdd9` | feat(ml): v2 detect mode apart from v1, ledger mode/commit/config hashes; log D86-D88 |
| `5008628ed581` † | `1d9aa912fa86` | feat(eval): v1 and v2 detection once on shaw and fox; v2 reading and cost re-estimate |
| `e0186e38994a` † | `6f361b0c4618` | feat(agents): v2 investigate apart from v1, M11 fingerprint stop on M12 testbeds; log D89-D90 |
| `4f00bc5287eb` † | `dabc7403a2a5` | feat(agents): v1 and v2 investigate once on shaw and fox (59 reports, 0.7353 USD at peak) |
| `c30854868542` † | `0ddd42222e06` | docs(status): log D91-D92, scope of the v2 evaluation, before any evaluation |
| `01d02774e068` † | `c85c2dfd941f` | feat(eval): results_v2.md, v1 against v2 on shaw and fox; README v2 section, release notes draft; log D93 |
| `5383f2c1a68a` † | `ac52644bbac6` | docs(v2): agent metrics and the IDS baseline in README and release notes; log D94 |
| `da33db4d1ace` | `cb673904fc21` | merge: M12 v2, opt-in detection mode measured on shaw and fox |
| `16ec00ab620b` † | `b4c514c8afd5` | docs(status): M12 done, project complete; optional items and manual steps |
