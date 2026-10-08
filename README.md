# YADDA

*Yet Another Detection Dashboard, Apparently.* This one checks whether the logs arrive.

YADDA reads the YARA-L rules deployed in a Google SecOps instance, plus a few exports from the same instance, and
reports what the SIEM can detect against MITRE ATT&CK: which telemetry arrives, which techniques have a working
rule, which could have one with the data already there, and what to fix first. It runs on a laptop, needs read
access to SecOps only, and works for one environment or many.

![Overview tab of the dashboard](docs/images/overview.png)

Most coverage tools count rules per technique. That number says little: a rule tagged T1003 is no use if it has
never fired, if it watches Linux logs while the technique matters on Windows, or if the logs it needs never
arrive. `yadda` checks each technique against MITRE's own detection analytics (ATT&CK v18 and later), per platform,
using the telemetry that the SIEM actually holds and the evidence that each rule fires.

To try it without a SecOps instance, run it on the fictional sample environment:

```
yadda setup
yadda run example
```

The dashboard opens from `output/example/latest/1_example_dashboard.html`.

Setting up a real environment, including a separate Google account for each one, is covered step by step in
[docs/setup.md](docs/setup.md).

## What you get

Each run writes a dated folder under `output/<environment>/`:

| File | Contents |
|---|---|
| `1_<env>_dashboard.html` | Tabs for Overview, Next actions, Telemetry, ATT&CK, Threats and Rules |
| `2_<env>_coverage.xlsx` | Every table, one sheet each, with a "Read me" sheet |
| `3_navigator_layers/` | Layers for [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/): detection state, threat groups, `yadda check` results |
| `4_sigma_candidates/` | SigmaHQ rules converted to YARA-L for techniques that have the data but no rule |
| `data/` | The same tables as CSV |

`output/<environment>/latest/` is a copy of the newest run, and older runs stay as a history.

![Telemetry tab](docs/images/telemetry.png)

![ATT&CK matrix coloured by detection state](docs/images/attack.png)

## Commands

```
yadda run <environment> [-step ...] [--ask]          every step and every output
yadda check <environment> <T-ids | group | software | --threats> [--layer]
yadda score <environment> <T-id> <-1..5> "<evidence>"   record a score by hand, e.g. 4 after a lab test
yadda test <environment> <guid | T1053.005#2> fired|missed|n/a|clear
yadda actors --sector S --country C --environment E --set|--add
yadda new <environment>
yadda import <environment> <folder | files | git URL>
yadda status
yadda setup [--latest | --check]
```

`yadda help <command>` prints examples.

`yadda run` has these steps, in order: **pull** (the deployed rules, through Google's
[Content Manager](https://github.com/chronicle/detection-rules/tree/main/tools/content_manager)), **queries** (the
SecOps exports, through the API), **data**, **evidence**, **robustness**, **review**, **atomics** and **sigma**. Skip a
step with `-<step>`, for example `yadda run acme -sigma -atomics`. A step that fails is reported and the others still
run. Output from every step goes to `run_log.txt` in the run folder.

Without API access, `yadda` uses the rules already in the environment's `rules/` folder (or loaded with `yadda import`) and
the query results you export by hand into `inputs/`.

## How a technique is judged

ATT&CK gives each technique a detection strategy with one analytic per platform, and each analytic lists the data
it needs (a data component, plus the log source MITRE has in mind). `yadda` calls each analytic a route. A route's
input counts as present only when a log type from the same platform delivers it, so Windows logon events never
stand in for Microsoft 365 sign-ins. Log types are assigned to platforms in `shared/log_type_platforms.csv`;
`yadda run <environment> --ask` asks you about any log type the table doesn't know and saves the answer for every
environment.

Two kinds of log type do not make a platform "seen". Alert feeds from security products (CS_ALERTS,
MICROSOFT_GRAPH_ALERT, GuardDuty) report what a product detected, not what happened on the host; their
ATT&CK-tagged alerts are shown separately as product detections. Network sensors (firewalls, proxies, DNS) supply
network inputs on every platform but do not prove that a platform's own logs arrive.

Each in-scope technique gets one state:

| State | Meaning |
|---|---|
| Validated | Score 4-5: a test proved it |
| Detected | Score 3: a rule fired within EVIDENCE_DAYS and isn't noisy |
| Limited | Score 2: the rule fires but is noisy or narrow |
| Unverified | Score 1: a rule is deployed, with no evidence yet |
| Scored by hand, no rule | A score you recorded with no SIEM rule behind it; shown, not counted |
| Data, no rule | Every input of a route arrives, so a rule could be written now |
| Some data | Some of a route's inputs arrive |
| No data seen | The platform's logs arrive, but none of the route's inputs |
| Platform not seen | No log type for the route's platform is in the SIEM |
| Can't tell | No telemetry export yet, or MITRE gives no route on these platforms |

Scores 1-3 come from the evidence step, which reads the rule health and false-positive exports: a rule that fired
within the window scores 3, one with more than FP_MAX % non-malicious closed cases (over at least MIN_CASES cases)
scores 2, and anything else stays at 1. Scores 4 and 5 are only set by hand. The scale is in
[shared/score_definitions.md](shared/score_definitions.md).

A rule counts only on the platforms its log types belong to: a rule on SaaS audit logs tagged with a technique does
not make that technique detected on Windows. Such techniques are shown as "Detected, not on this platform".

**Next actions** turns the gaps into a ranked list: telemetry that would complete the most routes (for example
"Enable WINEVTLOG event 4663" or "Onboard Sysmon"), rules that are broken or noisy, rules to write where the data
already arrives, and detections to prove with Atomic Red Team.

## Threats

`yadda actors --sector finance --country Germany --environment acme --set` picks ATT&CK groups that target that
sector and country (from the [MISP galaxy](https://github.com/MISP/misp-galaxy)) and writes them to `THREATS=` in
`environment.env`. The Threats tab then shows:

- the techniques those groups use, ranked by how many groups use them, with each one's state;
- their software and campaigns, with ATT&CK's procedure examples;
- published intrusions from the [Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow)
  corpus as ordered steps, with the first step at which each would be detected;
- techniques the groups probably also use, from the
  [Technique Inference Engine](https://github.com/center-for-threat-informed-defense/technique-inference-engine).
  These are labelled "inferred" and never counted in coverage.

![Threats tab](docs/images/threats.png)

## Other checks

**Robustness.** MITRE's [Detection Coverage Calculator](https://github.com/center-for-threat-informed-defense/summiting-the-pyramid)
scores how hard each rule is to evade. `yadda` translates YARA-L into the Sigma form the calculator reads (UDM to OCSF
through `shared/udm_to_ocsf.csv`). The calculator only scores Windows Event Log and Sysmon fields.

**Sigma candidates.** For techniques with data but no rule, `yadda` converts matching
[SigmaHQ](https://github.com/SigmaHQ/sigma) rules with
[pySigma-backend-secops](https://github.com/AttackIQ/pySigma-backend-secops), keeping only rules whose events the
environment sends. It corrects a few conversion errors (lost `not` over groups, lost anchors on value lists, doubled
regex backslashes) and skips rules that use fields with no UDM equivalent. Candidates are not counted until you
deploy them.

**Rule review.** Rules that never fired, fire too often, carry no ATT&CK tag or are tagged with many techniques are
listed in `rule_review.csv`. Your decisions in that file are kept between runs.

**Validation.** The atomics step lists [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests for
detected techniques. Record results with `yadda test`.

## Scores file

Detection scores and their dated history are kept in each environment's `techniques.yaml`, in
[DeTT&CT](https://github.com/rabobank-cdc/DeTTECT)'s technique-administration format, so the file also opens in
DeTT&CT. DeTT&CT itself is not needed.

## Folder layout

```
environments/
  _template/            copied by "yadda new"
  example/              fictional sample environment
  <name>/
    environment.env     SecOps instance, Google login, PLATFORMS=, THREATS=, thresholds
    inputs/             SecOps exports (any file name; the newest of each kind is used)
    rules/              deployed rules, from pull or import
    rule_config.yaml    which rules are enabled
    rule_review.csv     your review decisions
    validation.csv      Atomic Red Team results
    techniques.yaml     detection scores with history
shared/
  log_type_platforms.csv                 log type -> ATT&CK platform
  udm_event_type_to_data_component.csv   UDM event type -> ATT&CK data component
  queries/                               the SecOps queries behind the exports
output/<name>/<date>/                    results
```

Real environments are ignored by git (see `.gitignore`); only `_template` and `example` are tracked.

## Tests

```
.venv/bin/python -m pip install -r requirements-dev.txt      (Windows: .venv\Scripts\python)
.venv/bin/python -m pytest tests
```

`tests/fixtures/acme` is a small fictional environment whose rules each cover an edge case. `test_golden.py` runs
the whole pipeline on it and compares the outputs with `tests/golden/acme`. After an intended change, run
`python tests/characterize.py`, review the diff, then run it again with `--update`.

The SecOps API calls are tested against a mock built from Google's published API, not against a live instance.

## License

MIT, see [LICENSE](LICENSE). Data and tools fetched by `yadda setup` keep their own licenses; converted Sigma rules keep
their author, id and path, as the Detection Rule License requires.
