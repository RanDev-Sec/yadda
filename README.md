# YADDA

*Yet Another Detection Dashboard, Apparently.*

A command-line tool that measures MITRE ATT&CK detection coverage in Google SecOps. It reads your deployed YARA-L
rules and a few SecOps exports, and shows which telemetry arrives, which techniques have a working rule, which have
the data but no rule, and what to do next.

![Overview tab of the dashboard](docs/images/overview.png)

## Try it

The repository includes a fictional environment, so you can see the output without SecOps access:

```
yadda setup
yadda run example
```

Then open `output/example/latest/1_example_dashboard.html`. To set up a real environment, see
[docs/setup.md](docs/setup.md).

## What it does

- Checks each technique against MITRE's detection analytics, using the log types SecOps receives
- Scores rules from whether they fire and how noisy they are
- Lists next actions: telemetry to add, rules to fix, rules to write
- Maps threat groups for a sector or country and shows how much of their activity you'd detect
- Suggests SigmaHQ rules, converted to YARA-L, for gaps
- Writes a dashboard, an Excel workbook and ATT&CK Navigator layers

![Telemetry tab](docs/images/telemetry.png)

![ATT&CK matrix](docs/images/attack.png)

![Threats tab](docs/images/threats.png)

## Commands

```
yadda run <environment> [-step ...] [--ask]
yadda check <environment> <T-ids | group | software | --threats>
yadda score <environment> <T-id> <-1..5> "<evidence>"
yadda test <environment> <guid> fired|missed
yadda actors --sector S --country C --environment E --set
yadda new <environment>
yadda import <environment> <folder | git URL>
yadda status
yadda setup
```

`yadda help <command>` shows examples. Without API access, load rules with `yadda import` and put the query exports
in the environment's `inputs/` folder.

## Technique states

| State | Meaning |
|---|---|
| Validated | Proven by a test |
| Detected | A rule fired recently and isn't noisy |
| Limited | A rule fires but is noisy |
| Unverified | A rule is deployed, no evidence yet |
| Data, no rule | The data a rule needs arrives |
| Some data | Some of it arrives |
| No data seen | The platform's logs arrive, but not the data needed |
| Platform not seen | No logs from that platform |
| Can't tell | Not enough information |

## Tests

```
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests
```

## Built on

[MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data),
[Google SecOps Content Manager](https://github.com/chronicle/detection-rules/tree/main/tools/content_manager),
[Summiting the Pyramid](https://github.com/center-for-threat-informed-defense/summiting-the-pyramid),
[SigmaHQ](https://github.com/SigmaHQ/sigma),
[pySigma-backend-secops](https://github.com/AttackIQ/pySigma-backend-secops),
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team),
[MISP galaxy](https://github.com/MISP/misp-galaxy),
[Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow),
[Technique Inference Engine](https://github.com/center-for-threat-informed-defense/technique-inference-engine) and
[DeTT&CT](https://github.com/rabobank-cdc/DeTTECT)'s score format.

## License

MIT. Third-party rules and data keep their own licenses.
