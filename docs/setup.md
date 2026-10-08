# Setup

This guide starts from a laptop with nothing installed and ends with `yadda run` working against one or more SecOps
instances. Steps 1 to 3 are done once per laptop; steps 4 to 8 are repeated for each environment.

An environment is one Google SecOps instance: your own organisation's, a business unit's, or one you look after for
someone else. Each one gets a folder under `environments/` with its own settings, rules, exports and scores.

## 1. Install the prerequisites

`yadda` needs Git, the Google Cloud CLI (for signing in) and Python 3.12. Python 3.12 is required because Google's
Content Manager pins packages that do not install on newer versions. The simplest way to get it is
[uv](https://docs.astral.sh/uv/), which `yadda setup` uses to fetch a private copy without touching any other Python
on the machine.

Windows (cmd or PowerShell):

```
winget install -e --id Git.Git
winget install -e --id Google.CloudSDK
winget install -e --id astral-sh.uv
git config --global core.longpaths true
```

The last line lets Git write the long file paths in some of the tools `yadda setup` downloads.

macOS:

```
brew install git uv
brew install --cask google-cloud-sdk
```

Linux: install Git from your package manager, uv with `curl -LsSf https://astral.sh/uv/install.sh | sh`, and the
Google Cloud CLI from [Google's instructions](https://cloud.google.com/sdk/docs/install).

Open a new terminal afterwards so the new commands are on your PATH.

## 2. Get yadda and install its tools

```
git clone https://github.com/<you>/yadda.git
cd yadda
yadda setup                (macOS and Linux: ./yadda setup)
```

`yadda setup` creates a Python 3.12 virtual environment in `.venv/` and downloads the pinned versions of the tools and
data it uses (ATT&CK, SigmaHQ, Atomic Red Team, the MISP galaxy, Attack Flow, the Technique Inference Engine, the
Detection Coverage Calculator and Content Manager) into `tools/`. Versions are pinned in `tools.lock` and
`requirements.lock`, so running it again only fetches what is missing. Expect the first run to take a few minutes.

Add the folder to your PATH so `yadda` works from anywhere. On Windows, add it under *Edit environment variables for
your account*. On macOS and Linux, link the launcher into a folder already on your PATH:

```
ln -s "$PWD/yadda" ~/.local/bin/yadda
```

Check the install, then run the sample environment:

```
yadda doctor
yadda run example
```

Open `output/example/latest/1_example_dashboard.html` in a browser. If that works, everything except SecOps access
is in place.

## 3. Sign in to Google with your default account

If one Google account can reach every SecOps instance you work with, sign in once:

```
gcloud auth application-default login
```

This writes Application Default Credentials, which `yadda` and Content Manager use for API calls. If you need a
separate account for some environments, do that in step 5 instead; you can mix both.

The account needs read access to the SecOps instance: listing rules and running dashboard queries. The predefined
IAM role **Chronicle API Viewer** (`roles/chronicle.viewer`) on the instance's Google Cloud project is usually
enough. `yadda` never creates, changes or deletes anything in SecOps.

## 4. Create the environment

```
yadda new acme
```

This copies `environments/_template` to `environments/acme`. Use a short name without spaces; it appears in file
and folder names. `yadda go acme` moves to that folder in a Windows command prompt; on macOS and Linux use `cd "$(yadda go acme)"`.

Open `environments/acme/environment.env` and fill in the SecOps instance. In SecOps, go to
**Settings > SIEM Settings > Profile**, which shows the Google Cloud project, the region and the Customer ID (the
instance ID). Then set:

```
GOOGLE_SECOPS_API_BASE_URL=https://<region>-chronicle.googleapis.com/v1alpha
GOOGLE_SECOPS_API_UPLOAD_BASE_URL=https://<region>-chronicle.googleapis.com/upload/v1alpha
GOOGLE_SECOPS_INSTANCE=projects/<project id>/locations/<region>/instances/<customer id>
```

`<region>` is the instance's location, for example `us`, `eu` or `europe-west2`. If you have no API access at all,
leave these lines as they are and use the manual route in step 6.

## 5. Use a different Google account for this environment (optional)

Skip this step if your default sign-in from step 3 can reach this instance.

gcloud keeps its sign-in in a configuration folder. Pointing `CLOUDSDK_CONFIG` at a new folder gives you a separate
sign-in that does not touch your default one. Sign in once per environment.

Windows (cmd):

```
set CLOUDSDK_CONFIG=%USERPROFILE%\.gcloud-acme
gcloud auth application-default login
gcloud auth application-default set-quota-project <project id>
set CLOUDSDK_CONFIG=
```

macOS and Linux:

```
CLOUDSDK_CONFIG=~/.gcloud-acme gcloud auth application-default login
CLOUDSDK_CONFIG=~/.gcloud-acme gcloud auth application-default set-quota-project <project id>
```

The browser opens for sign-in; choose the account that has access to this instance. The credentials end up in
`application_default_credentials.json` inside that folder. Tell `yadda` to use them by adding this line to
`environments/acme/environment.env`:

```
GOOGLE_APPLICATION_CREDENTIALS=%USERPROFILE%\.gcloud-acme\application_default_credentials.json
```

or, on macOS and Linux:

```
GOOGLE_APPLICATION_CREDENTIALS=~/.gcloud-acme/application_default_credentials.json
```

`yadda` expands `%VARS%` and `~` on every operating system, so either form works. The setting applies only to this
environment; others keep using your default sign-in. If the login expires, run the same `login` command again.

## 6. Get the rules and exports

**With API access**, there is nothing to do here: `yadda run` pulls the deployed rules and runs the six queries in
`shared/queries/` itself.

**Without API access**, load the rules and export the queries by hand:

1. Load the rules from a folder of `.yaral` files or from a git repository you can clone:
   ```
   yadda import acme path/to/rules
   yadda import acme https://github.com/<org>/<repo>/tree/main/rules
   ```
2. In SecOps, open **Dashboards**, create a dashboard and add one chart per query in `shared/queries/`. Paste each
   query, set the time range from the table below, and export the result as CSV.
3. Save the CSV files in `environments/acme/inputs/`. File names don't matter: `yadda` recognises each export by its
   columns and uses the newest of each kind.

The exports are:

| Query | Time range | What it gives |
|---|---|---|
| `telemetry_inventory.yaral` | 7 days | Log types, event types and volumes: what the SIEM receives |
| `rule_health.yaral` | the maximum | When each rule last fired |
| `rule_fp_rate.yaral` | 1 year | Closed cases per rule and verdict |
| `rule_logtypes.yaral` | 90 days | Which log types each rule fired on |
| `log_type_host_os.yaral` | 7 days | Which operating systems each log type reports |
| `product_alerts.yaral` | 30 days | ATT&CK-tagged alerts from security products |

Only the telemetry inventory is essential. Without the others, the states that depend on them show as "Can't tell"
or "Unverified".

## 7. Set the scope and threats

In `environment.env`, list the ATT&CK platforms the environment has. Techniques on other platforms are left out:

```
PLATFORMS=Windows,Linux,Identity Provider,Office Suite,SaaS
```

The options are Windows, Linux, macOS, Identity Provider, Office Suite, SaaS, IaaS, Network Devices, Containers
and ESXi. If `PLATFORMS=` is not set, every platform is assessed and the run prints a warning.

Then choose the threat groups to measure against:

```
yadda actors --list
yadda actors --sector finance --country Germany --environment acme --set
```

`--set` replaces `THREATS=`, `--add` merges with it, and the previous file is backed up first. You can also edit
`THREATS=` by hand with ATT&CK group, software or campaign names or IDs, or the name of a file in
`shared/threat-intel/`.

## 8. Run it

```
yadda run acme
```

If the environment sends log types that `shared/log_type_platforms.csv` doesn't know, the run lists them with the
event types they carry; until they are placed they count for nothing. Run `yadda run acme --ask` to assign each one to
an ATT&CK platform. The answers are saved in the shared table and apply to every environment from then on.

Steps you don't need can be skipped, for example `yadda run acme -atomics -sigma`. Results are in
`output/acme/<date>/`, and `output/acme/latest/` always holds the newest run.

To add another environment, repeat steps 4 to 8 with a new name. `yadda status` prints one line per environment.

## Keeping things up to date

`yadda setup --check` tests that the installed tools still behave the way `yadda` expects. `yadda setup --latest` tries the
newest version of every tool and data set and keeps them only if all the checks pass.

## Keeping environment data private

Everything under `environments/` except `_template` and `example` is ignored by git, as is `output/`. Rules,
exports, scores and results stay on your machine unless you copy them somewhere yourself.
