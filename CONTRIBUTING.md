# Contributing

Thanks for your interest. Issues and pull requests are welcome.

## Development setup

```bash
./scripts/setup.sh            # macOS / Linux
scripts\setup.ps1             # Windows (PowerShell)
python -m capstone doctor     # check the environment at any time
```

Use `--skip-models` / `-SkipModels` if you only need to run the tests: they make no model calls.

## Before opening a pull request

```bash
python -m unittest discover -s tests -v
python -m capstone --org demo-corp org validate
python -m capstone --org harbor-valley-health org validate
```

All tests must pass and both example org packs must validate with 0 errors.

## Ground rules

These keep the system safe. Pull requests that break them will not be merged.

1. **The model proposes, code decides.** Dispositions, severities and action plans are computed in code from model output plus policy. Never wire model output straight to an action.
2. **Guardrails only add caution.** A guardrail may force escalation or block auto-close; it must never close, downgrade, or skip the approval gate.
3. **People-reaching actions are always gated.** Paging, stakeholder and external notification actions go through `orchestrator.approve()`. No configuration option may change that.
4. **Organization-specific values belong in org packs**, not in `capstone/`. If you find yourself writing a hostname, a person, a vendor field name or a threshold in engine code, it probably belongs in `orgs/<id>/`.
5. **Alert text is untrusted.** Anything derived from an alert is escaped in the UI and never treated as instructions.
6. **Every decision is audited** with a rationale (`state.audit`).
7. **Add a test** for any new guardrail, policy condition, mapping feature or API endpoint.

## Good first contributions

- A source mapping for another SIEM/EDR (`orgs/<id>/sources/*.json`) with a sample payload
- A new actuator type (for example a ticketing system) in `capstone/connectors/actuators.py`
- A sliding-window dedup instead of the calendar-day window
- An ML-based prompt-injection classifier alongside the pattern detector

## Project layout

See the repository map in [README.md](README.md) and the component guide in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
