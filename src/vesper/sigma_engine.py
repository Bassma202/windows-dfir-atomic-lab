"""Genuine pySigma YAML validation, Splunk SPL & Elastic Lucene compilation, and local detection evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.rule import SigmaRule


@dataclass
class CompiledSigmaRule:
    rule_id: str
    title: str
    level: str
    status: str
    mitre_tags: list[str]
    source_file: str
    splunk_spl: str
    elastic_lucene: str
    raw_detection: dict[str, Any]
    logsource: dict[str, Any]


def load_and_compile_sigma_rules(rules_dir: Path) -> list[CompiledSigmaRule]:
    """Validate Sigma YAML files via pySigma and compile them using official Splunk and Elastic backends."""
    splunk_backend = SplunkBackend(processing_pipeline=splunk_windows_pipeline())
    elastic_backend = LuceneBackend(processing_pipeline=ecs_windows())

    compiled: list[CompiledSigmaRule] = []
    for yml_path in sorted(rules_dir.glob("*.yml")):
        raw_text = yml_path.read_text(encoding="utf-8")
        # Strict pySigma schema parsing (raises SigmaError on invalid YAML/structure)
        rule = SigmaRule.from_yaml(raw_text)
        collection = SigmaCollection([rule])
        spl_queries = splunk_backend.convert(collection)
        es_queries = elastic_backend.convert(collection)
        raw_dict = yaml.safe_load(raw_text)

        compiled.append(
            CompiledSigmaRule(
                rule_id=str(rule.id),
                title=rule.title,
                level=str(rule.level.name).lower() if rule.level else "medium",
                status=str(rule.status.name).lower() if rule.status else "test",
                mitre_tags=[str(t) for t in rule.tags],
                source_file=yml_path.name,
                splunk_spl=spl_queries[0] if spl_queries else "",
                elastic_lucene=es_queries[0] if es_queries else "",
                raw_detection=raw_dict.get("detection", {}),
                logsource=raw_dict.get("logsource", {}),
            )
        )
    return compiled


def _match_field_spec(event: dict[str, Any], field_spec: str, expected: Any) -> bool:
    parts = field_spec.split("|")
    field_name = parts[0]
    modifiers = set(parts[1:])
    val = event.get(field_name)
    if val is None or val == "":
        return False

    if isinstance(expected, int):
        try:
            return int(val) == expected
        except (TypeError, ValueError):
            return False

    val_str = str(val).lower()
    expected_list = expected if isinstance(expected, list) else [expected]
    expected_lower = [str(e).lower() for e in expected_list]

    def _single_match(needle: str) -> bool:
        if "endswith" in modifiers:
            return val_str.endswith(needle)
        if "startswith" in modifiers:
            return val_str.startswith(needle)
        if "contains" in modifiers:
            return needle in val_str
        return val_str == needle

    if "all" in modifiers:
        return all(_single_match(n) for n in expected_lower)
    return any(_single_match(n) for n in expected_lower)


def _match_selection(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    return all(_match_field_spec(event, f_spec, exp) for f_spec, exp in selection.items())


def evaluate_sigma_rule_on_event(rule: CompiledSigmaRule, event: dict[str, Any]) -> bool:
    """Evaluate a compiled Sigma rule's detection block against a normalized Windows telemetry event."""
    det = rule.raw_detection
    condition = str(det.get("condition", "selection")).strip()
    selections = {k: v for k, v in det.items() if k != "condition" and isinstance(v, dict)}

    if condition in selections:
        return _match_selection(event, selections[condition])
    if " and " in condition:
        parts = [p.strip() for p in condition.split(" and ")]
        return all(_match_selection(event, selections[p]) for p in parts if p in selections)
    if " or " in condition:
        parts = [p.strip() for p in condition.split(" or ")]
        return any(_match_selection(event, selections[p]) for p in parts if p in selections)
    return False


def scan_events_with_sigma(rules: list[CompiledSigmaRule], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for ev in events:
        for rule in rules:
            if evaluate_sigma_rule_on_event(rule, ev):
                alerts.append(
                    {
                        "timestamp": ev.get("Timestamp", ""),
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "level": rule.level,
                        "mitre_tags": rule.mitre_tags,
                        "computer": ev.get("Computer", "UNKNOWN"),
                        "user": ev.get("User", "UNKNOWN"),
                        "image": ev.get("Image", ""),
                        "command_line": ev.get("CommandLine", ""),
                        "target_object": ev.get("TargetObject", ""),
                        "source_rule_file": rule.source_file,
                    }
                )
    return alerts
