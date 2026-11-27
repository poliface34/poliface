"""Stage 2 AnswerTemporalValidator enforcing non-retroactivity & historical isolation (WP-4.4)."""

from __future__ import annotations

from datetime import date
from typing import Any

from ..rag.models import RankedEvidenceItem, RetrievalTraceBundle
from ..source_validator import parse_iso_date
from .models import TemporalValidationReport

# Explicit statutory cutoff floors preventing retroactive application to earlier historical events
_SOURCE_CUTOFF_FLOOR: dict[str, str] = {
    "RG-7555-20250724": "2025-07-24",
    "RG-7566-20251219": "2026-01-01",
    "RG-10766-20251225": "2026-01-01",
    "SGK-PEK-2026-UYGULAMA": "2026-01-01",
    "SGK-TESVIK-2026-1-REHBER": "2026-01-01",
    "DV-MEVZUAT-6698-V2-POST7499": "2024-06-01",
    "DV-RG-7555-20250724": "2025-07-24",
    "DV-RG-7566-20251219": "2026-01-01",
}


class AnswerTemporalValidator:
    """Validates `as_of_date`, blocks retroactive statutes, and isolates historical/future items."""

    def __init__(self, *, source_registry: dict[str, Any] | None = None) -> None:
        self._sources = source_registry or {}

    def validate(
        self,
        trace_bundle: RetrievalTraceBundle,
        *,
        source_registry: dict[str, Any] | None = None,
    ) -> TemporalValidationReport:
        sources = source_registry if source_registry is not None else self._sources
        as_of_date = trace_bundle.as_of_date
        target_dt = parse_iso_date(as_of_date) if as_of_date else None
        if (
            not trace_bundle.temporal_audit.date_valid
            or not as_of_date
            or target_dt is None
        ):
            return TemporalValidationReport(
                as_of_date=as_of_date,
                date_valid=False,
                historical_context_items=trace_bundle.historical_context_bucket,
                temporal_flags=tuple(trace_bundle.temporal_audit.cutoff_flags),
                error_code=trace_bundle.temporal_audit.error_code or "TEMPORAL_ABSTAIN_MISSING_DATE",
            )

        temporal_flags: list[str] = list(trace_bundle.temporal_audit.cutoff_flags)
        rejected_retroactive: list[dict[str, Any]] = []
        historical_items: list[RankedEvidenceItem] = list(trace_bundle.historical_context_bucket)

        def _validate_active_bucket(items: tuple[RankedEvidenceItem, ...], bucket_label: str) -> tuple[RankedEvidenceItem, ...]:
            kept: list[RankedEvidenceItem] = []
            for item in items:
                ch = item.chunk
                eff_from = parse_iso_date(ch.effective_from)
                eff_to = parse_iso_date(ch.effective_to) if ch.effective_to else date(2999, 12, 31)

                src_rec = sources.get(ch.source_id)
                src_eff_to = (
                    parse_iso_date(src_rec.effective_to)
                    if src_rec is not None and getattr(src_rec, "effective_to", None)
                    else None
                )
                src_expired = src_eff_to is not None and target_dt > src_eff_to

                # Explicit hard cutoff floor check against source_id and document_version_id
                floor_str = _SOURCE_CUTOFF_FLOOR.get(ch.document_version_id) or _SOURCE_CUTOFF_FLOOR.get(ch.source_id)
                floor_dt = parse_iso_date(floor_str) if floor_str else None
                cutoff_violated = floor_dt is not None and target_dt < floor_dt

                is_future_item = cutoff_violated or (eff_from is not None and target_dt < eff_from)
                is_past_expired = (eff_to is not None and target_dt > eff_to) or src_expired

                if eff_from is None or eff_to is None or is_future_item or is_past_expired:
                    rejected_retroactive.append(
                        {
                            "bucket": bucket_label,
                            "chunk_id": ch.chunk_id,
                            "provision_id": ch.provision_id,
                            "source_id": ch.source_id,
                            "document_version_id": ch.document_version_id,
                            "effective_from": ch.effective_from,
                            "effective_to": ch.effective_to,
                            "as_of_date": as_of_date,
                            "reason": "EXPIRED_OR_SUPERSEDED_SOURCE_EXCLUDED" if is_past_expired else "TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED",
                        }
                    )
                    if "TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED" not in temporal_flags:
                        temporal_flags.append("TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED")
                    # Preserve ONLY expired/superseded historical items in historical context — NEVER future laws!
                    if is_past_expired and not is_future_item and item not in historical_items:
                        historical_items.append(item)
                    continue

                kept.append(item)
            return tuple(kept)

        active_norm = _validate_active_bucket(trace_bundle.normative_bucket, "NORMATIVE")
        active_interp = _validate_active_bucket(trace_bundle.interpretation_bucket, "INTERPRETATION_BOUNDARY")
        active_auto = _validate_active_bucket(trace_bundle.autonomous_norm_bucket, "AUTONOMOUS_NORM")

        # Validate precedents against event date (future precedent decisions cannot apply retroactively as settled law at event date)
        validated_precs: list[RankedEvidenceItem] = []
        for item in trace_bundle.precedent_bucket:
            ch = item.chunk
            dec_dt = parse_iso_date(ch.effective_from)
            if dec_dt is not None and target_dt < dec_dt:
                temporal_flags.append(f"FUTURE_PRECEDENT_NOT_YET_DECIDED_ON_AS_OF_DATE:{ch.source_id}")
                rejected_retroactive.append(
                    {
                        "bucket": "PRECEDENT",
                        "chunk_id": ch.chunk_id,
                        "provision_id": ch.provision_id,
                        "source_id": ch.source_id,
                        "decision_date": ch.effective_from,
                        "as_of_date": as_of_date,
                        "reason": "FUTURE_PRECEDENT_CANNOT_APPLY_RETROACTIVELY_AS_SETTLED",
                    }
                )
                continue

            post_status = str((item.precedent_metadata or {}).get("post_decision_amendment_status") or "UNAFFECTED")
            if post_status != "UNAFFECTED":
                temporal_flags.append(f"PRECEDENT_POST_DECISION_STATUTORY_AMENDMENT:{ch.source_id}")
            validated_precs.append(item)

        if historical_items and "HISTORICAL_CONTEXT_SEPARATED" not in temporal_flags:
            temporal_flags.append("HISTORICAL_CONTEXT_SEPARATED")

        return TemporalValidationReport(
            as_of_date=as_of_date,
            date_valid=True,
            active_normative_items=active_norm,
            active_interpretation_items=active_interp,
            active_autonomous_items=active_auto,
            validated_precedent_items=tuple(validated_precs),
            historical_context_items=tuple(historical_items),
            rejected_retroactive_items=tuple(rejected_retroactive),
            temporal_flags=tuple(dict.fromkeys(temporal_flags)),
            error_code=None,
        )
