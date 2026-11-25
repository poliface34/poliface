"""JSON Function-Calling dispatcher for hrAI @HukukSGK v1.0.5.1."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .autonomous_norms import (
    AutonomousNormModule,
    AutonomousNormRule,
    evaluate_autonomous_norm_conflict,
    load_l5_hr_procedures,
    load_l6_cba_contract_practices,
    lookup_autonomous_norm_guidance,
)
from .document_integrity import FetcherFn, verify_official_document
from .knowledge_card_validator import load_knowledge_cards, query_knowledge_cards
from .legal_reasoning import evaluate_hr_legal_scenario
from .models import LegalKnowledgeCard, LegalSourceRecord, NormReference, PrecedentRecord
from .norm_hierarchy import evaluate_precedent_application, resolve_norm_conflict
from .precedent_verifier import load_precedent_registry, verify_response_citations
from .source_validator import load_source_registry, resolve_effective_article, resolve_effective_sources
from .trust_chain import EvidenceBackedLegalAnswerBuilder, EvidenceRegistry

TOKEN_RE = re.compile(r"[a-zçğıöşü0-9]+", re.IGNORECASE)

TR_STOPWORDS: set[str] = {
    "ve",
    "veya",
    "ile",
    "bir",
    "bu",
    "da",
    "de",
    "için",
    "göre",
    "olan",
    "olarak",
    "ancak",
    "gibi",
    "hakkında",
    "ilişkin",
    "uyarınca",
    "gereğince",
    "sayılı",
    "kanun",
    "kanunu",
    "kanunun",
    "madde",
    "karar",
    "kararı",
    "kararları",
    "hüküm",
    "hükümleri",
    "süresi",
    "günü",
}

V1_1_PLANNED_TOOLS: set[str] = {
    "check_legal_deadline",
    "assess_termination_legality",
    "assess_sgk_compliance_and_ipc",
    "handoff_to_ucret_bordro",
}


def _tr_lower(text: str) -> str:
    return text.replace("İ", "i").replace("I", "ı").lower()


def _tokenize(text: str) -> set[str]:
    tokens = TOKEN_RE.findall(_tr_lower(text))
    return {
        tok
        for tok in tokens
        if (len(tok) >= 3 or (tok.isdigit() and len(tok) >= 2)) and tok not in TR_STOPWORDS
    }


class HukukSGKToolRouter:
    """Deterministic tool dispatcher backed by strictly validated L1-L4 official registries, L5/L6 autonomous norm templates, and provider-agnostic trust root registries."""

    def __init__(
        self,
        source_registry_path: str | Path | None = None,
        precedent_registry_path: str | Path | None = None,
        knowledge_base_dir: str | Path | None = None,
        audit_log_path: str | Path | None = None,
        document_fetcher: FetcherFn | None = None,
        *,
        approvers_registry_path: str | Path | None = None,
        attestation_ledger_path: str | Path | None = None,
        approvers_registry: dict[str, Any] | None = None,
        attestation_ledger: dict[str, Any] | None = None,
        autonomous_norms_audit_log_path: str | Path | None = None,
        runtime_environment: str = "PRODUCTION",
        require_signed_ledger_checkpoint: bool = True,
        expected_checkpoint_head_hash: str | None = None,
        expected_checkpoint_entry_count: int | None = None,
        expected_chain_digest_sha256: str | None = None,
        external_trust_anchor_provider: Any | None = None,
        expected_app_project_id: str | None = None,
        evidence_registry: EvidenceRegistry | None = None,
    ) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        src_path = Path(source_registry_path) if source_registry_path else base_dir / "config" / "legal_sources_registry.json"
        prec_path = Path(precedent_registry_path) if precedent_registry_path else base_dir / "config" / "yargitay_precedents.json"
        kb_dir = Path(knowledge_base_dir) if knowledge_base_dir else base_dir / "rag_kb"
        aud_path = Path(audit_log_path) if audit_log_path else base_dir / "config" / "verification_audit_log.json"
        appr_path = Path(approvers_registry_path) if approvers_registry_path else base_dir / "config" / "authorized_approvers.json"
        led_path = Path(attestation_ledger_path) if attestation_ledger_path else base_dir / "config" / "calendar_attestation_ledger.json"
        auto_aud_path = (
            Path(autonomous_norms_audit_log_path)
            if autonomous_norms_audit_log_path
            else base_dir / "config" / "autonomous_norms_audit_log.json"
        )

        self.project_root = base_dir
        self.sources: dict[str, LegalSourceRecord] = load_source_registry(src_path, strict=True)
        self.precedents: dict[str, PrecedentRecord] = load_precedent_registry(
            prec_path, source_registry=self.sources, strict=True
        )
        self.knowledge_cards: dict[str, LegalKnowledgeCard] = load_knowledge_cards(
            kb_dir,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            strict=True,
            audit_log_path=aud_path,
        )
        # L5/L6 autonomous norm layers are strictly isolated from the official L1-L4 core (74/74).
        # Loaded strictly whenever the L5/L6 folders exist under `kb_dir`.
        self.l5_hr_procedures: dict[str, AutonomousNormModule] = (
            load_l5_hr_procedures(kb_dir, self.sources, self.knowledge_cards, self.precedents, strict=True)
            if (kb_dir / "05_ik_prosedurleri").is_dir()
            else {}
        )
        self.l6_cba_contract_practices: dict[str, AutonomousNormModule] = (
            load_l6_cba_contract_practices(kb_dir, self.sources, self.knowledge_cards, self.precedents, strict=True)
            if (kb_dir / "06_tis_sozlesme_ve_isyeri_uygulamalari").is_dir()
            else {}
        )
        self._autonomous_rules_by_id: dict[str, AutonomousNormRule] = {}
        for mod in (*self.l5_hr_procedures.values(), *self.l6_cba_contract_practices.values()):
            for rule in mod.rules:
                self._autonomous_rules_by_id[rule.rule_id] = rule
        self.autonomous_norms_audit_log: dict[str, Any] | None = (
            json.loads(auto_aud_path.read_text(encoding="utf-8")) if auto_aud_path.is_file() else None
        )
        self.approvers_registry: dict[str, Any] | None = (
            approvers_registry
            if approvers_registry is not None
            else (json.loads(appr_path.read_text(encoding="utf-8")) if appr_path.is_file() else None)
        )
        self.attestation_ledger: dict[str, Any] | None = (
            attestation_ledger
            if attestation_ledger is not None
            else (json.loads(led_path.read_text(encoding="utf-8")) if led_path.is_file() else None)
        )
        self.runtime_environment = runtime_environment
        self.require_signed_ledger_checkpoint = require_signed_ledger_checkpoint
        self.expected_checkpoint_head_hash = expected_checkpoint_head_hash
        self.expected_checkpoint_entry_count = expected_checkpoint_entry_count
        self.expected_chain_digest_sha256 = expected_chain_digest_sha256
        self.external_trust_anchor_provider = external_trust_anchor_provider
        self.expected_app_project_id = expected_app_project_id
        self.document_fetcher = document_fetcher
        self.evidence_registry: EvidenceRegistry | None = evidence_registry

    def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "lookup_verified_source_and_precedent":
            return self._handle_lookup(arguments)
        if tool_name == "lookup_knowledge_card":
            return self._handle_lookup_knowledge_card(arguments)
        if tool_name == "lookup_autonomous_norm_guidance":
            return self._handle_lookup_autonomous_norm_guidance(arguments)
        if tool_name == "evaluate_autonomous_norm_conflict":
            return self._handle_evaluate_autonomous_norm_conflict(arguments)
        if tool_name == "check_article_effective_date":
            return self._handle_check_article_effective_date(arguments)
        if tool_name == "verify_document_integrity":
            return self._handle_verify_document_integrity(arguments)
        if tool_name == "verify_legal_citations":
            return self._handle_verify_citations(arguments)
        if tool_name == "resolve_norm_conflict":
            return self._handle_resolve_norm_conflict(arguments)
        if tool_name == "evaluate_precedent_application":
            return self._handle_evaluate_precedent_application(arguments)
        if tool_name == "evaluate_hr_legal_scenario":
            return self._handle_evaluate_hr_legal_scenario(arguments)
        if tool_name == "build_evidence_linked_answer":
            return self._handle_build_evidence_linked_answer(arguments)
        if tool_name == "escalate_to_legal_counsel":
            return self._handle_escalate(arguments)
        if tool_name in V1_1_PLANNED_TOOLS:
            return {
                "status": "NOT_IMPLEMENTED_IN_V1_0_2",
                "tool_name": tool_name,
                "message": (
                    f"'{tool_name}' aracı v1.1 deterministik süre/fesih/SGK İPC fazında eklenecektir. "
                    f"hrAI @HukukSGK v1.0.5.1 doğrulama güvenliği, L1–L4 resmî mevzuat çekirdeği, L5/L6 özerk norm katmanları ve 7 senaryolu hukuki muhakeme motorunu kapsar."
                ),
            }
        raise ValueError(f"Bilinmeyen araç adı: '{tool_name}'")

    def _handle_lookup(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).strip()
        as_of_date = str(args.get("as_of_date", "")).strip()
        layers = args.get("layers")
        include_superseded = bool(args.get("include_superseded", False))

        if not query or not as_of_date:
            raise ValueError("'query' ve 'as_of_date' zorunludur.")

        q_tokens = _tokenize(query)
        source_layers = [ly for ly in layers if ly != "YARGITAY_PRECEDENT"] if layers else None
        want_sources = layers is None or bool(source_layers)
        want_precedents = layers is None or "YARGITAY_PRECEDENT" in layers

        matched_sources: list[dict[str, Any]] = []
        superseded_sources: list[dict[str, Any]] = []

        if want_sources:
            resolved = resolve_effective_sources(
                self.sources,
                as_of_date=as_of_date,
                layers=source_layers,
                include_superseded=include_superseded,
            )
            scored_eff: list[tuple[int, LegalSourceRecord]] = []
            for src in resolved["effective_sources"]:
                haystack = " ".join(
                    [src.source_id, src.source_title, src.legal_reference, src.statute_number, *src.keywords]
                )
                score = len(q_tokens & _tokenize(haystack))
                if src.statute_number.lower() in _tr_lower(query):
                    score += 5
                if score > 0:
                    scored_eff.append((score, src))
            scored_eff.sort(key=lambda item: (-item[0], item[1].norm_priority, item[1].source_id))
            matched_sources = [src.to_dict() for _, src in scored_eff]

            if include_superseded:
                for src in resolved["inactive_or_superseded_sources"]:
                    haystack = " ".join(
                        [src.source_id, src.source_title, src.legal_reference, src.statute_number, *src.keywords]
                    )
                    if (q_tokens & _tokenize(haystack)) or src.statute_number.lower() in _tr_lower(query):
                        superseded_sources.append(src.to_dict())

        matched_precedents: list[dict[str, Any]] = []
        inactive_or_pending_precedents: list[dict[str, Any]] = []
        if want_precedents:
            scored_prec: list[tuple[int, PrecedentRecord]] = []
            scored_inactive_prec: list[tuple[int, PrecedentRecord]] = []
            for prec in self.precedents.values():
                haystack = " ".join(
                    [
                        prec.precedent_id,
                        prec.chamber,
                        prec.esas_no,
                        prec.karar_no,
                        prec.legal_principle,
                        prec.scope_limitations,
                        *prec.keywords,
                    ]
                )
                score = len(q_tokens & _tokenize(haystack))
                if prec.esas_no in query or prec.karar_no in query:
                    score += 5
                if score <= 0:
                    continue
                if prec.verification_status == "VERIFIED":
                    scored_prec.append((score, prec))
                elif include_superseded:
                    scored_inactive_prec.append((score, prec))
            scored_prec.sort(key=lambda item: (-item[0], item[1].precedent_id))
            scored_inactive_prec.sort(key=lambda item: (-item[0], item[1].precedent_id))
            matched_precedents = [prec.to_dict() for _, prec in scored_prec]
            inactive_or_pending_precedents = [prec.to_dict() for _, prec in scored_inactive_prec]

        card_results = query_knowledge_cards(self.knowledge_cards, query=query, as_of_date=as_of_date)

        return {
            "status": "OK",
            "query": query,
            "as_of_date": as_of_date,
            "matched_sources": matched_sources,
            "matched_precedents": matched_precedents,
            "inactive_or_pending_precedents": inactive_or_pending_precedents,
            "matched_knowledge_cards": card_results["effective_cards"],
            "not_effective_knowledge_cards": card_results["not_effective_on_date_cards"],
            "superseded_or_inactive_sources": superseded_sources,
            "no_verified_precedent_notice": (
                None
                if matched_precedents
                else "Doğrulanmış içtihat kayıt defterinde bu sorgu için teyitli Yargıtay Esas/Karar kaydı bulunamadı; karar numarası uydurulmamalıdır."
            ),
        }

    def _handle_lookup_knowledge_card(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).strip()
        as_of_date = str(args.get("as_of_date", "")).strip()
        law_no = args.get("law_no")
        if not query or not as_of_date:
            raise ValueError("'query' ve 'as_of_date' zorunludur.")
        res = query_knowledge_cards(self.knowledge_cards, query=query, as_of_date=as_of_date, law_no=law_no)
        return {
            "status": "OK",
            "query": query,
            "as_of_date": as_of_date,
            "law_no": law_no,
            **res,
        }

    def _handle_lookup_autonomous_norm_guidance(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query", "")).strip()
        if not query:
            raise ValueError("'query' zorunludur.")
        res = lookup_autonomous_norm_guidance(
            query,
            self.l5_hr_procedures,
            self.l6_cba_contract_practices,
            layer=args.get("layer"),
            norm_type=args.get("norm_type"),
            top_k=int(args.get("top_k", 5)),
        )
        return {"status": "OK", **res}

    def _handle_evaluate_autonomous_norm_conflict(self, args: dict[str, Any]) -> dict[str, Any]:
        proposed_change_direction = str(args.get("proposed_change_direction") or "").strip()
        if not proposed_change_direction:
            raise ValueError("'proposed_change_direction' zorunludur.")

        rule_obj: AutonomousNormRule | dict[str, Any] | None = None
        matched_rule_id: str | None = None
        if args.get("rule_id"):
            rid = str(args["rule_id"]).strip()
            rule_obj = self._autonomous_rules_by_id.get(rid)
            if rule_obj is None:
                raise ValueError(f"L5/L6 özerk norm kayıtlarında '{rid}' kuralı bulunamadı.")
            matched_rule_id = rid
        elif isinstance(args.get("rule"), dict):
            rule_obj = args["rule"]
            matched_rule_id = str(rule_obj.get("rule_id") or "") or None
        else:
            raise ValueError("'rule_id' veya 'rule' nesnesi zorunludur.")

        decision = evaluate_autonomous_norm_conflict(
            rule_obj,
            proposed_change_direction=proposed_change_direction,
            competing_norm_type=args.get("competing_norm_type"),
            statutory_floor_nature=args.get("statutory_floor_nature"),
            cba_expressly_forbids_individual_improvement=bool(
                args.get("cba_expressly_forbids_individual_improvement", False)
            ),
            written_employee_consent_4857_m22=bool(args.get("written_employee_consent_4857_m22", False)),
        )
        return {
            "status": "OK",
            "product_brand": "hrAI",
            "coordinator_agent": "@hrAI",
            "specialist_agent": "@HukukSGK",
            "product_website": "https://www.insenai.com.tr",
            "rule_id": matched_rule_id,
            **decision.to_dict(),
        }

    def _handle_check_article_effective_date(self, args: dict[str, Any]) -> dict[str, Any]:
        source_id = str(args["source_id"])
        article_ref = str(args["article_ref"])
        as_of_date = str(args["as_of_date"])
        src = self.sources.get(source_id)
        if src is None:
            raise ValueError(f"Mevzuat kayıt defterinde '{source_id}' bulunamadı.")
        return resolve_effective_article(src, article_ref=article_ref, as_of_date=as_of_date)

    def _handle_verify_document_integrity(self, args: dict[str, Any]) -> dict[str, Any]:
        target_id = str(args["record_id"])
        if target_id in self.sources:
            rec = self.sources[target_id]
            markers = rec.verification_audit.expected_text_markers if rec.verification_audit else (rec.statute_number,)
            expected_sha = rec.verification_audit.retrieved_content_sha256 if rec.verification_audit else rec.content_sha256
            res = verify_official_document(
                rec.source_url,
                expected_markers=markers,
                fetcher=self.document_fetcher,
                expected_sha256=expected_sha if args.get("enforce_sha256", False) else None,
            )
            return {"record_id": target_id, "record_type": "LEGAL_SOURCE", **res.to_dict()}
        if target_id in self.precedents:
            prec = self.precedents[target_id]
            markers = prec.verification_audit.expected_text_markers if prec.verification_audit else (prec.esas_no,)
            expected_sha = prec.verification_audit.retrieved_content_sha256 if prec.verification_audit else None
            res = verify_official_document(
                prec.official_source_url,
                expected_markers=markers,
                fetcher=self.document_fetcher,
                expected_sha256=expected_sha if args.get("enforce_sha256", False) else None,
            )
            return {"record_id": target_id, "record_type": "YARGITAY_PRECEDENT", **res.to_dict()}
        raise ValueError(f"Kayıt defterlerinde '{target_id}' bulunamadı.")

    def _handle_verify_citations(self, args: dict[str, Any]) -> dict[str, Any]:
        draft_text = str(args.get("draft_text", ""))
        as_of_date = str(args.get("as_of_date", ""))
        cited_source_ids = args.get("cited_source_ids")
        cited_precedent_ids = args.get("cited_precedent_ids")

        result = verify_response_citations(
            draft_text=draft_text,
            as_of_date=as_of_date,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            cited_source_ids=cited_source_ids,
            cited_precedent_ids=cited_precedent_ids,
        )
        return result.to_dict()

    def _handle_resolve_norm_conflict(self, args: dict[str, Any]) -> dict[str, Any]:
        na = args["norm_a"]
        nb = args["norm_b"]
        norm_a = NormReference(
            title=na["title"],
            norm_layer=na["norm_layer"],
            precedent_level=na.get("precedent_level", "NONE"),
            source_id=na.get("source_id"),
        )
        norm_b = NormReference(
            title=nb["title"],
            norm_layer=nb["norm_layer"],
            precedent_level=nb.get("precedent_level", "NONE"),
            source_id=nb.get("source_id"),
        )
        res = resolve_norm_conflict(
            norm_a=norm_a,
            norm_b=norm_b,
            mandatory_type=args["mandatory_type"],
            favors_employee_side=args.get("favors_employee_side", "UNKNOWN"),
            treaty_provision_nature=str(args.get("treaty_provision_nature", "UNSPECIFIED")),
        )
        return res.to_dict()

    def _handle_evaluate_precedent_application(self, args: dict[str, Any]) -> dict[str, Any]:
        prec_id = str(args["precedent_id"])
        source_id = str(args["interpreted_source_id"])
        as_of_date = str(args["as_of_date"])

        prec = self.precedents.get(prec_id)
        if prec is None:
            raise ValueError(f"İçtihat kayıt defterinde '{prec_id}' bulunamadı.")
        src = self.sources.get(source_id)
        if src is None:
            raise ValueError(f"Mevzuat kayıt defterinde '{source_id}' bulunamadı.")

        comp_raw = args.get("competing_norm")
        comp_norm: NormReference | None = None
        if isinstance(comp_raw, dict):
            comp_norm = NormReference(
                title=comp_raw["title"],
                norm_layer=comp_raw["norm_layer"],
                precedent_level=comp_raw.get("precedent_level", "NONE"),
                source_id=comp_raw.get("source_id"),
            )

        res = evaluate_precedent_application(
            precedent=prec,
            interpreted_source=src,
            as_of_date=as_of_date,
            scope_match_status=str(args.get("scope_match_status", "UNCERTAIN")),
            competing_norm=comp_norm,
            mandatory_type=str(args.get("mandatory_type", "RELATIVE_EMPLOYEE_FAVORABLE")),
            favors_employee_side=str(args.get("favors_employee_side", "UNKNOWN")),
            dispute_context=str(args.get("dispute_context", "")),
            application_rationale=str(args.get("application_rationale", "")),
            treaty_provision_nature=str(args.get("treaty_provision_nature", "UNSPECIFIED")),
        )
        return res.to_dict()

    def _handle_evaluate_hr_legal_scenario(self, args: dict[str, Any]) -> dict[str, Any]:
        scenario_type = str(args["scenario_type"])
        as_of_date = str(args["as_of_date"])
        facts = args.get("facts", {})
        if not isinstance(facts, dict):
            raise ValueError("'facts' alanı sözlük (dict) olmalıdır.")

        evaluation = evaluate_hr_legal_scenario(
            scenario_type=scenario_type,
            facts=facts,
            as_of_date=as_of_date,
            source_registry=self.sources,
            precedent_registry=self.precedents,
            knowledge_cards=self.knowledge_cards,
            approvers_registry=self.approvers_registry,
            attestation_ledger=self.attestation_ledger,
            project_root=self.project_root,
            runtime_environment=self.runtime_environment,
            require_signed_ledger_checkpoint=self.require_signed_ledger_checkpoint,
            expected_checkpoint_head_hash=self.expected_checkpoint_head_hash,
            expected_checkpoint_entry_count=self.expected_checkpoint_entry_count,
            expected_chain_digest_sha256=self.expected_chain_digest_sha256,
            external_trust_anchor_provider=self.external_trust_anchor_provider,
            expected_app_project_id=self.expected_app_project_id,
        )
        return evaluation.to_dict()

    def _handle_escalate(self, args: dict[str, Any]) -> dict[str, Any]:
        severity = str(args["severity"])
        reason = str(args["reason"])
        legal_issues = list(args.get("legal_issues", []))
        if not legal_issues:
            raise ValueError("Eskalasyon için en az bir 'legal_issues' maddesi gereklidir.")

        digest = hashlib.sha256(f"{severity}|{reason}|{'|'.join(legal_issues)}".encode("utf-8")).hexdigest()[:10].upper()
        return {
            "status": "ESCALATED_TO_LEGAL_COUNSEL",
            "ticket_id": f"LEGAL-ESC-{digest}",
            "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "severity": severity,
            "reason": reason,
            "affected_employees": list(args.get("affected_employees", [])),
            "legal_issues": legal_issues,
            "blocking_flags": list(args.get("blocking_flags", [])),
            "required_approver": args.get("required_approver", "Şirket Avukatı / İş Hukuku Müşaviri"),
            "payroll_handoff_blocked": True,
        }

    def build_evidence_linked_answer(
        self,
        *,
        query: str,
        answer_text: str,
        evidence_ids: list[str] | tuple[str, ...],
        as_of_date: str,
        evidence_registry: EvidenceRegistry | None = None,
        require_live_verified: bool = False,
        allow_historical_superseded: bool = False,
        historical_disclosure_text: str | None = None,
        scenario_evaluation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Connect an `@HukukSGK` legal answer directly to verified EvidenceRegistry records (WP2.6)."""
        reg = evidence_registry if evidence_registry is not None else self.evidence_registry
        if reg is None:
            raise ValueError(
                "Kanıta dayalı hukuki cevap oluşturmak için `evidence_registry` sağlanmalıdır "
                "(HukukSGKToolRouter(evidence_registry=...) veya doğrudan argüman)."
            )
        builder = EvidenceBackedLegalAnswerBuilder(reg)
        linked = builder.build_answer(
            query=query,
            answer_text=answer_text,
            evidence_ids=evidence_ids,
            as_of_date=as_of_date,
            require_live_verified=require_live_verified,
            allow_historical_superseded=allow_historical_superseded,
            historical_disclosure_text=historical_disclosure_text,
            router_payload=scenario_evaluation,
        )
        return linked.to_dict()

    def _handle_build_evidence_linked_answer(self, args: dict[str, Any]) -> dict[str, Any]:
        scenario_payload: dict[str, Any] | None = None
        if isinstance(args.get("scenario_request"), dict):
            scenario_payload = self._handle_evaluate_hr_legal_scenario(args["scenario_request"])
        elif isinstance(args.get("scenario_evaluation"), dict):
            scenario_payload = args["scenario_evaluation"]
        return self.build_evidence_linked_answer(
            query=str(args.get("query", "")),
            answer_text=str(args.get("answer_text", "")),
            evidence_ids=list(args.get("evidence_ids", [])),
            as_of_date=str(args.get("as_of_date", "")),
            require_live_verified=bool(args.get("require_live_verified", False)),
            allow_historical_superseded=bool(args.get("allow_historical_superseded", False)),
            historical_disclosure_text=args.get("historical_disclosure_text"),
            scenario_evaluation=scenario_payload,
        )

