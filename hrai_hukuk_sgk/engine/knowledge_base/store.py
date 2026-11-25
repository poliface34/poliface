"""Hybrid vector + lexical Legal Knowledge Base providers with strict metadata pre-filtering (WP-4.2).

Provides:
  1. `LegalKnowledgeStoreProvider` (provider-agnostic abstract contract).
  2. `PostgresPgvectorKnowledgeStore` (canonical PostgreSQL 16+ & pgvector >= 0.8 DDL + pre-filtered RRF SQL).
     Reports `NOT_CONFIGURED` honestly and fails closed whenever DB settings/drivers are absent.
  3. `LocalDeterministicHybridStore` (pure Python stdlib BM25 + cosine vector + RRF engine enforcing exact
     SQL-parity WHERE pre-filtering: VERIFIED + content_verified gate, `as_of_date` effective-window gate,
     statute-vs-precedent isolation, L5/L6 non-adoption guard, and companion InterpretationAndBoundaryRule lookup).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict
import math
import os
import re
import threading
from typing import Any

from .chunker import DEFAULT_LOCAL_EMBEDDING_DIM, POSTGRES_DEFAULT_EMBEDDING_DIM, compute_deterministic_embedding, tokenize_legal_text, tr_fold
from .models import (
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_JUDICIAL_PRECEDENT,
    VERIFICATION_QUARANTINED_TAMPER,
    VERIFICATION_VERIFIED,
    ExcludedUnverifiedNotice,
    InterpretationAndBoundaryRule,
    JudicialPrecedentNode,
    KnowledgeBaseError,
    KnowledgeSearchQuery,
    KnowledgeSearchResult,
    LegalDocumentVersion,
    LegalProvisionNode,
    LegalSearchChunk,
    SearchHit,
    TrustChainEvidenceAdapterProtocol,
    parse_strict_kb_date,
)
from .quality_gate import (
    POOL_FAILED_QUARANTINED,
    POOL_PENDING_ISOLATED,
    POOL_VERIFIED_ACTIVE,
    evaluate_chunk_ingest_gate,
    verify_chunk_runtime_integrity,
)
from .versioning import BitemporalVersionManager

_ARTICLE_QUERY_RE = re.compile(r"\b(?:m\.|madde\s*)(\d+)(?:/([ivxlcdm]+))?(?:[-–/\s]+([a-z]))?\b", re.IGNORECASE)
_LAW_NUM_RE = re.compile(r"\b(\d{3,5})\b")
_CASE_NUM_RE = re.compile(r"\b(\d{4}/\d+)\b")


def build_postgres_pgvector_ddl(*, embedding_dim: int = POSTGRES_DEFAULT_EMBEDDING_DIM) -> str:
    """Generate the canonical PostgreSQL 16+ & pgvector >= 0.8 schema DDL for hrAI @HukukSGK WP-4.2."""
    if embedding_dim <= 0:
        raise ValueError("embedding_dim pozitif olmalıdır.")
    return f"""-- hrAI @HukukSGK WP-4.2 Legal Knowledge Base Schema (PostgreSQL 16+ & pgvector >= 0.8)
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS kb_document_versions (
    document_version_id   TEXT PRIMARY KEY,
    source_id             TEXT NOT NULL,
    evidence_id           TEXT,
    document_kind         TEXT NOT NULL,
    norm_layer            TEXT NOT NULL,
    norm_priority         SMALLINT NOT NULL,
    statute_no            TEXT NOT NULL,
    title                 TEXT NOT NULL,
    official_gazette_no   TEXT NOT NULL,
    publication_date      DATE NOT NULL,
    effective_from        DATE NOT NULL,
    effective_to          DATE,
    supersedes_version_id TEXT REFERENCES kb_document_versions(document_version_id),
    content_sha256        CHAR(64) NOT NULL,
    verification_status   TEXT NOT NULL,
    document_fetch_status TEXT NOT NULL,
    audit_log_id          TEXT NOT NULL,
    source_url            TEXT NOT NULL DEFAULT '',
    created_at_utc        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kb_judicial_precedents (
    precedent_id          TEXT PRIMARY KEY,
    court_system          TEXT NOT NULL,  -- YARGITAY | DANISTAY | AYM (never statutory norm layer)
    chamber               TEXT NOT NULL,
    binding_level         TEXT NOT NULL,
    esas_no               TEXT NOT NULL,
    karar_no              TEXT NOT NULL,
    decision_date         DATE NOT NULL,
    official_gazette_no   TEXT,
    official_source_url   TEXT NOT NULL,
    evidence_id           TEXT,
    interpreted_provisions JSONB NOT NULL,
    legal_principle       TEXT NOT NULL,
    operative_holding     TEXT NOT NULL,
    applies_to            JSONB NOT NULL,
    does_not_apply_to     JSONB NOT NULL,
    post_decision_status  TEXT NOT NULL,
    verification_status   TEXT NOT NULL,
    content_sha256        CHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS kb_interpretation_rules (
    rule_id               TEXT PRIMARY KEY,
    provision_id          TEXT NOT NULL,
    source_id             TEXT NOT NULL,
    card_id               TEXT,
    topic                 TEXT NOT NULL,
    effective_from        DATE NOT NULL,
    effective_to          DATE,
    verification_status   TEXT NOT NULL,
    how_to_interpret      JSONB NOT NULL,
    exceptions            JSONB NOT NULL,
    transitional_rules    JSONB NOT NULL,
    counter_arguments     JSONB NOT NULL,
    required_documents    JSONB NOT NULL,
    abstention_boundary   JSONB NOT NULL,
    content_sha256        CHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS kb_provision_chunks (
    chunk_id              TEXT PRIMARY KEY,
    provision_id          TEXT NOT NULL,
    document_version_id   TEXT NOT NULL,
    source_id             TEXT NOT NULL,
    evidence_id           TEXT,
    document_kind         TEXT NOT NULL,
    chunk_kind            TEXT NOT NULL,
    norm_layer            TEXT NOT NULL,
    norm_priority         SMALLINT NOT NULL,
    law_no                TEXT,
    article_no            TEXT,
    effective_from        DATE NOT NULL,
    effective_to          DATE,
    verification_status   TEXT NOT NULL,
    content_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    adoption_status       TEXT,
    content_sha256        CHAR(64) NOT NULL,
    chunk_sha256          CHAR(64) NOT NULL,
    raw_text              TEXT NOT NULL,
    context_header        TEXT NOT NULL,
    tsv_tr                TSVECTOR GENERATED ALWAYS AS (
                              to_tsvector('turkish', coalesce(context_header, '') || ' ' || coalesce(raw_text, ''))
                          ) STORED,
    embedding             VECTOR({embedding_dim}) NOT NULL,
    metadata_json         JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kb_chunks_gate ON kb_provision_chunks (verification_status, content_verified, document_kind, norm_layer);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_dates ON kb_provision_chunks (effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_law_prov ON kb_provision_chunks (law_no, provision_id);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_tsv ON kb_provision_chunks USING GIN (tsv_tr);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_vec ON kb_provision_chunks USING hnsw (embedding vector_cosine_ops);
"""


POSTGRES_PGVECTOR_SCHEMA_DDL = build_postgres_pgvector_ddl()


class LegalKnowledgeStoreProvider(ABC):
    """Provider-agnostic interface decoupling agent & RAG retrieval from concrete DB backends."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human/audit name of this storage backend."""

    @property
    @abstractmethod
    def integration_mode(self) -> str:
        """One of `LIVE_PRODUCTION`, `LOCAL_DETERMINISTIC`, or `NOT_CONFIGURED`."""

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Return honest configuration/reachability status."""

    @abstractmethod
    def upsert_bundle(
        self,
        *,
        document_versions: list[LegalDocumentVersion] | tuple[LegalDocumentVersion, ...] = (),
        provisions: list[LegalProvisionNode] | tuple[LegalProvisionNode, ...] = (),
        rules: list[InterpretationAndBoundaryRule] | tuple[InterpretationAndBoundaryRule, ...] = (),
        precedents: list[JudicialPrecedentNode] | tuple[JudicialPrecedentNode, ...] = (),
        chunks: list[LegalSearchChunk] | tuple[LegalSearchChunk, ...] = (),
    ) -> dict[str, Any]:
        """Validate & ingest versioned legal knowledge items through dual quality gates."""

    @abstractmethod
    def hybrid_search(self, query: KnowledgeSearchQuery) -> KnowledgeSearchResult:
        """Run pre-filtered hybrid vector + lexical search strictly bounded by verification & as_of_date."""

    @abstractmethod
    def get_rules_for_provision(self, provision_id: str, as_of_date: str) -> tuple[InterpretationAndBoundaryRule, ...]:
        """Return verified interpretation/exception/abstention rules valid on `as_of_date`."""

    @abstractmethod
    def resolve_version_as_of(self, provision_id: str, as_of_date: str) -> dict[str, Any]:
        """Point-in-time statutory/provision version resolution."""


class PostgresPgvectorKnowledgeStore(LegalKnowledgeStoreProvider):
    """Production PostgreSQL 16 + pgvector hybrid retrieval adapter (fails closed when NOT_CONFIGURED)."""

    def __init__(
        self,
        *,
        dsn: str | None = None,
        instance_connection_name: str | None = None,
        database_name: str | None = None,
        embedding_dim: int = POSTGRES_DEFAULT_EMBEDDING_DIM,
        ssl_mode: str = "VERIFY_CA",
    ) -> None:
        self._dsn = dsn or os.environ.get("HRAI_KB_POSTGRES_DSN") or os.environ.get("CALISORA_CLOUD_SQL_INSTANCE")
        self._instance_conn = instance_connection_name
        self._database_name = database_name
        self._embedding_dim = embedding_dim
        self._ssl_mode = ssl_mode

    @property
    def provider_name(self) -> str:
        return "POSTGRESQL_PGVECTOR_HYBRID_STORE"

    @property
    def integration_mode(self) -> str:
        if self._dsn and self._ssl_mode.upper() in {"VERIFY_CA", "VERIFY_FULL", "REQUIRE"}:
            return "CONFIGURED_UNVERIFIED_EXTERNAL"
        return "NOT_CONFIGURED"

    def health_check(self) -> dict[str, Any]:
        configured = bool(self._dsn or (self._instance_conn and self._database_name))
        return {
            "provider_name": self.provider_name,
            "integration_mode": "NOT_CONFIGURED" if not configured else "CONFIGURED_UNVERIFIED",
            "configured": configured,
            "reachable": False,
            "embedding_dim": self._embedding_dim,
            "ssl_mode": self._ssl_mode,
            "reason": (
                "PostgreSQL + pgvector canlı bağlantı bilgileri (HRAI_KB_POSTGRES_DSN / Cloud SQL) yapılandırılmadı."
                if not configured
                else "Yapılandırma mevcut; dış veritabanı sürücüsü ve canlı bağlantı doğrulaması bekleniyor."
            ),
        }

    def schema_ddl(self) -> str:
        return build_postgres_pgvector_ddl(embedding_dim=self._embedding_dim)

    def build_hybrid_search_sql(self, query: KnowledgeSearchQuery) -> tuple[str, dict[str, Any]]:
        """Build parameterized pgvector + GIN tsvector SQL with strict metadata pre-filtering & RRF."""
        if not query.as_of_date:
            raise KnowledgeBaseError(
                "MISSING_AS_OF_DATE_FOR_TEMPORAL_SEARCH",
                "PostgreSQL pgvector sorgusu olay tarihi (as_of_date) olmadan yürütülemez.",
            )
        parse_strict_kb_date(query.as_of_date, "as_of_date")
        if not query.query_text or len(query.query_text.strip()) < 2:
            raise KnowledgeBaseError("INVALID_SEARCH_QUERY", "Arama metni en az 2 karakter olmalıdır.")

        where_clauses = [
            "verification_status = 'VERIFIED'",
            "content_verified = TRUE",
            "effective_from <= %(as_of_date)s::date",
            "(effective_to IS NULL OR effective_to >= %(as_of_date)s::date)",
        ]
        params: dict[str, Any] = {
            "as_of_date": query.as_of_date,
            "query_text": query.query_text.strip(),
            "top_k": max(1, min(50, int(query.top_k))),
            "rrf_k": 60,
        }

        if query.require_adopted_autonomous_norms:
            where_clauses.append(
                "(document_kind <> 'AUTONOMOUS_NORM' OR adoption_status = 'COMPANY_ADOPTED_COUNSEL_VERIFIED')"
            )

        if query.document_kinds:
            where_clauses.append("document_kind = ANY(%(document_kinds)s)")
            params["document_kinds"] = list(query.document_kinds)

        if query.chunk_kinds:
            where_clauses.append("chunk_kind = ANY(%(chunk_kinds)s)")
            params["chunk_kinds"] = list(query.chunk_kinds)

        if query.law_nos:
            where_clauses.append("law_no = ANY(%(law_nos)s)")
            params["law_nos"] = list(query.law_nos)

        if query.court_systems:
            where_clauses.append("(metadata_json->>'court_system') = ANY(%(court_systems)s)")
            params["court_systems"] = list(query.court_systems)

        where_sql = "\n      AND ".join(where_clauses)
        sql = f"""SET LOCAL hnsw.iterative_scan = strict_order;
WITH filtered AS (
    SELECT
        chunk_id,
        provision_id,
        document_version_id,
        source_id,
        evidence_id,
        document_kind,
        chunk_kind,
        norm_layer,
        norm_priority,
        law_no,
        article_no,
        effective_from,
        effective_to,
        content_sha256,
        chunk_sha256,
        raw_text,
        context_header,
        metadata_json,
        1 - (embedding <=> %(query_embedding)s::vector({self._embedding_dim})) AS vector_score,
        ts_rank_cd(tsv_tr, plainto_tsquery('turkish', %(query_text)s)) AS lexical_score
    FROM kb_provision_chunks
    WHERE {where_sql}
),
ranked AS (
    SELECT
        *,
        ROW_NUMBER() OVER (ORDER BY vector_score DESC) AS vec_rank,
        ROW_NUMBER() OVER (ORDER BY lexical_score DESC, norm_priority ASC) AS lex_rank
    FROM filtered
)
SELECT
    *,
    (1.0 / (%(rrf_k)s + vec_rank) + 1.0 / (%(rrf_k)s + lex_rank)) AS rrf_score
FROM ranked
ORDER BY rrf_score DESC, norm_priority ASC, chunk_id ASC
LIMIT %(top_k)s;"""
        return sql, params

    def upsert_bundle(self, **kwargs: Any) -> dict[str, Any]:
        raise KnowledgeBaseError(
            "POSTGRES_PGVECTOR_NOT_CONFIGURED",
            "Canlı PostgreSQL + pgvector sürücüsü/bağlantısı yapılandırılmadığı için yazma işlemi fail-closed durduruldu.",
        )

    def hybrid_search(self, query: KnowledgeSearchQuery) -> KnowledgeSearchResult:
        raise KnowledgeBaseError(
            "POSTGRES_PGVECTOR_NOT_CONFIGURED",
            "Canlı PostgreSQL + pgvector bağlantısı yapılandırılmadı (integration_mode=NOT_CONFIGURED).",
        )

    def get_rules_for_provision(self, provision_id: str, as_of_date: str) -> tuple[InterpretationAndBoundaryRule, ...]:
        raise KnowledgeBaseError(
            "POSTGRES_PGVECTOR_NOT_CONFIGURED",
            "Canlı PostgreSQL + pgvector bağlantısı yapılandırılmadı.",
        )

    def resolve_version_as_of(self, provision_id: str, as_of_date: str) -> dict[str, Any]:
        raise KnowledgeBaseError(
            "POSTGRES_PGVECTOR_NOT_CONFIGURED",
            "Canlı PostgreSQL + pgvector bağlantısı yapılandırılmadı.",
        )


def _cosine_similarity(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def _is_chunk_active_as_of(chunk: LegalSearchChunk, as_of: str) -> bool:
    target = parse_strict_kb_date(as_of, "as_of_date")
    c_from = parse_strict_kb_date(chunk.effective_from, "effective_from")
    c_to = parse_strict_kb_date(chunk.effective_to, "effective_to") if chunk.effective_to else None
    return c_from <= target and (c_to is None or target <= c_to)


def _is_chunk_expired_as_of(chunk: LegalSearchChunk, as_of: str) -> bool:
    target = parse_strict_kb_date(as_of, "as_of_date")
    c_to = parse_strict_kb_date(chunk.effective_to, "effective_to") if chunk.effective_to else None
    return c_to is not None and c_to < target


class LocalDeterministicHybridStore(LegalKnowledgeStoreProvider):
    """Zero-dependency pure-Python stdlib hybrid vector+BM25 store enforcing exact SQL pre-filter semantics."""

    def __init__(
        self,
        *,
        embedding_dim: int = DEFAULT_LOCAL_EMBEDDING_DIM,
        trust_chain_adapter: TrustChainEvidenceAdapterProtocol | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._embedding_dim = embedding_dim
        self._versions = BitemporalVersionManager(trust_chain_adapter=trust_chain_adapter)
        self._active_chunks: dict[str, LegalSearchChunk] = {}
        self._pending_chunks: dict[str, LegalSearchChunk] = {}
        self._quarantined_chunks: dict[str, tuple[LegalSearchChunk, tuple[str, ...]]] = {}
        self._rules_by_provision: dict[str, list[InterpretationAndBoundaryRule]] = {}
        self._pending_rules: list[InterpretationAndBoundaryRule] = []
        self._precedents: dict[str, JudicialPrecedentNode] = {}
        self._pending_precedents: dict[str, JudicialPrecedentNode] = {}

    @property
    def provider_name(self) -> str:
        return "LOCAL_DETERMINISTIC_HYBRID_STORE"

    @property
    def integration_mode(self) -> str:
        return "LOCAL_DETERMINISTIC"

    @property
    def version_manager(self) -> BitemporalVersionManager:
        return self._versions

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "provider_name": self.provider_name,
                "integration_mode": self.integration_mode,
                "configured": True,
                "reachable": True,
                "embedding_dim": self._embedding_dim,
                "active_chunk_count": len(self._active_chunks),
                "pending_isolated_count": len(self._pending_chunks),
                "quarantined_count": len(self._quarantined_chunks),
                "verified_precedent_count": len(self._precedents),
            }

    def upsert_bundle(
        self,
        *,
        document_versions: list[LegalDocumentVersion] | tuple[LegalDocumentVersion, ...] = (),
        provisions: list[LegalProvisionNode] | tuple[LegalProvisionNode, ...] = (),
        rules: list[InterpretationAndBoundaryRule] | tuple[InterpretationAndBoundaryRule, ...] = (),
        precedents: list[JudicialPrecedentNode] | tuple[JudicialPrecedentNode, ...] = (),
        chunks: list[LegalSearchChunk] | tuple[LegalSearchChunk, ...] = (),
    ) -> dict[str, Any]:
        ingested_active = 0
        isolated_pending = 0
        quarantined = 0
        decisions: list[dict[str, Any]] = []

        with self._lock:
            for dv in document_versions:
                self._versions.register_document_version(dv)

            for prov in provisions:
                self._versions.register_provision_version(prov)

            for rule in rules:
                if rule.verification_status == VERIFICATION_VERIFIED:
                    existing_ids = {r.rule_id for r in self._rules_by_provision.get(rule.provision_id, [])}
                    if rule.rule_id not in existing_ids:
                        self._rules_by_provision.setdefault(rule.provision_id, []).append(rule)
                else:
                    self._pending_rules.append(rule)

            for prec in precedents:
                if prec.verification_status == VERIFICATION_VERIFIED:
                    self._precedents[prec.precedent_id] = prec
                else:
                    self._pending_precedents[prec.precedent_id] = prec

            for ch in chunks:
                gate = evaluate_chunk_ingest_gate(ch)
                decisions.append({"chunk_id": ch.chunk_id, **gate.to_dict()})
                if gate.accepted_active and gate.pool == POOL_VERIFIED_ACTIVE:
                    self._active_chunks[ch.chunk_id] = ch
                    ingested_active += 1
                elif gate.pool == POOL_PENDING_ISOLATED:
                    self._pending_chunks[ch.chunk_id] = ch
                    isolated_pending += 1
                else:
                    self._quarantined_chunks[ch.chunk_id] = (ch, gate.error_codes)
                    quarantined += 1

        return {
            "ingested_active_chunks": ingested_active,
            "isolated_pending_chunks": isolated_pending,
            "quarantined_chunks": quarantined,
            "document_version_count": len(document_versions),
            "provision_count": len(provisions),
            "precedent_count": len(precedents),
            "gate_decisions": decisions,
        }

    def get_rules_for_provision(self, provision_id: str, as_of_date: str) -> tuple[InterpretationAndBoundaryRule, ...]:
        target = parse_strict_kb_date(as_of_date, "as_of_date")
        with self._lock:
            matched: list[InterpretationAndBoundaryRule] = []
            for rule in self._rules_by_provision.get(provision_id, []):
                if rule.verification_status != VERIFICATION_VERIFIED:
                    continue
                r_from = parse_strict_kb_date(rule.effective_from, "rule.effective_from")
                r_to = parse_strict_kb_date(rule.effective_to, "rule.effective_to") if rule.effective_to else None
                if r_from <= target and (r_to is None or target <= r_to):
                    matched.append(rule)
            return tuple(matched)

    def resolve_version_as_of(self, provision_id: str, as_of_date: str) -> dict[str, Any]:
        return self._versions.resolve_version_as_of(provision_id, as_of_date)

    def get_precedent(self, precedent_id: str) -> JudicialPrecedentNode | None:
        with self._lock:
            return self._precedents.get(precedent_id)

    def verify_integrity(self) -> tuple[bool, dict[str, Any]]:
        errors: list[str] = []
        with self._lock:
            ver_ok, ver_rep = self._versions.verify_integrity()
            if not ver_ok:
                errors.extend(ver_rep["errors"])

            for cid, chunk in list(self._active_chunks.items()):
                ok, code = verify_chunk_runtime_integrity(chunk)
                if not ok:
                    errors.append(f"active_chunk={cid}: {code}")
            return len(errors) == 0, {
                "valid": len(errors) == 0,
                "version_report": ver_rep,
                "active_chunk_count": len(self._active_chunks),
                "pending_chunk_count": len(self._pending_chunks),
                "quarantined_chunk_count": len(self._quarantined_chunks),
                "errors": errors,
            }

    def _passes_non_date_prefilters(self, chunk: LegalSearchChunk, query: KnowledgeSearchQuery) -> bool:
        if query.require_adopted_autonomous_norms and chunk.document_kind == DOC_KIND_AUTONOMOUS_NORM:
            if chunk.adoption_status != "COMPANY_ADOPTED_COUNSEL_VERIFIED":
                return False
        if query.document_kinds and chunk.document_kind not in query.document_kinds:
            return False
        if query.chunk_kinds and chunk.chunk_kind not in query.chunk_kinds:
            return False
        if query.law_nos:
            allowed_laws = {str(x).strip() for x in query.law_nos}
            if str(chunk.law_no or "") not in allowed_laws:
                return False
        if query.court_systems:
            cs = str(chunk.metadata.get("court_system") or "")
            if cs not in query.court_systems:
                return False
        return True

    def _rank_candidates(
        self,
        candidates: list[LegalSearchChunk],
        *,
        query_text: str,
        top_k: int,
        as_of_date: str,
        is_historical: bool,
    ) -> list[SearchHit]:
        if not candidates:
            return []

        q_vec = compute_deterministic_embedding(query_text, dim=self._embedding_dim)
        q_tokens = tokenize_legal_text(query_text)
        q_fold = tr_fold(query_text)
        q_laws = set(_LAW_NUM_RE.findall(q_fold))
        q_cases = set(_CASE_NUM_RE.findall(q_fold))
        q_arts = _ARTICLE_QUERY_RE.findall(q_fold)

        # Document frequencies across pre-filtered pool (BM25-IDF)
        n_docs = len(candidates)
        doc_tokens: list[set[str]] = []
        df: dict[str, int] = {}
        for ch in candidates:
            toks = set(tokenize_legal_text(f"{ch.context_header} {ch.raw_text} {' '.join(ch.metadata.get('keywords', []))}"))
            doc_tokens.append(toks)
            for t in toks:
                df[t] = df.get(t, 0) + 1

        vec_scores: list[float] = []
        lex_scores: list[float] = []
        for idx, ch in enumerate(candidates):
            vec_sc = _cosine_similarity(q_vec, ch.embedding)
            vec_scores.append(vec_sc)

            lex_sc = 0.0
            c_toks = doc_tokens[idx]
            for qt in q_tokens:
                if qt in c_toks:
                    idf = math.log(1.0 + (n_docs - df.get(qt, 0) + 0.5) / (df.get(qt, 0) + 0.5))
                    lex_sc += max(0.5, idf)

            # High-precision structural identifier boosts (Kanun No, Madde/Fıkra/Bent, Esas/Karar)
            hay_fold = tr_fold(f"{ch.provision_id} {ch.source_id} {ch.context_header} {ch.raw_text}")
            if ch.law_no and str(ch.law_no) in q_laws:
                lex_sc += 4.5
            for case_no in q_cases:
                if case_no in hay_fold:
                    lex_sc += 6.0
            for art_num, f_rom, b_let in q_arts:
                art_marker = f"m-{art_num}"
                if art_marker in ch.provision_id.lower() or f"madde {art_num}" in hay_fold or f"m.{art_num}" in hay_fold:
                    lex_sc += 5.0
                if f_rom:
                    rom_map = {"i": "f-1", "ii": "f-2", "iii": "f-3", "iv": "f-4"}
                    expected_f = rom_map.get(f_rom.lower(), f"f-{f_rom.lower()}")
                    if expected_f in ch.provision_id.lower():
                        lex_sc += 4.0
                if b_let and f"b-{b_let.lower()}" in ch.provision_id.lower():
                    lex_sc += 4.0

            lex_scores.append(lex_sc)

        vec_order = sorted(range(n_docs), key=lambda i: (-vec_scores[i], candidates[i].norm_priority, candidates[i].chunk_id))
        lex_order = sorted(range(n_docs), key=lambda i: (-lex_scores[i], candidates[i].norm_priority, candidates[i].chunk_id))

        vec_rank = {doc_i: r + 1 for r, doc_i in enumerate(vec_order)}
        lex_rank = {doc_i: r + 1 for r, doc_i in enumerate(lex_order)}

        rrf_k = 60.0
        scored_indices = [
            i
            for i in range(n_docs)
            if lex_scores[i] > 0.0 or vec_scores[i] > 0.08
        ]
        if not scored_indices:
            return []

        scored_indices.sort(
            key=lambda i: (
                -(1.0 / (rrf_k + vec_rank[i]) + 1.0 / (rrf_k + lex_rank[i])),
                -lex_scores[i],
                candidates[i].norm_priority,
                candidates[i].chunk_id,
            )
        )

        hits: list[SearchHit] = []
        for rank_idx, doc_i in enumerate(scored_indices[:top_k], start=1):
            ch = candidates[doc_i]
            rrf = 1.0 / (rrf_k + vec_rank[doc_i]) + 1.0 / (rrf_k + lex_rank[doc_i])
            companions = self.get_rules_for_provision(ch.provision_id, as_of_date) if not is_historical else ()
            if is_historical:
                # For historical queries, fetch rules covering chunk's historical window
                companions = tuple(
                    r
                    for r in self._rules_by_provision.get(ch.provision_id, [])
                    if r.verification_status == VERIFICATION_VERIFIED and r.effective_from == ch.effective_from
                )
            hits.append(
                SearchHit(
                    rank=rank_idx,
                    rrf_score=rrf,
                    vector_score=vec_scores[doc_i],
                    lexical_score=lex_scores[doc_i],
                    chunk=ch,
                    is_historical_context=is_historical,
                    companion_rules=companions,
                )
            )
        return hits

    def _collect_excluded_notices(self, query: KnowledgeSearchQuery) -> list[ExcludedUnverifiedNotice]:
        q_toks = set(tokenize_legal_text(query.query_text))
        q_fold = tr_fold(query.query_text)
        q_laws = set(_LAW_NUM_RE.findall(q_fold))
        notices: list[ExcludedUnverifiedNotice] = []
        seen_keys: set[tuple[str, str]] = set()

        def _matches_query(text_blob: str, law_no: str | None) -> bool:
            if law_no and str(law_no) in q_laws:
                return True
            t_toks = set(tokenize_legal_text(text_blob))
            return len(q_toks & t_toks) >= 2 or (len(q_toks) == 1 and bool(q_toks & t_toks))

        for ch in self._pending_chunks.values():
            if not self._passes_non_date_prefilters(ch, query):
                if query.document_kinds and ch.document_kind not in query.document_kinds:
                    continue
                if query.law_nos and str(ch.law_no or "") not in query.law_nos:
                    continue
            blob = f"{ch.source_id} {ch.provision_id} {ch.context_header} {ch.raw_text} {' '.join(ch.metadata.get('keywords', []))}"
            if _matches_query(blob, ch.law_no):
                notice_status = (
                    ch.adoption_status or ch.verification_status
                    if ch.document_kind == DOC_KIND_AUTONOMOUS_NORM
                    else ch.verification_status
                )
                key = (ch.source_id, notice_status)
                if key not in seen_keys:
                    seen_keys.add(key)
                    notices.append(
                        ExcludedUnverifiedNotice(
                            record_id=ch.metadata.get("card_id") or ch.provision_id,
                            source_id=ch.source_id,
                            document_kind=ch.document_kind,
                            status=notice_status,
                            reason="Tam metin/hukuki inceleme tamamlanmadığı veya kurum kabulü beklediği için aktif arama havuzundan hariç tutuldu.",
                        )
                    )

        for ch, codes in self._quarantined_chunks.values():
            blob = f"{ch.source_id} {ch.provision_id} {ch.context_header} {ch.raw_text}"
            if _matches_query(blob, ch.law_no):
                status_str = ",".join(codes) if codes else ch.verification_status
                key = (ch.source_id, status_str)
                if key not in seen_keys:
                    seen_keys.add(key)
                    notices.append(
                        ExcludedUnverifiedNotice(
                            record_id=ch.provision_id,
                            source_id=ch.source_id,
                            document_kind=ch.document_kind,
                            status=status_str,
                            reason="Bütünlük veya Trust Chain doğrulamasından geçemediği için karantinaya alındı ve aktif havuzdan dışlandı.",
                        )
                    )

        return notices

    def hybrid_search(self, query: KnowledgeSearchQuery) -> KnowledgeSearchResult:
        if not query.as_of_date:
            raise KnowledgeBaseError(
                "MISSING_AS_OF_DATE_FOR_TEMPORAL_SEARCH",
                "Tarihsiz arama yasaktır: 'as_of_date' (YYYY-MM-DD) verilmeden hukuki hüküm getirilemez.",
            )
        parse_strict_kb_date(query.as_of_date, "as_of_date")
        if not isinstance(query.query_text, str) or len(query.query_text.strip()) < 2:
            raise KnowledgeBaseError("INVALID_SEARCH_QUERY", "Arama metni en az 2 karakter olmalıdır.")

        top_k = max(1, min(50, int(query.top_k)))
        with self._lock:
            active_candidates: list[LegalSearchChunk] = []
            historical_candidates: list[LegalSearchChunk] = []
            quarantined_runtime_count = 0

            for ch_id, chunk in list(self._active_chunks.items()):
                ok, err_code = verify_chunk_runtime_integrity(chunk)
                if not ok:
                    # Quarantine fail-closed if runtime integrity was compromised
                    self._quarantined_chunks[ch_id] = (chunk, (err_code or VERIFICATION_QUARANTINED_TAMPER,))
                    del self._active_chunks[ch_id]
                    quarantined_runtime_count += 1
                    continue

                if not self._passes_non_date_prefilters(chunk, query):
                    continue

                if _is_chunk_active_as_of(chunk, query.as_of_date):
                    active_candidates.append(chunk)
                elif query.include_historical and _is_chunk_expired_as_of(chunk, query.as_of_date):
                    historical_candidates.append(chunk)

            if quarantined_runtime_count > 0:
                raise KnowledgeBaseError(
                    VERIFICATION_QUARANTINED_TAMPER,
                    f"Çalışma zamanında {quarantined_runtime_count} chunk üzerinde SHA-256/bütünlük tahrifatı saptandı; arama fail-closed durduruldu.",
                )

            active_hits = tuple(
                self._rank_candidates(
                    active_candidates,
                    query_text=query.query_text,
                    top_k=top_k,
                    as_of_date=query.as_of_date,
                    is_historical=False,
                )
            )
            historical_hits = (
                tuple(
                    self._rank_candidates(
                        historical_candidates,
                        query_text=query.query_text,
                        top_k=top_k,
                        as_of_date=query.as_of_date,
                        is_historical=True,
                    )
                )
                if query.include_historical
                else ()
            )
            excluded = tuple(self._collect_excluded_notices(query))

            return KnowledgeSearchResult(
                query_text=query.query_text,
                as_of_date=query.as_of_date,
                provider_name=self.provider_name,
                integration_mode=self.integration_mode,
                active_hits=active_hits,
                historical_hits=historical_hits,
                excluded_unverified_notices=excluded,
                prefilter_summary={
                    "verified_active_candidates": len(active_candidates),
                    "historical_candidates": len(historical_candidates),
                    "excluded_unverified_matches": len(excluded),
                    "total_active_pool": len(self._active_chunks),
                    "total_pending_isolated": len(self._pending_chunks),
                    "total_quarantined": len(self._quarantined_chunks),
                },
            )
