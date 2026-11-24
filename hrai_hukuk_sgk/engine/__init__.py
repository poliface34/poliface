"""CALISORA @HukukSGK v1.0.4: Hardened Verification Engine, Legal Reasoning, Production Trust Root & Law No. 5070 NES/CAdES/XAdES Verification."""

from .esign5070.interfaces import (
    CertificateRevocationProvider,
    EshsTrustListProvider,
    QualifiedSignature5070VerifierProvider,
)
from .knowledge_card_validator import (
    load_central_audit_index,
    load_knowledge_cards,
    query_knowledge_cards,
    validate_knowledge_card_file,
)
from .models import (
    AmendmentRecord,
    ArticleEffectiveRule,
    CitationAuditResult,
    DocumentFetchResult,
    LegalKnowledgeCard,
    LegalSourceRecord,
    NormConflictResolution,
    NormReference,
    PrecedentRecord,
    RegistryValidationReport,
    VerificationAudit,
    VerificationFlag,
)
from .norm_hierarchy import resolve_norm_conflict
from .precedent_verifier import (
    load_precedent_registry,
    validate_precedent_registry,
    verify_response_citations,
)
from .source_validator import (
    is_specific_official_url,
    load_source_registry,
    resolve_effective_article,
    resolve_effective_sources,
    validate_source_registry,
)
from .tools_router import HukukSGKToolRouter
from .trust_root.interfaces import (
    ExternalTrustAnchorProvider,
    ImmutableEvidenceStorageProvider,
    KeySignerProvider,
    ProductionAuthorizationProvider,
    SourceAcquisitionProvider,
    TimestampAuthorityProvider,
)

__all__ = [
    "AmendmentRecord",
    "ArticleEffectiveRule",
    "CertificateRevocationProvider",
    "CitationAuditResult",
    "DocumentFetchResult",
    "EshsTrustListProvider",
    "ExternalTrustAnchorProvider",
    "HukukSGKToolRouter",
    "ImmutableEvidenceStorageProvider",
    "KeySignerProvider",
    "LegalKnowledgeCard",
    "LegalSourceRecord",
    "NormConflictResolution",
    "NormReference",
    "PrecedentRecord",
    "ProductionAuthorizationProvider",
    "QualifiedSignature5070VerifierProvider",
    "RegistryValidationReport",
    "SourceAcquisitionProvider",
    "TimestampAuthorityProvider",
    "VerificationAudit",
    "VerificationFlag",
    "is_specific_official_url",
    "load_knowledge_cards",
    "load_precedent_registry",
    "load_source_registry",
    "query_knowledge_cards",
    "resolve_effective_article",
    "resolve_effective_sources",
    "resolve_norm_conflict",
    "validate_knowledge_card_file",
    "validate_precedent_registry",
    "validate_source_registry",
    "verify_response_citations",
]
