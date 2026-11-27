"""K-01 & O-04: Cryptographically Verifiable Detached Legal Sign-Off & Dual-Control Override History.

Closes Critical Finding K-01 and Medium Finding O-04 from WP4_5_EVALUATION_SPEC v1.2:
  - SHA-256 alone does not authenticate WHO approved an answer key. Dataset files MUST only contain
    `PENDING_LEGAL_REVIEW`; inline `APPROVED_FOR_BENCHMARK` is rejected fail-closed.
  - Real approvals live in a detached envelope store (`SignedAnswerKeyApprovalEnvelope`) signed with
    external counsel private keys (Ed25519 or RSA-PSS-SHA256 over RFC 8785 JCS) and verified against
    an external `TrustedLegalApproverRegistry` containing ONLY public keys & bar enrollment metadata.
  - Any edit to an answer key invalidates prior signatures (`STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED`).
  - Supports append-only `REVOKE`, `KEY_COMPROMISE` invalidation, and `SUPERSEDE_REAPPROVE` history.
  - O-04 dual-control workflow for `LEGAL_FATAL_OVERRIDE`: engineering dispute memos cannot clear a veto,
    and overturning requires a second independent legal reviewer (`second_reviewer_id != first_reviewer_id`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any

from ..attestation_verifier import (
    SUPPORTED_SIGNATURE_ALGORITHMS,
    parse_utc_timestamp,
    sign_canonical_payload,
    verify_asymmetric_signature,
)
from .models import EvaluationCase, EvaluationIntegrityError

SIGNOFF_SCHEMA_V1 = "HRAI_WP45_LEGAL_SIGNOFF_V1"

ACTION_APPROVE = "APPROVE"
ACTION_REVOKE = "REVOKE"
ACTION_SUPERSEDE_REAPPROVE = "SUPERSEDE_REAPPROVE"
ACTION_OVERRIDE_FATAL = "OVERRIDE_FATAL"
ACTION_UPHOLD_OVERRIDE = "UPHOLD_OVERRIDE"
ACTION_OVERTURN_OVERRIDE = "OVERTURN_OVERRIDE"

VALID_SIGNOFF_ACTIONS: frozenset[str] = frozenset(
    {
        ACTION_APPROVE,
        ACTION_REVOKE,
        ACTION_SUPERSEDE_REAPPROVE,
        ACTION_OVERRIDE_FATAL,
        ACTION_UPHOLD_OVERRIDE,
        ACTION_OVERTURN_OVERRIDE,
    }
)

VALID_COUNSEL_ROLES: frozenset[str] = frozenset(
    {
        "INDEPENDENT_LABOR_LAW_COUNSEL",
        "SENIOR_SOCIAL_SECURITY_COUNSEL",
        "EXTERNAL_LEGAL_COUNSEL",
    }
)

SCOPE_ANSWER_KEY_APPROVAL = "EVALUATION_ANSWER_KEY_APPROVAL"
SCOPE_LEGAL_FATAL_OVERRIDE = "LEGAL_FATAL_OVERRIDE"

SIGNOFF_VERIFIED_APPROVED = "CRYPTOGRAPHICALLY_VERIFIED_APPROVED"
SIGNOFF_PENDING = "UNVERIFIED_PENDING"
SIGNOFF_REVOKED = "REVOKED_LEGAL_SIGN_OFF"
SIGNOFF_STALE = "STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED"
SIGNOFF_REJECTED = "REJECTED_INVALID_SIGNOFF"

SIGNATURE_ALGORITHM_PARAMS: dict[str, dict[str, Any]] = {
    "ED25519": {
        "standard": "RFC 8032 PureEd25519",
        "canonicalization": "RFC 8785 (JCS UTF-8 raw bytes)",
        "prehash": False,
        "key_bits": 256,
    },
    "RSA-PSS-SHA256": {
        "standard": "RFC 8017 RSASSA-PSS",
        "canonicalization": "RFC 8785 (JCS UTF-8 bytes)",
        "min_rsa_key_bits": 2048,
        "hash_algorithm": "SHA-256",
        "mgf": "MGF1-SHA256",
        "salt_length_bytes": 32,
        "padding": "PSS",
    },
}


def compute_public_key_fingerprint(public_key_pem: str) -> str:
    """Normalized SHA-256 fingerprint of a PEM public key."""
    return hashlib.sha256(str(public_key_pem or "").strip().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrustedLegalApproverRecord:
    approver_id: str
    approver_role: str
    bar_association_ref: str
    enrollment_status: str
    key_id: str
    key_version: str
    algorithm: str
    public_key_pem: str
    public_key_fingerprint_sha256: str
    valid_from_utc: str
    valid_until_utc: str
    status: str = "ACTIVE"  # ACTIVE | REVOKED | SUSPENDED
    revoked_at_utc: str | None = None
    revocation_reason: str | None = None
    authorized_scopes: tuple[str, ...] = (SCOPE_ANSWER_KEY_APPROVAL, SCOPE_LEGAL_FATAL_OVERRIDE)


@dataclass(frozen=True)
class TrustedLegalApproverRegistry:
    registry_version: str
    approvers: tuple[TrustedLegalApproverRecord, ...] = ()

    def resolve(self, *, approver_id: str, key_id: str) -> TrustedLegalApproverRecord | None:
        for rec in self.approvers:
            if rec.approver_id == approver_id and rec.key_id == key_id:
                return rec
        return None


@dataclass(frozen=True)
class SignedAnswerKeyApprovalEnvelope:
    schema: str
    envelope_id: str
    nonce: str
    action: str
    case_id: str
    answer_key_sha256: str
    dataset_version: str
    approver_id: str
    approver_role: str
    key_id: str
    key_version: str
    algorithm: str
    public_key_fingerprint_sha256: str
    signed_at_utc: str
    legal_rationale: str
    supersedes_envelope_id: str | None
    signature_b64: str
    qualified_e_signature_5070_equivalent: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "envelope_id": self.envelope_id,
            "nonce": self.nonce,
            "action": self.action,
            "case_id": self.case_id,
            "answer_key_sha256": self.answer_key_sha256,
            "dataset_version": self.dataset_version,
            "approver_id": self.approver_id,
            "approver_role": self.approver_role,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "algorithm": self.algorithm,
            "public_key_fingerprint_sha256": self.public_key_fingerprint_sha256,
            "signed_at_utc": self.signed_at_utc,
            "legal_rationale": self.legal_rationale,
            "supersedes_envelope_id": self.supersedes_envelope_id,
            "signature_b64": self.signature_b64,
            "qualified_e_signature_5070_equivalent": self.qualified_e_signature_5070_equivalent,
        }


@dataclass(frozen=True)
class EngineeringDisputeMemo:
    dispute_id: str
    case_id: str
    target_override_envelope_id: str
    filed_by: str
    filed_at_utc: str
    dispute_reason: str
    evidence_trace_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": "ENGINEERING_DISPUTE_MEMO",
            "dispute_id": self.dispute_id,
            "case_id": self.case_id,
            "target_override_envelope_id": self.target_override_envelope_id,
            "filed_by": self.filed_by,
            "filed_at_utc": self.filed_at_utc,
            "dispute_reason": self.dispute_reason,
            "evidence_trace_id": self.evidence_trace_id,
        }


@dataclass(frozen=True)
class VerifiedCaseSignoffState:
    case_id: str
    approved: bool
    signoff_status: str
    active_envelope_id: str | None
    approver_id: str | None
    failure_codes: tuple[str, ...]
    approval_history: tuple[dict[str, Any], ...] = ()
    legal_fatal_override_active: bool = False
    legal_fatal_override_reason: str = ""
    override_history: tuple[dict[str, Any], ...] = ()


def build_answer_key_signoff_payload(
    *,
    envelope_id: str,
    nonce: str,
    action: str,
    case_id: str,
    answer_key_sha256: str,
    dataset_version: str,
    approver_id: str,
    approver_role: str,
    key_id: str,
    key_version: str,
    algorithm: str,
    public_key_fingerprint_sha256: str,
    signed_at_utc: str,
    legal_rationale: str,
    supersedes_envelope_id: str | None = None,
) -> dict[str, Any]:
    """Build RFC 8785 (JCS) canonical signing payload binding approver, case_id, and answer_key_sha256."""
    return {
        "schema": SIGNOFF_SCHEMA_V1,
        "envelope_id": str(envelope_id).strip(),
        "nonce": str(nonce).strip(),
        "action": str(action).strip().upper(),
        "case_id": str(case_id).strip(),
        "answer_key_sha256": str(answer_key_sha256).strip().lower(),
        "dataset_version": str(dataset_version).strip(),
        "approver_id": str(approver_id).strip(),
        "approver_role": str(approver_role).strip(),
        "key_id": str(key_id).strip(),
        "key_version": str(key_version).strip(),
        "algorithm": str(algorithm).strip().upper(),
        "public_key_fingerprint_sha256": str(public_key_fingerprint_sha256).strip().lower(),
        "signed_at_utc": str(signed_at_utc).strip(),
        "legal_rationale": str(legal_rationale).strip(),
        "supersedes_envelope_id": str(supersedes_envelope_id).strip() if supersedes_envelope_id else None,
        "qualified_e_signature_5070_equivalent": False,
    }


def create_signed_answer_key_approval_envelope(
    *,
    case: EvaluationCase,
    dataset_version: str,
    envelope_id: str,
    nonce: str,
    action: str = ACTION_APPROVE,
    approver_id: str,
    approver_role: str,
    key_id: str,
    key_version: str,
    algorithm: str,
    private_key_pem: str,
    public_key_fingerprint_sha256: str,
    signed_at_utc: str,
    legal_rationale: str,
    supersedes_envelope_id: str | None = None,
) -> SignedAnswerKeyApprovalEnvelope:
    """Create a cryptographically signed detached envelope using an external counsel private key."""
    if action not in VALID_SIGNOFF_ACTIONS:
        raise EvaluationIntegrityError(f"Geçersiz hukuk onay eylemi: '{action}'.")
    key_sha = case.expected_answer_key_sha256()
    payload = build_answer_key_signoff_payload(
        envelope_id=envelope_id,
        nonce=nonce,
        action=action,
        case_id=case.case_id,
        answer_key_sha256=key_sha,
        dataset_version=dataset_version,
        approver_id=approver_id,
        approver_role=approver_role,
        key_id=key_id,
        key_version=key_version,
        algorithm=algorithm,
        public_key_fingerprint_sha256=public_key_fingerprint_sha256,
        signed_at_utc=signed_at_utc,
        legal_rationale=legal_rationale,
        supersedes_envelope_id=supersedes_envelope_id,
    )
    sig_b64 = sign_canonical_payload(payload, private_key_pem, algorithm=algorithm)
    return SignedAnswerKeyApprovalEnvelope(
        schema=SIGNOFF_SCHEMA_V1,
        envelope_id=envelope_id,
        nonce=nonce,
        action=action,
        case_id=case.case_id,
        answer_key_sha256=key_sha,
        dataset_version=dataset_version,
        approver_id=approver_id,
        approver_role=approver_role,
        key_id=key_id,
        key_version=key_version,
        algorithm=algorithm.upper().strip(),
        public_key_fingerprint_sha256=public_key_fingerprint_sha256.lower().strip(),
        signed_at_utc=signed_at_utc,
        legal_rationale=legal_rationale,
        supersedes_envelope_id=supersedes_envelope_id,
        signature_b64=sig_b64,
        qualified_e_signature_5070_equivalent=False,
    )


def _verify_single_envelope(
    env: SignedAnswerKeyApprovalEnvelope,
    *,
    registry: TrustedLegalApproverRegistry,
    expected_case_id: str,
    expected_answer_key_sha256: str,
    required_scope: str,
    seen_nonces: set[str],
) -> tuple[bool, tuple[str, ...]]:
    codes: list[str] = []
    if env.schema != SIGNOFF_SCHEMA_V1:
        codes.append("INVALID_SIGNOFF_SCHEMA")
    if env.qualified_e_signature_5070_equivalent is not False:
        codes.append("INVALID_5070_EQUIVALENCE_CLAIM")
    if env.action not in VALID_SIGNOFF_ACTIONS:
        codes.append("INVALID_SIGNOFF_ACTION")
    if env.case_id != expected_case_id:
        codes.append("CASE_ID_MISMATCH")
    if not env.nonce or len(env.nonce.strip()) < 8 or env.nonce in seen_nonces:
        codes.append("MISSING_OR_REPLAYED_NONCE")
    else:
        seen_nonces.add(env.nonce)

    if env.algorithm.upper().strip() not in SUPPORTED_SIGNATURE_ALGORITHMS:
        codes.append("UNSUPPORTED_SIGNATURE_ALGORITHM")

    rec = registry.resolve(approver_id=env.approver_id, key_id=env.key_id)
    if rec is None:
        codes.append("UNTRUSTED_OR_UNKNOWN_LEGAL_APPROVER")
        return False, tuple(codes)

    if rec.enrollment_status.upper() != "ENROLLED":
        codes.append("APPROVER_NOT_ENROLLED")
    if rec.approver_role not in VALID_COUNSEL_ROLES or env.approver_role != rec.approver_role:
        codes.append("UNAUTHORIZED_APPROVER_ROLE")
    if not rec.bar_association_ref.strip():
        codes.append("MISSING_BAR_ASSOCIATION_REF")
    if required_scope not in rec.authorized_scopes:
        codes.append("MISSING_AUTHORIZED_SCOPE")
    if env.key_version != rec.key_version or env.algorithm.upper().strip() != rec.algorithm.upper().strip():
        codes.append("KEY_METADATA_MISMATCH")
    expected_fp = compute_public_key_fingerprint(rec.public_key_pem)
    if (
        env.public_key_fingerprint_sha256.lower() != rec.public_key_fingerprint_sha256.lower()
        or env.public_key_fingerprint_sha256.lower() != expected_fp
    ):
        codes.append("PUBLIC_KEY_FINGERPRINT_MISMATCH")

    # Revocation & compromise checks
    if rec.status.upper() == "REVOKED" or rec.revoked_at_utc:
        if (rec.revocation_reason or "").upper() in {"KEY_COMPROMISE", "CA_COMPROMISE"}:
            codes.append("KEY_COMPROMISED_APPROVAL_INVALID")
        else:
            s_dt = parse_utc_timestamp(env.signed_at_utc)
            r_dt = parse_utc_timestamp(rec.revoked_at_utc)
            if s_dt is None or r_dt is None or s_dt >= r_dt:
                codes.append("SIGNER_KEY_REVOKED")
    elif rec.status.upper() != "ACTIVE":
        codes.append("SIGNER_KEY_SUSPENDED_OR_INACTIVE")

    s_dt = parse_utc_timestamp(env.signed_at_utc)
    vf_dt = parse_utc_timestamp(rec.valid_from_utc)
    vu_dt = parse_utc_timestamp(rec.valid_until_utc)
    if s_dt is None or vf_dt is None or vu_dt is None or s_dt < vf_dt or s_dt > vu_dt:
        codes.append("SIGNATURE_OUTSIDE_KEY_VALIDITY_WINDOW")

    # Answer-key SHA-256 binding check
    if env.answer_key_sha256.lower() != expected_answer_key_sha256.lower():
        codes.append("STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED")

    # Asymmetric cryptographic verification over RFC 8785 (JCS) payload
    payload = build_answer_key_signoff_payload(
        envelope_id=env.envelope_id,
        nonce=env.nonce,
        action=env.action,
        case_id=env.case_id,
        answer_key_sha256=env.answer_key_sha256,
        dataset_version=env.dataset_version,
        approver_id=env.approver_id,
        approver_role=env.approver_role,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint_sha256=env.public_key_fingerprint_sha256,
        signed_at_utc=env.signed_at_utc,
        legal_rationale=env.legal_rationale,
        supersedes_envelope_id=env.supersedes_envelope_id,
    )
    sig_ok, _sig_msg = verify_asymmetric_signature(
        payload,
        env.signature_b64,
        rec.public_key_pem,
        env.algorithm,
    )
    if not sig_ok:
        codes.append("CRYPTO_SIGNATURE_INVALID")

    return (len(codes) == 0), tuple(dict.fromkeys(codes))


def verify_detached_legal_signoffs(
    *,
    case: EvaluationCase,
    envelopes: tuple[SignedAnswerKeyApprovalEnvelope, ...] = (),
    dispute_memos: tuple[EngineeringDisputeMemo, ...] = (),
    registry: TrustedLegalApproverRegistry | None = None,
    strict_raise_on_stale_or_invalid: bool = False,
) -> VerifiedCaseSignoffState:
    """Verify detached Ed25519/RSA-PSS legal signoffs, revocations, re-approvals, and O-04 override appeal history."""
    case_envs = [e for e in envelopes if e.case_id == case.case_id]
    case_disputes = [d for d in dispute_memos if d.case_id == case.case_id]

    if not case_envs and not case_disputes:
        return VerifiedCaseSignoffState(
            case_id=case.case_id,
            approved=False,
            signoff_status=SIGNOFF_PENDING,
            active_envelope_id=None,
            approver_id=None,
            failure_codes=(),
            approval_history=(),
            legal_fatal_override_active=False,
            legal_fatal_override_reason="",
            override_history=(),
        )

    if registry is None:
        codes = ("APPROVERS_REGISTRY_UNAVAILABLE",)
        if strict_raise_on_stale_or_invalid:
            raise EvaluationIntegrityError(f"{case.case_id}: TrustedLegalApproverRegistry olmadan hukuk onayı doğrulanamaz.")
        return VerifiedCaseSignoffState(
            case_id=case.case_id,
            approved=False,
            signoff_status=SIGNOFF_REJECTED,
            active_envelope_id=None,
            approver_id=None,
            failure_codes=codes,
            approval_history=(),
        )

    expected_sha = case.expected_answer_key_sha256()
    seen_nonces: set[str] = set()

    # Sort approval/revocation events and override events chronologically
    sorted_envs = sorted(case_envs, key=lambda e: (e.signed_at_utc, e.envelope_id))
    approval_history: list[dict[str, Any]] = []
    failure_codes: list[str] = []

    approved = False
    signoff_status = SIGNOFF_PENDING
    active_envelope_id: str | None = None
    active_approver_id: str | None = None

    # O-04 Override appeal tracking
    override_events: list[tuple[str, dict[str, Any]]] = []
    override_active = False
    override_reason = ""
    first_override_reviewer_id: str | None = None
    first_override_envelope_id: str | None = None

    for env in sorted_envs:
        if env.action in {ACTION_APPROVE, ACTION_REVOKE, ACTION_SUPERSEDE_REAPPROVE}:
            ok, errs = _verify_single_envelope(
                env,
                registry=registry,
                expected_case_id=case.case_id,
                expected_answer_key_sha256=expected_sha,
                required_scope=SCOPE_ANSWER_KEY_APPROVAL,
                seen_nonces=seen_nonces,
            )
            entry = {
                "envelope_id": env.envelope_id,
                "action": env.action,
                "approver_id": env.approver_id,
                "key_id": env.key_id,
                "signed_at_utc": env.signed_at_utc,
                "supersedes_envelope_id": env.supersedes_envelope_id,
                "verified": ok,
                "error_codes": list(errs),
                "rationale": env.legal_rationale,
            }
            approval_history.append(entry)
            if not ok:
                failure_codes.extend(errs)
                if "STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED" in errs:
                    signoff_status = SIGNOFF_STALE
                else:
                    signoff_status = SIGNOFF_REJECTED
                approved = False
                if strict_raise_on_stale_or_invalid:
                    raise EvaluationIntegrityError(
                        f"{case.case_id} ({','.join(errs)}): bağımsız hukuk imza zarfı geçersiz veya bayatladı."
                    )
                continue

            if env.action == ACTION_REVOKE:
                approved = False
                signoff_status = SIGNOFF_REVOKED
                active_envelope_id = env.envelope_id
                active_approver_id = env.approver_id
            elif env.action in {ACTION_APPROVE, ACTION_SUPERSEDE_REAPPROVE}:
                approved = True
                signoff_status = SIGNOFF_VERIFIED_APPROVED
                active_envelope_id = env.envelope_id
                active_approver_id = env.approver_id

        elif env.action in {ACTION_OVERRIDE_FATAL, ACTION_UPHOLD_OVERRIDE, ACTION_OVERTURN_OVERRIDE}:
            ok, errs = _verify_single_envelope(
                env,
                registry=registry,
                expected_case_id=case.case_id,
                expected_answer_key_sha256=expected_sha,
                required_scope=SCOPE_LEGAL_FATAL_OVERRIDE,
                seen_nonces=seen_nonces,
            )
            ev_rec = {
                "event_type": env.action,
                "envelope_id": env.envelope_id,
                "approver_id": env.approver_id,
                "signed_at_utc": env.signed_at_utc,
                "supersedes_envelope_id": env.supersedes_envelope_id,
                "verified": ok,
                "error_codes": list(errs),
                "rationale": env.legal_rationale,
            }
            if not ok:
                failure_codes.extend(errs)
                override_events.append((env.signed_at_utc, ev_rec))
                if strict_raise_on_stale_or_invalid:
                    raise EvaluationIntegrityError(
                        f"{case.case_id} ({','.join(errs)}): hukuk override/itiraz imza zarfı geçersiz."
                    )
                continue

            if env.action == ACTION_OVERRIDE_FATAL:
                override_active = True
                override_reason = env.legal_rationale or "Bağımsız hukukçu FATAL veto kararı."
                first_override_reviewer_id = env.approver_id
                first_override_envelope_id = env.envelope_id
            elif env.action == ACTION_UPHOLD_OVERRIDE:
                if first_override_reviewer_id and env.approver_id == first_override_reviewer_id:
                    ev_rec["verified"] = False
                    ev_rec["error_codes"].append("DUAL_CONTROL_SECOND_REVIEWER_REQUIRED")
                    failure_codes.append("DUAL_CONTROL_SECOND_REVIEWER_REQUIRED")
                else:
                    override_active = True
            elif env.action == ACTION_OVERTURN_OVERRIDE:
                if first_override_reviewer_id and env.approver_id == first_override_reviewer_id:
                    # O-04 Dual-Control: Original reviewer cannot unilaterally overturn without 2nd counsel!
                    ev_rec["verified"] = False
                    ev_rec["error_codes"].append("DUAL_CONTROL_SECOND_REVIEWER_REQUIRED")
                    failure_codes.append("DUAL_CONTROL_SECOND_REVIEWER_REQUIRED")
                else:
                    override_active = False
                    override_reason = f"2. Hukukçu ({env.approver_id}) tarafından kaldırıldı: {env.legal_rationale}"

            override_events.append((env.signed_at_utc, ev_rec))

    for memo in case_disputes:
        override_events.append((memo.filed_at_utc, memo.to_dict()))
    override_events.sort(key=lambda pair: pair[0])

    return VerifiedCaseSignoffState(
        case_id=case.case_id,
        approved=approved,
        signoff_status=signoff_status,
        active_envelope_id=active_envelope_id,
        approver_id=active_approver_id,
        failure_codes=tuple(dict.fromkeys(failure_codes)),
        approval_history=tuple(approval_history),
        legal_fatal_override_active=override_active,
        legal_fatal_override_reason=override_reason,
        override_history=tuple(rec for _, rec in override_events),
    )
