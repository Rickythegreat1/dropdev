//! Local-only received-proposal review and approval. Network receipt never calls
//! this module. The Inbox remains immutable; Core owns provenance, previews,
//! receipts and restart/replay mapping atomically with its import baseline.
pub use crate::store::ProposalRef;
use crate::{
    store::Inbox,
    wire::{Change, Envelope},
    PeerError, PeerResult,
};
use devdrop_core::{
    file_permissions::FilePermissions,
    local::{Engine, Operation, Plan, Receipt, ReceivedChange, ReceivedProposal},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSide {
    Source,
    Target,
}
impl LocalSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Target => "target",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTarget {
    pub pair_id: String,
    pub side: LocalSide,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewApproval {
    pub confirmed_digest: String,
    pub disposable_copies: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyApproval {
    pub approved_plan_id: String,
    pub confirmed_digest: String,
    pub disposable_copies: bool,
    pub allow_permission_widening: bool,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionChoice {
    Incoming,
    Local,
    Both,
}
impl ResolutionChoice {
    fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Local => "local",
            Self::Both => "both",
        }
    }
}
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReviewedChange {
    Put {
        path: String,
        hash: String,
        data_bytes: usize,
        permissions: FilePermissions,
    },
    Delete {
        path: String,
        previous_hash: String,
    },
}
#[derive(Debug, Clone, Serialize)]
pub struct ProposalReview {
    pub proposal: ProposalRef,
    pub sender_fingerprint: String,
    pub receiver_fingerprint: String,
    pub channel: String,
    pub previous_digest: String,
    pub changes: Vec<ReviewedChange>,
    pub queued_only: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct LocalPreview {
    pub proposal: ProposalRef,
    pub local_target: LocalTarget,
    pub plan_id: String,
    pub state: String,
    pub operations: Vec<Operation>,
    pub blockers: Vec<String>,
    pub reverses: Option<String>,
}
fn core<T>(value: std::result::Result<T, devdrop_core::local::LocalError>) -> PeerResult<T> {
    value.map_err(|error| PeerError(error.0))
}
fn confirm(reference: &ProposalRef, digest: &str, disposable: bool) -> PeerResult<()> {
    if !disposable {
        return Err(PeerError(
            "Confirm disposable copies before received preview, resolution or apply.",
        ));
    }
    if digest != reference.digest {
        return Err(PeerError(
            "Confirm the exact queued proposal digest before local import.",
        ));
    }
    Ok(())
}
fn received(envelope: &Envelope) -> PeerResult<ReceivedProposal> {
    Ok(ReceivedProposal {
        pairing_id: envelope.pairing_id.clone(),
        sequence: envelope.sequence,
        digest: envelope.digest()?,
        previous_digest: envelope.previous_digest.clone(),
        changes: envelope
            .changes
            .iter()
            .map(|change| match change {
                Change::Put {
                    path,
                    hash,
                    bytes,
                    permissions,
                } => ReceivedChange::Put {
                    path: path.clone(),
                    hash: hash.clone(),
                    bytes: bytes.clone(),
                    permissions: permissions.clone(),
                },
                Change::Delete {
                    path,
                    previous_hash,
                } => ReceivedChange::Delete {
                    path: path.clone(),
                    previous_hash: previous_hash.clone(),
                },
            })
            .collect(),
    })
}
fn bind(
    plan: &Plan,
    plan_id: &str,
    proposal: &ReceivedProposal,
    target: &LocalTarget,
) -> PeerResult<()> {
    let origin = plan.received.as_ref().ok_or(PeerError(
        "Selected plan is not a received-proposal preview.",
    ))?;
    if plan.id != plan_id
        || plan.pair_id != target.pair_id
        || origin.side != target.side.as_str()
        || origin.pairing_id != proposal.pairing_id
        || origin.sequence != proposal.sequence
        || origin.digest != proposal.digest
        || origin.previous_digest != proposal.previous_digest
        || origin.semantic_hash != core(proposal.semantic_hash())?
    {
        return Err(PeerError(
            "Local preview does not match the exact proposal, content or chosen destination.",
        ));
    }
    Ok(())
}
fn view(plan: Plan, reference: &ProposalRef, target: &LocalTarget) -> LocalPreview {
    LocalPreview {
        proposal: reference.clone(),
        local_target: target.clone(),
        plan_id: plan.id,
        state: plan.state,
        operations: plan.operations,
        blockers: plan.blockers,
        reverses: plan.reverses,
    }
}
/// Sanitized, read-only evidence; no contents, staging root or signing keys escape.
pub fn review(inbox: &Inbox, reference: &ProposalRef) -> PeerResult<ProposalReview> {
    let proposal = inbox.validated_proposal(reference)?;
    Ok(ProposalReview {
        proposal: reference.clone(),
        sender_fingerprint: proposal.sender_fingerprint,
        receiver_fingerprint: proposal.receiver_fingerprint,
        channel: proposal.channel,
        previous_digest: proposal.previous_digest,
        changes: proposal
            .changes
            .into_iter()
            .map(|change| match change {
                Change::Put {
                    path,
                    hash,
                    bytes,
                    permissions,
                } => ReviewedChange::Put {
                    path,
                    hash,
                    data_bytes: bytes.len(),
                    permissions,
                },
                Change::Delete {
                    path,
                    previous_hash,
                } => ReviewedChange::Delete {
                    path,
                    previous_hash,
                },
            })
            .collect(),
        queued_only: true,
    })
}
/// Explicit confirmation precedes Core CAS storage. No sparse source folder exists.
pub fn preview(
    inbox: &Inbox,
    engine: &Engine,
    reference: &ProposalRef,
    target: &LocalTarget,
    approval: &PreviewApproval,
) -> PeerResult<LocalPreview> {
    confirm(
        reference,
        &approval.confirmed_digest,
        approval.disposable_copies,
    )?;
    let proposal = received(&inbox.validated_proposal(reference)?)?;
    let plan = core(engine.preview_received(
        &target.pair_id,
        target.side.as_str(),
        proposal.clone(),
        &approval.confirmed_digest,
        approval.disposable_copies,
    ))?;
    bind(&plan, &plan.id, &proposal, target)?;
    Ok(view(plan, reference, target))
}
/// Apply only the exact immutable Core preview, under separate local approvals.
pub fn apply(
    inbox: &Inbox,
    engine: &Engine,
    reference: &ProposalRef,
    target: &LocalTarget,
    plan_id: &str,
    approval: &ApplyApproval,
) -> PeerResult<Receipt> {
    confirm(
        reference,
        &approval.confirmed_digest,
        approval.disposable_copies,
    )?;
    if approval.approved_plan_id != plan_id {
        return Err(PeerError(
            "Approve the exact received preview ID before applying.",
        ));
    }
    let proposal = received(&inbox.validated_proposal(reference)?)?;
    let plan = core(engine.get_plan(plan_id))?;
    bind(&plan, plan_id, &proposal, target)?;
    core(engine.apply(
        plan_id,
        &approval.approved_plan_id,
        approval.disposable_copies,
        approval.allow_permission_widening,
    ))
}
/// Resolving a received conflict affects only its reviewed local side. The new
/// preview still needs its own explicit apply approval; no general pair sync runs.
pub fn resolve_preview(
    inbox: &Inbox,
    engine: &Engine,
    reference: &ProposalRef,
    target: &LocalTarget,
    plan_id: &str,
    path: &str,
    choice: ResolutionChoice,
    approval: &PreviewApproval,
) -> PeerResult<LocalPreview> {
    confirm(
        reference,
        &approval.confirmed_digest,
        approval.disposable_copies,
    )?;
    let proposal = received(&inbox.validated_proposal(reference)?)?;
    bind(&core(engine.get_plan(plan_id))?, plan_id, &proposal, target)?;
    let plan = core(engine.resolve_received_preview(plan_id, path, choice.as_str()))?;
    bind(&plan, &plan.id, &proposal, target)?;
    Ok(view(plan, reference, target))
}
/// Rollback is another exact preview; remote provenance remains historically
/// advanced, so later incoming data cannot silently overwrite restored work.
pub fn rollback_preview(
    inbox: &Inbox,
    engine: &Engine,
    reference: &ProposalRef,
    target: &LocalTarget,
    plan_id: &str,
    approval: &PreviewApproval,
) -> PeerResult<LocalPreview> {
    confirm(
        reference,
        &approval.confirmed_digest,
        approval.disposable_copies,
    )?;
    let proposal = received(&inbox.validated_proposal(reference)?)?;
    bind(&core(engine.get_plan(plan_id))?, plan_id, &proposal, target)?;
    let plan = core(engine.rollback_preview(plan_id))?;
    bind(&plan, &plan.id, &proposal, target)?;
    Ok(view(plan, reference, target))
}
