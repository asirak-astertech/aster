//! Shared cryptographic boundary for the reference mission-session composition.

pub use crate::envelope::{
    EnvelopeError, EnvelopeHeader, EnvelopeSealer, SealRequest, SealedEnvelope, VerifiedControl,
    VerifiedEnvelope, VerifiedObject,
};
