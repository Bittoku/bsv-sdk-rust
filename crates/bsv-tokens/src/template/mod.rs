//! Script templates for STAS token transactions.

pub mod stas;
pub mod stas3;
pub mod stas_btg;

pub use stas::{
    unlock, unlock_from_signing_key, unlock_mpkh, StasMpkhUnlockingTemplate, StasUnlockingTemplate,
};
pub use stas3::{Stas3MpkhUnlockingTemplate, Stas3UnlockingTemplate};
pub use stas_btg::{
    unlock_btg, unlock_btg_checkpoint, StasBtgCheckpointUnlockingTemplate, StasBtgUnlockingTemplate,
};
