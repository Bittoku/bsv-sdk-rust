//! Script templates for STAS token transactions.

pub mod stas3;
pub mod stas;
pub mod stas_btg;

pub use stas3::{Stas3UnlockingTemplate, Stas3MpkhUnlockingTemplate};
pub use stas::{unlock, unlock_mpkh, unlock_from_signing_key, StasUnlockingTemplate, StasMpkhUnlockingTemplate};
pub use stas_btg::{
    unlock_btg, unlock_btg_checkpoint, StasBtgUnlockingTemplate,
    StasBtgCheckpointUnlockingTemplate,
};
