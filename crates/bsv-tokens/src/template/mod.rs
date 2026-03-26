//! Script templates for STAS token transactions.

pub mod dstas;
pub mod stas;
pub mod stas_btg;

pub use dstas::{DstasUnlockingTemplate, DstasMpkhUnlockingTemplate};
pub use stas::{unlock, unlock_mpkh, unlock_from_signing_key, StasUnlockingTemplate, StasMpkhUnlockingTemplate};
pub use stas_btg::{
    unlock_btg, unlock_btg_checkpoint, StasBtgUnlockingTemplate,
    StasBtgCheckpointUnlockingTemplate,
};
