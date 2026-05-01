//! Interpreter configuration with pre/post-genesis limits.

/// Maximum number of non-push opcodes allowed before genesis activation.
pub const MAX_OPS_BEFORE_GENESIS: usize = 500;
/// Maximum combined stack size (data + alt) allowed before genesis activation.
pub const MAX_STACK_SIZE_BEFORE_GENESIS: usize = 1000;
/// Maximum script byte size allowed before genesis activation.
pub const MAX_SCRIPT_SIZE_BEFORE_GENESIS: usize = 10000;
/// Maximum single data element byte size allowed before genesis activation.
pub const MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS: usize = 520;
/// Maximum byte length for numeric script values before genesis activation.
pub const MAX_SCRIPT_NUMBER_LENGTH_BEFORE_GENESIS: usize = 4;
/// Maximum number of public keys in a multisig operation before genesis activation.
pub const MAX_PUB_KEYS_PER_MULTISIG_BEFORE_GENESIS: usize = 20;

/// Script configuration limits.
pub struct Config {
    /// Whether post-genesis rules are active (relaxes most limits).
    pub after_genesis: bool,
}

impl Config {
    /// Create a configuration with pre-genesis (legacy) limits.
    pub fn before_genesis() -> Self {
        Config {
            after_genesis: false,
        }
    }

    /// Create a configuration with post-genesis (relaxed) limits.
    pub fn after_genesis() -> Self {
        Config {
            after_genesis: true,
        }
    }

    /// Return the maximum number of non-push opcodes allowed per script.
    pub fn max_ops(&self) -> usize {
        if self.after_genesis {
            i32::MAX as usize
        } else {
            MAX_OPS_BEFORE_GENESIS
        }
    }

    /// Return the maximum combined stack size (data + alt).
    pub fn max_stack_size(&self) -> usize {
        if self.after_genesis {
            i32::MAX as usize
        } else {
            MAX_STACK_SIZE_BEFORE_GENESIS
        }
    }

    /// Return the maximum script byte size.
    pub fn max_script_size(&self) -> usize {
        if self.after_genesis {
            i32::MAX as usize
        } else {
            MAX_SCRIPT_SIZE_BEFORE_GENESIS
        }
    }

    /// Return the maximum byte size for a single data element.
    pub fn max_script_element_size(&self) -> usize {
        if self.after_genesis {
            i32::MAX as usize
        } else {
            MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS
        }
    }

    /// Return the maximum byte length for numeric script values.
    pub fn max_script_number_length(&self) -> usize {
        if self.after_genesis {
            750 * 1000
        } else {
            MAX_SCRIPT_NUMBER_LENGTH_BEFORE_GENESIS
        }
    }

    /// Return the maximum number of public keys in a multisig operation.
    pub fn max_pub_keys_per_multisig(&self) -> usize {
        if self.after_genesis {
            i32::MAX as usize
        } else {
            MAX_PUB_KEYS_PER_MULTISIG_BEFORE_GENESIS
        }
    }
}
