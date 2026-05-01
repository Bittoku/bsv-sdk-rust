//! Peer — mutual authentication, session management, certificate exchange.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bsv_primitives::ec::public_key::PublicKey;
use bsv_primitives::ec::signature::Signature;
use bsv_wallet::types::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::certificates::VerifiableCertificate;
use crate::error::AuthError;
use crate::session_manager::{DefaultSessionManager, SessionManager};
use crate::transport::Transport;
use crate::types::*;
use crate::utils;

/// Callback types.
pub type OnGeneralMessageCallback =
    Box<dyn Fn(&PublicKey, &[u8]) -> Result<(), AuthError> + Send + Sync>;
/// Callback invoked when certificates are received from a peer.
pub type OnCertificateReceivedCallback =
    Box<dyn Fn(&PublicKey, &[VerifiableCertificate]) -> Result<(), AuthError> + Send + Sync>;
/// Callback invoked when a peer requests certificates.
pub type OnCertificateRequestCallback =
    Box<dyn Fn(&PublicKey, &RequestedCertificateSet) -> Result<(), AuthError> + Send + Sync>;

/// Callback type for initial response handling.
type InitialResponseFn = Box<dyn Fn(&str) -> Result<(), AuthError> + Send + Sync>;

struct InitialResponseCallback {
    callback: InitialResponseFn,
    session_nonce: String,
}

/// Peer capable of mutual authentication.
pub struct Peer {
    session_manager: Arc<dyn SessionManager>,
    transport: Arc<dyn Transport>,
    wallet: Arc<dyn bsv_wallet::wallet_trait::WalletInterface + Send + Sync>,
    /// Certificate types to request from peers during handshake.
    pub certificates_to_request: RwLock<RequestedCertificateSet>,
    general_message_callbacks: RwLock<HashMap<i32, OnGeneralMessageCallback>>,
    certificate_received_callbacks: RwLock<HashMap<i32, OnCertificateReceivedCallback>>,
    certificate_request_callbacks: RwLock<HashMap<i32, OnCertificateRequestCallback>>,
    initial_response_callbacks: Mutex<HashMap<i32, InitialResponseCallback>>,
    callback_counter: AtomicI32,
    auto_persist_last_session: bool,
    last_interacted_peer: RwLock<Option<PublicKey>>,
}

/// Configuration for creating a new Peer.
pub struct PeerOptions {
    /// Wallet used for key derivation, signing, and verification.
    pub wallet: Arc<dyn bsv_wallet::wallet_trait::WalletInterface + Send + Sync>,
    /// Transport layer for sending and receiving messages.
    pub transport: Arc<dyn Transport>,
    /// Certificate types to request from peers during handshake.
    pub certificates_to_request: Option<RequestedCertificateSet>,
    /// Custom session manager (defaults to in-memory manager).
    pub session_manager: Option<Arc<dyn SessionManager>>,
    /// Whether to persist the last interacted peer for convenience (defaults to true).
    pub auto_persist_last_session: Option<bool>,
}

impl Peer {
    /// Create a new Peer from the given options and register it for incoming messages.
    pub fn new(cfg: PeerOptions) -> Arc<Self> {
        let session_manager = cfg
            .session_manager
            .unwrap_or_else(|| Arc::new(DefaultSessionManager::new()));

        let auto_persist = cfg.auto_persist_last_session.unwrap_or(true);

        let peer = Arc::new(Peer {
            wallet: cfg.wallet,
            transport: cfg.transport,
            session_manager,
            certificates_to_request: RwLock::new(cfg.certificates_to_request.unwrap_or_default()),
            general_message_callbacks: RwLock::new(HashMap::new()),
            certificate_received_callbacks: RwLock::new(HashMap::new()),
            certificate_request_callbacks: RwLock::new(HashMap::new()),
            initial_response_callbacks: Mutex::new(HashMap::new()),
            callback_counter: AtomicI32::new(0),
            auto_persist_last_session: auto_persist,
            last_interacted_peer: RwLock::new(None),
        });

        // Register the incoming message handler
        let peer_clone = Arc::clone(&peer);
        let _ = peer.transport.on_data(Box::new(move |message| {
            peer_clone.handle_incoming_message(message)
        }));

        peer
    }

    fn next_callback_id(&self) -> i32 {
        self.callback_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn identity_key(&self) -> Result<PublicKey, AuthError> {
        let result = self.wallet.get_public_key(GetPublicKeyArgs {
            identity_key: true,
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: 0,
                    protocol: String::new(),
                },
                key_id: String::new(),
                counterparty: Counterparty::default(),
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            for_self: None,
        })?;
        Ok(result.public_key)
    }

    fn key_id(prefix: &str, suffix: &str) -> String {
        format!("{} {}", prefix, suffix)
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    // === Callback registration ===

    /// Register a callback for incoming general messages. Returns a listener ID.
    pub fn listen_for_general_messages(&self, callback: OnGeneralMessageCallback) -> i32 {
        let id = self.next_callback_id();
        self.general_message_callbacks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, callback);
        id
    }

    /// Remove a previously registered general message listener by ID.
    pub fn stop_listening_for_general_messages(&self, id: i32) {
        if let Ok(mut map) = self.general_message_callbacks.write() {
            map.remove(&id);
        }
    }

    /// Register a callback for when certificates are received. Returns a listener ID.
    pub fn listen_for_certificates_received(&self, callback: OnCertificateReceivedCallback) -> i32 {
        let id = self.next_callback_id();
        self.certificate_received_callbacks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, callback);
        id
    }

    /// Remove a previously registered certificate received listener by ID.
    pub fn stop_listening_for_certificates_received(&self, id: i32) {
        self.certificate_received_callbacks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    /// Register a callback for when certificates are requested by a peer. Returns a listener ID.
    pub fn listen_for_certificates_requested(&self, callback: OnCertificateRequestCallback) -> i32 {
        let id = self.next_callback_id();
        self.certificate_request_callbacks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, callback);
        id
    }

    /// Remove a previously registered certificate request listener by ID.
    pub fn stop_listening_for_certificates_requested(&self, id: i32) {
        self.certificate_request_callbacks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    // === Core protocol ===

    /// Send a message to a peer, initiating authentication if needed.
    pub fn to_peer(
        &self,
        message: &[u8],
        identity_key: Option<&PublicKey>,
    ) -> Result<(), AuthError> {
        let ik = identity_key.cloned().or_else(|| {
            if self.auto_persist_last_session {
                self.last_interacted_peer.read().ok()?.clone()
            } else {
                None
            }
        });

        let peer_session = self.get_authenticated_session(ik.as_ref())?;

        let request_nonce = utils::random_base64(32);
        let my_identity_key = self.identity_key()?;

        let mut general_message = AuthMessage::new(MessageType::General, my_identity_key);
        general_message.nonce = request_nonce.clone();
        general_message.your_nonce = peer_session.peer_nonce.clone();
        general_message.payload = message.to_vec();

        // Sign the message
        let sig_result = self.wallet.create_signature(CreateSignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&request_nonce, &peer_session.peer_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: peer_session.peer_identity_key.clone(),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: message.to_vec(),
            hash_to_directly_sign: Vec::new(),
        })?;

        general_message.signature = sig_result.signature.to_der();

        // Update session
        let mut updated = peer_session.clone();
        updated.last_update = Self::now_ms();
        self.session_manager.update_session(updated);

        if self.auto_persist_last_session {
            *self
                .last_interacted_peer
                .write()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))? =
                peer_session.peer_identity_key.clone();
        }

        self.transport.send(&general_message)
    }

    /// Get or create an authenticated session with a peer.
    pub fn get_authenticated_session(
        &self,
        identity_key: Option<&PublicKey>,
    ) -> Result<PeerSession, AuthError> {
        if let Some(ik) = identity_key {
            if let Ok(session) = self.session_manager.get_session(&ik.to_hex()) {
                if session.is_authenticated {
                    if self.auto_persist_last_session {
                        *self
                            .last_interacted_peer
                            .write()
                            .map_err(|_| AuthError::LockError("lock poisoned".into()))? =
                            Some(ik.clone());
                    }
                    return Ok(session);
                }
            }
        }

        self.initiate_handshake(identity_key)
    }

    fn initiate_handshake(
        &self,
        peer_identity_key: Option<&PublicKey>,
    ) -> Result<PeerSession, AuthError> {
        let session_nonce = utils::create_nonce(
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;

        let session = PeerSession {
            is_authenticated: false,
            session_nonce: session_nonce.clone(),
            peer_nonce: String::new(),
            peer_identity_key: peer_identity_key.cloned(),
            last_update: Self::now_ms(),
        };

        self.session_manager.add_session(session.clone())?;

        let my_identity_key = self.identity_key()?;

        let certs_to_request = self
            .certificates_to_request
            .read()
            .map_err(|_| AuthError::LockError("lock poisoned".into()))?
            .clone();

        let initial_request = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: my_identity_key,
            nonce: String::new(),
            initial_nonce: session_nonce.clone(),
            your_nonce: String::new(),
            certificates: Vec::new(),
            requested_certificates: certs_to_request,
            payload: Vec::new(),
            signature: Vec::new(),
        };

        // Set up response channel using a shared flag
        let response_received = Arc::new(Mutex::new(false));
        let response_received_clone = Arc::clone(&response_received);

        let callback_id = self.next_callback_id();
        let session_nonce_clone = session_nonce.clone();
        {
            let mut callbacks = self
                .initial_response_callbacks
                .lock()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
            callbacks.insert(
                callback_id,
                InitialResponseCallback {
                    callback: Box::new(move |_peer_nonce| {
                        *response_received_clone
                            .lock()
                            .map_err(|_| AuthError::LockError("lock poisoned".into()))? = true;
                        Ok(())
                    }),
                    session_nonce: session_nonce_clone,
                },
            );
        }

        self.transport.send(&initial_request)?;

        // For synchronous mock transport, the response is processed inline during send.
        // Check if we got a response.
        let got_response = *response_received
            .lock()
            .map_err(|_| AuthError::LockError("lock poisoned".into()))?;

        // Clean up callback
        {
            let mut callbacks = self
                .initial_response_callbacks
                .lock()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
            callbacks.remove(&callback_id);
        }

        if got_response {
            // Re-fetch the session which should now be updated
            self.session_manager
                .get_session(&session_nonce)
                .or_else(|_| {
                    if let Some(ik) = peer_identity_key {
                        self.session_manager.get_session(&ik.to_hex())
                    } else {
                        Err(AuthError::SessionNotFound)
                    }
                })
        } else {
            Err(AuthError::Timeout)
        }
    }

    fn handle_incoming_message(&self, message: &AuthMessage) -> Result<(), AuthError> {
        if message.version != AUTH_VERSION {
            return Err(AuthError::General(format!(
                "invalid auth version: {}, expected: {}",
                message.version, AUTH_VERSION
            )));
        }

        match message.message_type {
            MessageType::InitialRequest => self.handle_initial_request(message),
            MessageType::InitialResponse => self.handle_initial_response(message),
            MessageType::CertificateRequest => self.handle_certificate_request(message),
            MessageType::CertificateResponse => self.handle_certificate_response(message),
            MessageType::General => self.handle_general_message(message),
        }
    }

    fn handle_initial_request(&self, message: &AuthMessage) -> Result<(), AuthError> {
        if message.initial_nonce.is_empty() {
            return Err(AuthError::InvalidNonce);
        }

        let our_nonce = utils::create_nonce(
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;

        let certs_to_request = self
            .certificates_to_request
            .read()
            .map_err(|_| AuthError::LockError("lock poisoned".into()))?
            .clone();
        let needs_certs = certs_to_request.has_certificate_types();

        let session = PeerSession {
            is_authenticated: !needs_certs,
            session_nonce: our_nonce.clone(),
            peer_nonce: message.initial_nonce.clone(),
            peer_identity_key: Some(message.identity_key.clone()),
            last_update: Self::now_ms(),
        };

        self.session_manager.add_session(session.clone())?;

        // Send certificates if requested
        if message.requested_certificates.has_certifiers()
            || message.requested_certificates.has_certificate_types()
        {
            self.send_certificates(message)?;
        }

        let my_identity_key = self.identity_key()?;

        let mut response = AuthMessage::new(MessageType::InitialResponse, my_identity_key);
        response.nonce = our_nonce.clone();
        response.your_nonce = message.initial_nonce.clone();
        response.initial_nonce = session.session_nonce.clone();
        response.requested_certificates = certs_to_request;

        // Sign: data = initial_nonce_bytes || session_nonce_bytes
        let initial_nonce_bytes = BASE64.decode(&message.initial_nonce)?;
        let session_nonce_bytes = BASE64.decode(&session.session_nonce)?;
        let mut sig_data =
            Vec::with_capacity(initial_nonce_bytes.len() + session_nonce_bytes.len());
        sig_data.extend_from_slice(&initial_nonce_bytes);
        sig_data.extend_from_slice(&session_nonce_bytes);

        let sig_result = self.wallet.create_signature(CreateSignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&message.initial_nonce, &session.session_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(message.identity_key.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: sig_data,
            hash_to_directly_sign: Vec::new(),
        })?;

        response.signature = sig_result.signature.to_der();

        self.transport.send(&response)
    }

    fn handle_initial_response(&self, message: &AuthMessage) -> Result<(), AuthError> {
        // Verify nonce
        let valid = utils::verify_nonce(
            &message.your_nonce,
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;
        if !valid {
            return Err(AuthError::InvalidNonce);
        }

        let session = self.session_manager.get_session(&message.your_nonce)?;

        // Verify signature
        let session_nonce_bytes = BASE64.decode(&session.session_nonce)?;
        let initial_nonce_bytes = BASE64.decode(&message.initial_nonce)?;
        let mut sig_data =
            Vec::with_capacity(session_nonce_bytes.len() + initial_nonce_bytes.len());
        sig_data.extend_from_slice(&session_nonce_bytes);
        sig_data.extend_from_slice(&initial_nonce_bytes);

        let signature = Signature::from_der(&message.signature)
            .map_err(|e| AuthError::General(format!("failed to parse signature: {}", e)))?;

        let verify_result = self.wallet.verify_signature(VerifySignatureArgs {
            data: sig_data,
            signature: Some(signature),
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&session.session_nonce, &message.initial_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(message.identity_key.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            hash_to_directly_verify: Vec::new(),
            for_self: None,
        })?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature);
        }

        let certs_to_request = self
            .certificates_to_request
            .read()
            .map_err(|_| AuthError::LockError("lock poisoned".into()))?
            .clone();
        let needs_certs = certs_to_request.has_certificate_types();

        let mut updated = session.clone();
        updated.peer_nonce = message.initial_nonce.clone();
        updated.peer_identity_key = Some(message.identity_key.clone());
        updated.last_update = Self::now_ms();

        if !needs_certs {
            updated.is_authenticated = true;
        } else if !message.certificates.is_empty() {
            // Validate certificates
            self.validate_received_certificates(message, &certs_to_request)?;
            updated.is_authenticated = true;

            // Notify certificate listeners
            let callbacks = self
                .certificate_received_callbacks
                .read()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
            for callback in callbacks.values() {
                callback(&message.identity_key, &message.certificates)?;
            }
        }

        self.session_manager.update_session(updated);

        *self
            .last_interacted_peer
            .write()
            .map_err(|_| AuthError::LockError("lock poisoned".into()))? =
            Some(message.identity_key.clone());

        // Notify initial response callbacks
        let callbacks_snapshot: Vec<(i32, String)> = {
            let callbacks = self
                .initial_response_callbacks
                .lock()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
            callbacks
                .iter()
                .filter(|(_, cb)| cb.session_nonce == session.session_nonce)
                .map(|(id, cb)| (*id, cb.session_nonce.clone()))
                .collect()
        };

        for (id, _) in &callbacks_snapshot {
            let callback = {
                let callbacks = self
                    .initial_response_callbacks
                    .lock()
                    .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
                callbacks.get(id).map(|cb| &cb.callback as *const _)
            };
            if let Some(_callback_ptr) = callback {
                // Safe because we hold the lock implicitly through the Arc
                let callbacks = self
                    .initial_response_callbacks
                    .lock()
                    .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
                if let Some(cb) = callbacks.get(id) {
                    let _ = (cb.callback)(&session.session_nonce);
                }
            }
        }

        // Remove triggered callbacks
        {
            let mut callbacks = self
                .initial_response_callbacks
                .lock()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
            for (id, _) in &callbacks_snapshot {
                callbacks.remove(id);
            }
        }

        // Send certificates if peer requested them
        if message.requested_certificates.has_certifiers()
            || message.requested_certificates.has_certificate_types()
        {
            self.send_certificates(message)?;
        }

        Ok(())
    }

    fn handle_certificate_request(&self, message: &AuthMessage) -> Result<(), AuthError> {
        let valid = utils::verify_nonce(
            &message.your_nonce,
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;
        if !valid {
            return Err(AuthError::InvalidNonce);
        }

        let session = self.session_manager.get_session(&message.your_nonce)?;

        // Verify signature over serialized requested certificates
        let cert_request_data =
            serde_json::to_vec(&SerializableRequestedCerts(&message.requested_certificates))
                .map_err(|e| AuthError::General(format!("serialize cert request: {}", e)))?;

        let signature = Signature::from_der(&message.signature)
            .map_err(|e| AuthError::General(format!("failed to parse signature: {}", e)))?;

        let verify_result = self.wallet.verify_signature(VerifySignatureArgs {
            data: cert_request_data,
            signature: Some(signature),
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&message.nonce, &session.session_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(message.identity_key.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            hash_to_directly_verify: Vec::new(),
            for_self: None,
        })?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature);
        }

        // Update session timestamp
        let mut updated = session;
        updated.last_update = Self::now_ms();
        self.session_manager.update_session(updated);

        if message.requested_certificates.has_certifiers()
            || message.requested_certificates.has_certificate_types()
        {
            self.send_certificates(message)?;
        }

        Ok(())
    }

    fn handle_certificate_response(&self, message: &AuthMessage) -> Result<(), AuthError> {
        let valid = utils::verify_nonce(
            &message.your_nonce,
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;
        if !valid {
            return Err(AuthError::InvalidNonce);
        }

        let session = self.session_manager.get_session(&message.your_nonce)?;

        // Verify signature over serialized certificates
        let cert_data = serde_json::to_vec(&"[]") // TODO: proper serialization
            .unwrap_or_default();

        let signature = Signature::from_der(&message.signature)
            .map_err(|e| AuthError::General(format!("failed to parse signature: {}", e)))?;

        let verify_result = self.wallet.verify_signature(VerifySignatureArgs {
            data: cert_data,
            signature: Some(signature),
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&message.nonce, &session.session_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(message.identity_key.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            hash_to_directly_verify: Vec::new(),
            for_self: None,
        })?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature);
        }

        let mut updated = session;
        updated.last_update = Self::now_ms();

        if !message.certificates.is_empty() {
            let certs_to_request = self
                .certificates_to_request
                .read()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?
                .clone();
            self.validate_received_certificates(message, &certs_to_request)?;
            updated.is_authenticated = true;

            // Notify certificate listeners
            let callbacks = self
                .certificate_received_callbacks
                .read()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
            for callback in callbacks.values() {
                callback(&message.identity_key, &message.certificates)?;
            }
        }

        self.session_manager.update_session(updated);

        Ok(())
    }

    fn handle_general_message(&self, message: &AuthMessage) -> Result<(), AuthError> {
        let valid = utils::verify_nonce(
            &message.your_nonce,
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;
        if !valid {
            return Err(AuthError::InvalidNonce);
        }

        let session = self.session_manager.get_session(&message.your_nonce)?;

        if !session.is_authenticated {
            return Err(AuthError::NotAuthenticated);
        }

        // Verify signature
        let signature = Signature::from_der(&message.signature)
            .map_err(|e| AuthError::General(format!("failed to parse signature: {}", e)))?;

        let verify_result = self.wallet.verify_signature(VerifySignatureArgs {
            data: message.payload.clone(),
            signature: Some(signature),
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&message.nonce, &session.session_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(message.identity_key.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            hash_to_directly_verify: Vec::new(),
            for_self: None,
        })?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature);
        }

        // Update session
        let mut updated = session;
        updated.last_update = Self::now_ms();
        self.session_manager.update_session(updated);

        if self.auto_persist_last_session {
            *self
                .last_interacted_peer
                .write()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))? =
                Some(message.identity_key.clone());
        }

        // Notify listeners
        let callbacks = self
            .general_message_callbacks
            .read()
            .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
        for callback in callbacks.values() {
            let _ = callback(&message.identity_key, &message.payload);
        }

        Ok(())
    }

    fn send_certificates(&self, message: &AuthMessage) -> Result<(), AuthError> {
        // Check for custom callbacks first
        let has_callbacks = !self
            .certificate_request_callbacks
            .read()
            .map_err(|_| AuthError::LockError("lock poisoned".into()))?
            .is_empty();

        if has_callbacks {
            let callbacks = self
                .certificate_request_callbacks
                .read()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))?;
            for callback in callbacks.values() {
                callback(&message.identity_key, &message.requested_certificates)?;
            }
            return Ok(());
        }

        // Default: get certificates from wallet
        // This is a simplified version; full implementation would use wallet.list_certificates
        // and wallet.prove_certificate
        Ok(())
    }

    fn validate_received_certificates(
        &self,
        message: &AuthMessage,
        _requested: &RequestedCertificateSet,
    ) -> Result<(), AuthError> {
        if message.certificates.is_empty() {
            return Err(AuthError::CertificateValidation(
                "no certificates were provided".into(),
            ));
        }

        for cert in &message.certificates {
            // Verify subject matches sender
            if cert.certificate.subject != message.identity_key {
                return Err(AuthError::CertificateValidation(
                    "certificate subject does not match sender identity key".to_string(),
                ));
            }

            // Verify signature
            cert.verify()?;
        }

        Ok(())
    }

    /// Request certificates from a peer.
    pub fn request_certificates(
        &self,
        identity_key: &PublicKey,
        requirements: RequestedCertificateSet,
    ) -> Result<(), AuthError> {
        let peer_session = self.get_authenticated_session(Some(identity_key))?;

        let request_nonce = utils::create_nonce(
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;

        let my_identity_key = self.identity_key()?;

        let mut cert_request = AuthMessage::new(MessageType::CertificateRequest, my_identity_key);
        cert_request.nonce = request_nonce.clone();
        cert_request.your_nonce = peer_session.peer_nonce.clone();
        cert_request.requested_certificates = requirements.clone();

        // Sign the serialized requirements
        let cert_request_data = serde_json::to_vec(&SerializableRequestedCerts(&requirements))
            .map_err(|e| AuthError::General(format!("serialize cert request: {}", e)))?;

        let sig_result = self.wallet.create_signature(CreateSignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&request_nonce, &peer_session.peer_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(identity_key.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: cert_request_data,
            hash_to_directly_sign: Vec::new(),
        })?;

        cert_request.signature = sig_result.signature.to_der();

        // Update session
        let mut updated = peer_session;
        updated.last_update = Self::now_ms();
        self.session_manager.update_session(updated);

        if self.auto_persist_last_session {
            *self
                .last_interacted_peer
                .write()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))? =
                Some(identity_key.clone());
        }

        self.transport.send(&cert_request)
    }

    /// Send certificates back to a peer.
    pub fn send_certificate_response(
        &self,
        identity_key: &PublicKey,
        certificates: Vec<VerifiableCertificate>,
    ) -> Result<(), AuthError> {
        let peer_session = self.get_authenticated_session(Some(identity_key))?;

        let response_nonce = utils::create_nonce(
            self.wallet.as_ref(),
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            },
        )?;

        let my_identity_key = self.identity_key()?;

        let mut cert_response = AuthMessage::new(MessageType::CertificateResponse, my_identity_key);
        cert_response.nonce = response_nonce.clone();
        cert_response.your_nonce = peer_session.peer_nonce.clone();
        cert_response.certificates = certificates;

        // Sign the serialized certificates
        let cert_data = serde_json::to_vec(&"[]").unwrap_or_default(); // TODO: proper serialization

        let sig_result = self.wallet.create_signature(CreateSignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: AUTH_PROTOCOL_ID.to_string(),
                },
                key_id: Self::key_id(&response_nonce, &peer_session.peer_nonce),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(identity_key.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: cert_data,
            hash_to_directly_sign: Vec::new(),
        })?;

        cert_response.signature = sig_result.signature.to_der();

        // Update session
        let mut updated = peer_session;
        updated.last_update = Self::now_ms();
        self.session_manager.update_session(updated);

        if self.auto_persist_last_session {
            *self
                .last_interacted_peer
                .write()
                .map_err(|_| AuthError::LockError("lock poisoned".into()))? =
                Some(identity_key.clone());
        }

        self.transport.send(&cert_response)
    }
}

/// Helper for serializing RequestedCertificateSet to JSON (matching Go format).
struct SerializableRequestedCerts<'a>(&'a RequestedCertificateSet);

impl<'a> serde::Serialize for SerializableRequestedCerts<'a> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;

        // Certifiers as hex strings
        let certifiers: Vec<String> = self.0.certifiers.iter().map(|c| c.to_hex()).collect();
        map.serialize_entry("certifiers", &certifiers)?;

        // Certificate types: base64(type) -> [fields]
        let types: HashMap<String, &Vec<String>> = self
            .0
            .certificate_types
            .iter()
            .map(|(k, v)| (BASE64.encode(k), v))
            .collect();
        map.serialize_entry("certificateTypes", &types)?;

        map.end()
    }
}
