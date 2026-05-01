//! Tests for Peer authentication and message exchange.

use bsv_auth::error::AuthError;
use bsv_auth::peer::{Peer, PeerOptions};
use bsv_auth::session_manager::DefaultSessionManager;
use bsv_auth::transport::Transport;
use bsv_auth::types::AuthMessage;
use bsv_primitives::ec::private_key::PrivateKey;
use bsv_wallet::{ProtoWallet, ProtoWalletArgs};
use std::sync::{Arc, Mutex};

/// A mock transport that pairs two peers together (synchronous delivery).
struct MockTransport {
    name: String,
    handler: Mutex<Option<Box<dyn Fn(&AuthMessage) -> Result<(), AuthError> + Send + Sync>>>,
    paired: Mutex<Option<Arc<MockTransport>>>,
}

impl MockTransport {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            handler: Mutex::new(None),
            paired: Mutex::new(None),
        })
    }

    fn pair(a: &Arc<MockTransport>, b: &Arc<MockTransport>) {
        *a.paired.lock().unwrap() = Some(Arc::clone(b));
        *b.paired.lock().unwrap() = Some(Arc::clone(a));
    }
}

impl Transport for MockTransport {
    fn send(&self, message: &AuthMessage) -> Result<(), AuthError> {
        let paired = self.paired.lock().unwrap();
        let paired = paired.as_ref().ok_or(AuthError::TransportNotConnected)?;

        let handler = paired.handler.lock().unwrap();
        let handler = handler.as_ref().ok_or(AuthError::NoHandlerRegistered)?;

        handler(message)
    }

    fn on_data(
        &self,
        callback: Box<dyn Fn(&AuthMessage) -> Result<(), AuthError> + Send + Sync>,
    ) -> Result<(), AuthError> {
        *self.handler.lock().unwrap() = Some(callback);
        Ok(())
    }
}

fn make_peer(name: &str, pk: &PrivateKey, transport: Arc<MockTransport>) -> Arc<Peer> {
    let wallet = ProtoWallet::new(ProtoWalletArgs::PrivateKey(pk.clone())).unwrap();
    let session_manager = Arc::new(DefaultSessionManager::new());

    Peer::new(PeerOptions {
        wallet: Arc::new(wallet),
        transport: transport as Arc<dyn Transport>,
        certificates_to_request: None,
        session_manager: Some(session_manager as Arc<dyn bsv_auth::SessionManager>),
        auto_persist_last_session: Some(true),
    })
}

#[test]
fn test_peer_authentication_and_message_exchange() {
    let alice_pk =
        PrivateKey::from_hex("143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c")
            .unwrap();
    let bob_pk =
        PrivateKey::from_hex("0881208859876fc227d71bfb8b91814462c5164b6fee27e614798f6e85d2547d")
            .unwrap();

    let alice_transport = MockTransport::new("Alice");
    let bob_transport = MockTransport::new("Bob");
    MockTransport::pair(&alice_transport, &bob_transport);

    let alice = make_peer("Alice", &alice_pk, alice_transport);
    let bob = make_peer("Bob", &bob_pk, bob_transport);

    // Set up Bob's message listener
    let received_message = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received_message);
    let received_sender = Arc::new(Mutex::new(None));
    let sender_clone = Arc::clone(&received_sender);

    bob.listen_for_general_messages(Box::new(move |sender, payload| {
        *sender_clone.lock().unwrap() = Some(sender.clone());
        *received_clone.lock().unwrap() = payload.to_vec();
        Ok(())
    }));

    // Alice sends a message to Bob
    let test_message = b"Hello Bob!";
    let bob_identity = bob_pk.pub_key();
    alice.to_peer(test_message, Some(&bob_identity)).unwrap();

    // Verify Bob received the message
    let received = received_message.lock().unwrap();
    assert_eq!(&*received, test_message);

    let sender = received_sender.lock().unwrap();
    assert!(sender.is_some());
    assert_eq!(
        sender.as_ref().unwrap().to_hex(),
        alice_pk.pub_key().to_hex()
    );
}

#[test]
fn test_peer_bidirectional_communication() {
    let alice_pk =
        PrivateKey::from_hex("143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c")
            .unwrap();
    let bob_pk =
        PrivateKey::from_hex("0881208859876fc227d71bfb8b91814462c5164b6fee27e614798f6e85d2547d")
            .unwrap();

    let alice_transport = MockTransport::new("Alice");
    let bob_transport = MockTransport::new("Bob");
    MockTransport::pair(&alice_transport, &bob_transport);

    let alice = make_peer("Alice", &alice_pk, alice_transport);
    let bob = make_peer("Bob", &bob_pk, bob_transport);

    // Bob listens
    let bob_received = Arc::new(Mutex::new(Vec::new()));
    let bob_clone = Arc::clone(&bob_received);
    bob.listen_for_general_messages(Box::new(move |_sender, payload| {
        *bob_clone.lock().unwrap() = payload.to_vec();
        Ok(())
    }));

    // Alice listens
    let alice_received = Arc::new(Mutex::new(Vec::new()));
    let alice_clone = Arc::clone(&alice_received);
    alice.listen_for_general_messages(Box::new(move |_sender, payload| {
        *alice_clone.lock().unwrap() = payload.to_vec();
        Ok(())
    }));

    // Alice sends to Bob
    alice
        .to_peer(b"Hello Bob!", Some(&bob_pk.pub_key()))
        .unwrap();
    assert_eq!(&*bob_received.lock().unwrap(), b"Hello Bob!");

    // Bob sends to Alice
    bob.to_peer(b"Hello Alice!", Some(&alice_pk.pub_key()))
        .unwrap();
    assert_eq!(&*alice_received.lock().unwrap(), b"Hello Alice!");
}
