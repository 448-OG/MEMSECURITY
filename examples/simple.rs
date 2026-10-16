#![allow(clippy::disallowed_names)]
fn main() {
    foo()
}

#[cfg(all(
    feature = "encryption",
    feature = "ed25519",
    feature = "x25519",
    feature = "uuid"
))]
fn foo() {
    use memsecurity::*;
    use random_detached::{Generator, RandomBytes};
    let mut foo = EncryptedMem::new().unwrap();

    let plaintext_bytes = RandomBytes::<32>::new().unwrap();

    foo.encrypt(plaintext_bytes.expose()).unwrap();

    let decrypted = foo.decrypt().unwrap();
    assert_eq!(
        plaintext_bytes.expose(),
        decrypted.expose_borrowed().as_ref()
    );

    {
        assert!(foo
            .sign(*RandomBytes::<32>::new().unwrap().expose())
            .is_ok());

        let plaintext_bytes = RandomBytes::<4>::new().unwrap();

        foo.encrypt(plaintext_bytes.expose()).unwrap();

        assert!(foo
            .sign(*RandomBytes::<32>::new().unwrap().expose())
            .is_err());
    }

    {
        let mut alice_kek = EncryptedMem::new().unwrap();
        let alice_secret = RandomBytes::<32>::new().unwrap();
        alice_kek.encrypt(alice_secret.expose()).unwrap();
        drop(alice_secret);
        let alice_public = alice_kek.x25519_public_key().unwrap();

        let mut bob_kek = EncryptedMem::new().unwrap();
        let bob_secret = RandomBytes::<32>::new().unwrap();
        bob_kek.encrypt(bob_secret.expose()).unwrap();
        drop(bob_secret);
        let bob_public = bob_kek.x25519_public_key().unwrap();

        let alice_shared_secret = alice_kek.x25519_dh(bob_public).unwrap();
        let bob_shared_secret = bob_kek.x25519_dh(alice_public).unwrap();

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes())
    }

    {
        let mut store = EncryptedMem::new().unwrap();
        store.encrypt_uuid().unwrap();

        let decrypted = store.decrypt_uuid().unwrap();
        assert_eq!(decrypted.expose_borrowed().len(), 16usize);
    }
}
