/* Post-Quantum NTRU public key algorithm*/

use ntrust_native::AesState;
use ntrust_native::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use ntrust_native::{
    CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};

use std::error;

fn test() {
    let mut rng = AesState::new();
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut ss_alice = [0u8; CRYPTO_BYTES];
    let mut ss_bob = [0u8; CRYPTO_BYTES];

    crypto_kem_keypair(&mut pk, &mut sk, &mut rng).unwrap();
    crypto_kem_enc(&mut ct, &mut ss_bob, &pk, &mut rng).unwrap();
    crypto_kem_dec(&mut ss_alice, &ct, &sk).unwrap();

    assert_eq!(ss_bob, ss_alice);
}
