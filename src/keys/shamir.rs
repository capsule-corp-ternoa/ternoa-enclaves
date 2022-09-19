use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use vsss_rs::{curve25519::WrappedScalar, Shamir, Share};

const BYTES: usize = 33;

const M: usize = 5;
const N: usize = 8;

pub fn split_secret(
	secret: &[u8; BYTES - 1],
) -> std::result::Result<[Share<BYTES>; N], vsss_rs::Error> {
	let mut osrng = OsRng::default();
	let scalar = Scalar::from_bytes_mod_order(*secret);

	// let static_secret = StaticSecret::from(scalar.to_bytes());
	// let secret_key = SecretKey::from_bytes(&scalar.to_bytes()).unwrap();

	Shamir::<M, N>::split_secret::<WrappedScalar, OsRng, BYTES>(scalar.into(), &mut osrng)
}

pub fn combine_shares(shares: &[Share<BYTES>; M]) -> [u8; BYTES - 1] {
	let scalar = Shamir::<M, N>::combine_shares::<WrappedScalar, BYTES>(shares).unwrap();

	// let static_secret = StaticSecret::from(scalar.0.to_bytes());
	// let secret_key = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
	scalar.0.to_bytes()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test() {
		let secret = Scalar::random(&mut OsRng::default()).to_bytes();

		// Create the Shares
		let shares = split_secret(&secret).unwrap();

		// Gather shares from parties
		let select = [shares[5], shares[3], shares[0], shares[7], shares[2]];

		// Reconstruct the secret
		let reconst = combine_shares(&select);

		assert_eq!(reconst, secret);
	}
}
