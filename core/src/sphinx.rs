use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as EdFr};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;

use crate::config::{HEADER_SIZE, L, PACKET_SIZE, PAYLOAD_SIZE};
use crate::poseidon::Poseidon;
use crate::types::{AffinePoint, KeyPair, Scalar, SphinxPacket};

/// Sphinx packet construction and processing.
///
/// Header (~400 bytes): routing info, encrypted with Poseidon-CTR. Processed in SNARK.
/// Payload (~1648 bytes): message content, encrypted with derived stream cipher. Outside SNARK.

#[derive(Clone, Debug)]
pub struct SphinxRoute {
    pub hops: Vec<HopInfo>,
}

#[derive(Clone, Debug)]
pub struct HopInfo {
    pub node_pk: AffinePoint,
    pub address: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ProcessedHeader {
    pub next_hop_address: [u8; 32],
    pub next_header: [u8; HEADER_SIZE],
    pub shared_secret: Scalar,
}

/// Construct a Sphinx packet for a given route.
pub fn construct_packet<R: RngCore>(
    message: &[u8],
    route: &SphinxRoute,
    rng: &mut R,
) -> SphinxPacket {
    assert!(route.hops.len() == L, "Route must have exactly L={} hops", L);
    assert!(
        message.len() <= PAYLOAD_SIZE,
        "Message too large for single packet"
    );

    let poseidon = Poseidon::new();

    // Generate ephemeral keypair (scalar in BabyJubjub's scalar field)
    let eph_sk = EdFr::rand(rng);
    let eph_pk: AffinePoint = (EdwardsProjective::generator() * eph_sk).into();

    // Compute shared secrets for each hop (forward)
    let mut shared_secrets = Vec::with_capacity(L);
    let mut current_sk = eph_sk;

    for hop in &route.hops {
        // ECDH: shared_point = sk * hop_pk (scalar mult in EdFr)
        let shared_point: AffinePoint = (hop.node_pk.into_group() * current_sk).into();
        let shared_secret = poseidon.hash(&[shared_point.x, shared_point.y]);
        shared_secrets.push(shared_secret);

        // Blinding factor for next hop (convert from BN254 Fr to Ed Fr via bytes)
        let blind_bn254 = poseidon.hash(&[shared_secret, Fr::from(1u64)]);
        let mut blind_bytes = Vec::new();
        blind_bn254.serialize_compressed(&mut blind_bytes).unwrap();
        let blind = EdFr::from_le_bytes_mod_order(&blind_bytes);
        current_sk = current_sk * blind;
    }

    // Build header layers (from last hop to first, onion-style)
    let mut header = [0u8; HEADER_SIZE];

    // Encode routing for each layer (simplified: just addresses)
    for (i, hop) in route.hops.iter().enumerate().rev() {
        let routing_key = poseidon.hash(&[shared_secrets[i], Fr::from(2u64)]);
        let mut key_bytes = Vec::new();
        routing_key.serialize_compressed(&mut key_bytes).unwrap();

        // XOR header with derived keystream (Poseidon-CTR)
        let keystream = generate_poseidon_keystream(&poseidon, &shared_secrets[i], HEADER_SIZE);
        for (j, byte) in header.iter_mut().enumerate() {
            *byte ^= keystream[j];
        }

        // Insert this hop's routing info at the beginning
        let addr_offset = i * 32;
        if addr_offset + 32 <= HEADER_SIZE {
            header[addr_offset..addr_offset + 32].copy_from_slice(&hop.address);
        }
    }

    // Encrypt payload with stream cipher derived from final shared secret
    let mut payload = [0u8; PAYLOAD_SIZE];
    payload[..message.len()].copy_from_slice(message);

    let payload_keystream =
        generate_poseidon_keystream(&poseidon, &shared_secrets[L - 1], PAYLOAD_SIZE);
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= payload_keystream[i];
    }

    // Embed ephemeral public key in first 32 bytes of header
    let mut pk_bytes = Vec::new();
    eph_pk.serialize_compressed(&mut pk_bytes).unwrap();
    header[..pk_bytes.len().min(32)].copy_from_slice(&pk_bytes[..pk_bytes.len().min(32)]);

    SphinxPacket {
        header,
        payload: payload.try_into().unwrap(),
    }
}

/// Process a Sphinx packet at a relay node (peel one layer).
pub fn process_at_relay(
    packet: &SphinxPacket,
    node_keypair: &KeyPair,
    poseidon: &Poseidon,
) -> ProcessedHeader {
    // Extract ephemeral pk from header
    use ark_serialize::CanonicalDeserialize;
    let eph_pk_bytes = &packet.header[..32];
    let eph_pk = EdwardsAffine::deserialize_compressed(eph_pk_bytes).unwrap_or_default();

    // ECDH: shared_point = node_sk * eph_pk (scalar in EdFr)
    let shared_point: AffinePoint = (eph_pk.into_group() * node_keypair.secret).into();
    let shared_secret = poseidon.hash(&[shared_point.x, shared_point.y]);

    // Decrypt header layer with Poseidon-CTR
    let keystream = generate_poseidon_keystream(poseidon, &shared_secret, HEADER_SIZE);
    let mut decrypted_header = packet.header;
    for (i, byte) in decrypted_header.iter_mut().enumerate() {
        *byte ^= keystream[i];
    }

    // Extract next hop address (first 32 bytes after our routing info)
    let mut next_hop_address = [0u8; 32];
    next_hop_address.copy_from_slice(&decrypted_header[32..64]);

    ProcessedHeader {
        next_hop_address,
        next_header: decrypted_header,
        shared_secret,
    }
}

/// Generate Poseidon-CTR keystream of given length.
fn generate_poseidon_keystream(poseidon: &Poseidon, key: &Scalar, length: usize) -> Vec<u8> {
    let blocks_needed = (length + 31) / 32; // 32 bytes per field element
    let mut keystream = Vec::with_capacity(blocks_needed * 32);

    for ctr in 0..blocks_needed {
        let block = poseidon.hash(&[*key, Fr::from(ctr as u64)]);
        let mut block_bytes = Vec::new();
        block.serialize_compressed(&mut block_bytes).unwrap();
        keystream.extend_from_slice(&block_bytes);
    }

    keystream.truncate(length);
    keystream
}

/// Compute packet hash for receipt generation.
pub fn packet_hash(packet: &SphinxPacket, poseidon: &Poseidon) -> Scalar {
    let h1 = Fr::from_le_bytes_mod_order(&packet.header[..31]);
    let h2 = Fr::from_le_bytes_mod_order(&packet.payload[..31]);
    poseidon.hash(&[h1, h2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::SeedableRng;

    fn make_keypair<R: RngCore>(rng: &mut R) -> KeyPair {
        use ark_ec::Group;
        let secret = EdFr::rand(rng);
        let public: AffinePoint = (EdwardsProjective::generator() * secret).into();
        KeyPair { secret, public }
    }

    #[test]
    fn test_packet_construction() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let msg = b"Hello, anonymous world!";

        let keys: Vec<KeyPair> = (0..L).map(|_| make_keypair(&mut rng)).collect();
        let route = SphinxRoute {
            hops: keys
                .iter()
                .enumerate()
                .map(|(i, k)| HopInfo {
                    node_pk: k.public,
                    address: {
                        let mut a = [0u8; 32];
                        a[0] = i as u8;
                        a
                    },
                })
                .collect(),
        };

        let packet = construct_packet(msg, &route, &mut rng);
        assert_eq!(packet.header.len(), HEADER_SIZE);
        assert_eq!(packet.payload.len(), PAYLOAD_SIZE);
    }

    #[test]
    fn test_fixed_packet_size() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(43);

        let keys: Vec<KeyPair> = (0..L).map(|_| make_keypair(&mut rng)).collect();
        let route = SphinxRoute {
            hops: keys
                .iter()
                .map(|k| HopInfo {
                    node_pk: k.public,
                    address: [0u8; 32],
                })
                .collect(),
        };

        // Different message sizes should produce same packet size
        for msg_len in [0, 10, 100, 1000, PAYLOAD_SIZE] {
            let msg = vec![0xAB; msg_len];
            let packet = construct_packet(&msg, &route, &mut rng);
            assert_eq!(
                packet.header.len() + packet.payload.len(),
                PACKET_SIZE,
                "Packet size mismatch for message length {}",
                msg_len
            );
        }
    }

    #[test]
    fn test_packet_hash_deterministic() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(44);
        let poseidon = Poseidon::new();

        let keys: Vec<KeyPair> = (0..L).map(|_| make_keypair(&mut rng)).collect();
        let route = SphinxRoute {
            hops: keys
                .iter()
                .map(|k| HopInfo {
                    node_pk: k.public,
                    address: [0u8; 32],
                })
                .collect(),
        };

        let packet = construct_packet(b"test", &route, &mut rng);
        let h1 = packet_hash(&packet, &poseidon);
        let h2 = packet_hash(&packet, &poseidon);
        assert_eq!(h1, h2);
    }
}
