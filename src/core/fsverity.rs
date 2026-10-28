//! fs-verity file digests (SHA-256, 4096-byte blocks, no salt) — the same value the kernel
//! reports with FS_IOC_MEASURE_VERITY once fs-verity is on for the installed file. The
//! manifest lists them per file, so an installed base file can be checked against its package.

use sha2::{Digest, Sha256};

const BLOCK: usize = 4096;
const HASH: usize = 32;

fn sha256(data: &[u8]) -> [u8; HASH] {
    let mut out = [0u8; HASH];
    out.copy_from_slice(Sha256::digest(data).as_slice());
    out
}

/// Root hash of the Merkle tree: all zeroes for an empty file, the hash of the single
/// zero-padded block for a one-block file, otherwise hashes of hashes up to one block.
fn root_hash(data: &[u8]) -> [u8; HASH] {
    if data.is_empty() {
        return [0; HASH];
    }
    let mut block = [0u8; BLOCK];
    let mut level: Vec<[u8; HASH]> = data
        .chunks(BLOCK)
        .map(|c| {
            block.fill(0);
            block[..c.len()].copy_from_slice(c);
            sha256(&block)
        })
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(BLOCK / HASH)
            .map(|hs| {
                block.fill(0);
                for (i, h) in hs.iter().enumerate() {
                    block[i * HASH..(i + 1) * HASH].copy_from_slice(h);
                }
                sha256(&block)
            })
            .collect();
    }
    level[0]
}

/// The fs-verity file digest: SHA-256 of the 256-byte fsverity_descriptor.
pub fn digest(data: &[u8]) -> [u8; HASH] {
    let mut desc = [0u8; 256];
    desc[0] = 1; // version
    desc[1] = 1; // FS_VERITY_HASH_ALG_SHA256
    desc[2] = 12; // log2(4096)
    desc[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
    desc[16..16 + HASH].copy_from_slice(&root_hash(data));
    sha256(&desc)
}

pub fn digest_hex(data: &[u8]) -> String {
    digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::digest_hex;

    /// Bytes `i % 251` — the same files were measured by the kernel (btrfs, FS_IOC_MEASURE_VERITY).
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn matches_kernel() {
        for (size, want) in KERNEL_VECTORS {
            assert_eq!(digest_hex(&pattern(*size)), *want, "size {size}");
        }
    }

    const KERNEL_VECTORS: &[(usize, &str)] = &[
        (0, "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95"),
        (1, "b803429503d95915829b29fdbc8bbad142f3abfd11b1cadf5526582e685c0551"),
        (4095, "5f4953aad672b0188023d6cd6fbce9d09508eb7dad165b6298ce0086bc1e72db"),
        (4096, "13e9b8848ae484a36acb3f3cac0ceb2f7601e96633d15c92f9bd3dd44e492157"),
        (4097, "b0d074abef4d544404facfab6ba242f6a8ccbde90f1325cd286f3c8aa8d0f8aa"),
        (524288, "d82861203d50ae9b60948504a704f35f5118bd229aeb1a22d6dae47b1767c4c4"),
        (524289, "4dc6905041c9c4ee73e13b53f63f5d289c46da359b664a965ead7f8cc4d799d4"),
        (300000, "9ba81fdc4f8dfd3b0d13b883f7f73f07e6c0c006c6ef81a3bc024508c8a57e3f"),
    ];
}
