use crate::error::Result;
use crate::zex_codec;

/// Default zexc compression level.
///
/// Kept below 15: zexc's optimal-parse path (`zexc::algorithms::optimal`,
/// used at level >= 15) has no run-length guard and is O(n^2) on long runs
/// of repeated bytes — common in ELF binaries (padding/BSS/alignment).
/// A ~300MB gcc payload at level 19 pegged 4 cores for 50+ minutes without
/// finishing. Level 12 stays on the greedy/lazy parser, which doesn't have
/// this blowup. Revisit once zexc gets an RLE short-circuit in optimal.rs.
pub const DEFAULT_LEVEL: i32 = 12;

/// Compress tar bytes into a native `.zex` (zexc / ZEX1) frame.
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    Ok(zex_codec::compress(data, level)?)
}

/// Decompress a native `.zex` (zexc / ZEX1) frame back to tar bytes.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zex_codec::decompress(data)?)
}
