use crate::error::Result;
use crate::zex_codec;

// Default zexc compression level.
pub const DEFAULT_LEVEL: i32 = 12;

// Compress tar bytes into a native .zex frame.
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    Ok(zex_codec::compress(data, level)?)
}

// Decompress a native .zex frame back to tar bytes.

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zex_codec::decompress(data)?)
}
