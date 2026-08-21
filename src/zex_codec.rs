// Compression codec wrapper around zexc.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use zexc::{compress as zexc_compress, decompress as zexc_decompress, CompressOptions, CompressionMode, StreamDecoder};

pub const MAGIC: &[u8; 4] = b"ZEX1";

pub fn is_zex_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == MAGIC
}

// Compress tar archive bytes into a .zex frame.
pub fn compress(data: &[u8], level: i32) -> io::Result<Vec<u8>> {
    let level = level.clamp(1, 22) as u8;
    let opts = CompressOptions::default()
        .mode(CompressionMode::Balanced)
        .level(level);
    zexc_compress(data, &opts).map_err(|e| io::Error::other(e.to_string()))
}

// Decompress a .zex frame into tar archive bytes.
pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    zexc_decompress(data).map_err(|e| io::Error::other(e.to_string()))
}

// Return a streaming zexc decoder for a reader.
pub fn stream_decoder<R: Read>(reader: R) -> StreamDecoder<R> {
    StreamDecoder::new(reader)
}

// Open a path and return a streaming zexc decoder.
pub fn open_decoder(path: &Path) -> io::Result<StreamDecoder<File>> {
    let file = File::open(path)?;
    Ok(StreamDecoder::new(file))
}


