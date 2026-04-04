#![cfg(windows)]

use anyhow::{Result, anyhow};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const CONTENT_FINGERPRINT_CHUNK_SIZE_BYTES: usize = 1024 * 1024;
const CONTENT_FINGERPRINT_PREFIX: &[u8] = b"ironmesh-content-fingerprint-v1";

#[derive(Debug, Clone)]
pub(crate) struct ContentFingerprintBuilder {
    expected_size_bytes: u64,
    total_read_bytes: u64,
    fingerprint_hasher: blake3::Hasher,
    chunk_hasher: blake3::Hasher,
    chunk_size_bytes: usize,
}

impl ContentFingerprintBuilder {
    pub(crate) fn new(expected_size_bytes: u64) -> Self {
        let mut fingerprint_hasher = blake3::Hasher::new();
        fingerprint_hasher.update(CONTENT_FINGERPRINT_PREFIX);
        fingerprint_hasher.update(&expected_size_bytes.to_le_bytes());
        Self {
            expected_size_bytes,
            total_read_bytes: 0,
            fingerprint_hasher,
            chunk_hasher: blake3::Hasher::new(),
            chunk_size_bytes: 0,
        }
    }

    pub(crate) fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let remaining_in_chunk =
                CONTENT_FINGERPRINT_CHUNK_SIZE_BYTES.saturating_sub(self.chunk_size_bytes);
            let take = remaining_in_chunk.min(bytes.len());
            let (head, tail) = bytes.split_at(take);
            self.chunk_hasher.update(head);
            self.chunk_size_bytes += head.len();
            self.total_read_bytes = self.total_read_bytes.saturating_add(head.len() as u64);
            if self.chunk_size_bytes == CONTENT_FINGERPRINT_CHUNK_SIZE_BYTES {
                self.finish_chunk();
            }
            bytes = tail;
        }
    }

    pub(crate) fn finish(mut self) -> Result<String> {
        self.finish_chunk();
        if self.total_read_bytes != self.expected_size_bytes {
            return Err(anyhow!(
                "content fingerprint byte count mismatch: expected={} actual={}",
                self.expected_size_bytes,
                self.total_read_bytes
            ));
        }
        Ok(format!(
            "cfp-{}",
            self.fingerprint_hasher.finalize().to_hex()
        ))
    }

    fn finish_chunk(&mut self) {
        if self.chunk_size_bytes == 0 {
            return;
        }

        let chunk_hash = self.chunk_hasher.finalize();
        self.fingerprint_hasher
            .update(chunk_hash.to_hex().as_str().as_bytes());
        self.fingerprint_hasher
            .update(&(self.chunk_size_bytes as u64).to_le_bytes());
        self.chunk_hasher = blake3::Hasher::new();
        self.chunk_size_bytes = 0;
    }
}

pub(crate) struct FingerprintingReader<R> {
    inner: R,
    builder: ContentFingerprintBuilder,
}

impl<R> FingerprintingReader<R> {
    pub(crate) fn new(inner: R, expected_size_bytes: u64) -> Self {
        Self {
            inner,
            builder: ContentFingerprintBuilder::new(expected_size_bytes),
        }
    }

    pub(crate) fn finish(self) -> Result<String> {
        self.builder.finish()
    }
}

impl<R: Read> Read for FingerprintingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.builder.update(&buf[..read]);
        Ok(read)
    }
}

pub(crate) fn file_content_fingerprint(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let expected_size_bytes = file.metadata()?.len();
    let mut builder = ContentFingerprintBuilder::new(expected_size_bytes);
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        builder.update(&buffer[..read]);
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::{ContentFingerprintBuilder, FingerprintingReader, file_content_fingerprint};
    use anyhow::Result;
    use std::io::{Cursor, Read};

    #[test]
    fn builder_matches_streaming_reader_for_large_payload() -> Result<()> {
        let payload = vec![0x5a; 2 * 1024 * 1024 + 123];

        let mut builder = ContentFingerprintBuilder::new(payload.len() as u64);
        builder.update(&payload);
        let from_builder = builder.finish()?;

        let mut reader =
            FingerprintingReader::new(Cursor::new(payload.clone()), payload.len() as u64);
        let mut sink = Vec::new();
        reader.read_to_end(&mut sink)?;
        let from_reader = reader.finish()?;

        assert_eq!(sink, payload);
        assert_eq!(from_builder, from_reader);
        Ok(())
    }

    #[test]
    fn file_fingerprint_matches_reader_fingerprint() -> Result<()> {
        let payload = format!(
            "{}{}",
            "A".repeat(1024 * 1024 + 37),
            "\ncontent-fingerprint"
        );
        let path = std::env::temp_dir().join(format!(
            "ironmesh-content-fingerprint-{}.bin",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, payload.as_bytes())?;

        let mut reader =
            FingerprintingReader::new(Cursor::new(payload.as_bytes()), payload.len() as u64);
        let mut sink = Vec::new();
        reader.read_to_end(&mut sink)?;
        let from_reader = reader.finish()?;
        let from_file = file_content_fingerprint(&path)?;

        assert_eq!(from_reader, from_file);

        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
