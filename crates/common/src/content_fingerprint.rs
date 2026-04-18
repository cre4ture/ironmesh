use anyhow::{Result, anyhow};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const CONTENT_FINGERPRINT_CHUNK_SIZE_BYTES: usize = 1024 * 1024;
const CONTENT_FINGERPRINT_PREFIX: &[u8] = b"ironmesh-content-fingerprint-v1";

#[derive(Debug, Clone)]
pub struct ContentFingerprintBuilder {
    expected_size_bytes: u64,
    total_read_bytes: u64,
    fingerprint_hasher: blake3::Hasher,
    chunk_hasher: blake3::Hasher,
    chunk_size_bytes: usize,
}

impl ContentFingerprintBuilder {
    pub fn new(expected_size_bytes: u64) -> Self {
        Self {
            expected_size_bytes,
            total_read_bytes: 0,
            fingerprint_hasher: seeded_content_fingerprint_hasher(expected_size_bytes),
            chunk_hasher: blake3::Hasher::new(),
            chunk_size_bytes: 0,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
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

    pub fn finish(mut self) -> Result<String> {
        self.finish_chunk();
        if self.total_read_bytes != self.expected_size_bytes {
            return Err(anyhow!(
                "content fingerprint byte count mismatch: expected={} actual={}",
                self.expected_size_bytes,
                self.total_read_bytes
            ));
        }
        Ok(finalize_content_fingerprint(self.fingerprint_hasher))
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

pub struct FingerprintingReader<R> {
    inner: R,
    builder: ContentFingerprintBuilder,
}

impl<R> FingerprintingReader<R> {
    pub fn new(inner: R, expected_size_bytes: u64) -> Self {
        Self {
            inner,
            builder: ContentFingerprintBuilder::new(expected_size_bytes),
        }
    }

    pub fn finish(self) -> Result<String> {
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

pub fn file_content_fingerprint(path: &Path) -> Result<String> {
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

pub fn content_fingerprint_from_chunk_refs<I, S>(total_size_bytes: u64, chunk_refs: I) -> String
where
    I: IntoIterator<Item = (S, u64)>,
    S: AsRef<str>,
{
    let mut hasher = seeded_content_fingerprint_hasher(total_size_bytes);
    for (chunk_hash, chunk_size_bytes) in chunk_refs {
        hasher.update(chunk_hash.as_ref().as_bytes());
        hasher.update(&chunk_size_bytes.to_le_bytes());
    }
    finalize_content_fingerprint(hasher)
}

fn seeded_content_fingerprint_hasher(expected_size_bytes: u64) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTENT_FINGERPRINT_PREFIX);
    hasher.update(&expected_size_bytes.to_le_bytes());
    hasher
}

fn finalize_content_fingerprint(hasher: blake3::Hasher) -> String {
    format!("cfp-{}", hasher.finalize().to_hex())
}

#[cfg(test)]
mod tests {
    use super::{
        ContentFingerprintBuilder, FingerprintingReader, content_fingerprint_from_chunk_refs,
        file_content_fingerprint,
    };
    use anyhow::Result;
    use std::io::{Cursor, Read};

    #[test]
    fn builder_matches_reader_for_large_payload() -> Result<()> {
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
    fn builder_matches_chunk_refs_for_large_payload() -> Result<()> {
        let payload = vec![0x7c; 3 * 1024 * 1024 + 17];

        let mut builder = ContentFingerprintBuilder::new(payload.len() as u64);
        builder.update(&payload);
        let from_builder = builder.finish()?;

        let chunk_refs = payload.chunks(super::CONTENT_FINGERPRINT_CHUNK_SIZE_BYTES).map(|chunk| {
            (blake3::hash(chunk).to_hex().to_string(), chunk.len() as u64)
        });
        let from_chunk_refs = content_fingerprint_from_chunk_refs(payload.len() as u64, chunk_refs);

        assert_eq!(from_builder, from_chunk_refs);
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