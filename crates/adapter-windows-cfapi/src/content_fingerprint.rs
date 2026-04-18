#![cfg(windows)]

#[cfg(test)]
pub(crate) use common::content_fingerprint::ContentFingerprintBuilder;
pub(crate) use common::content_fingerprint::{FingerprintingReader, file_content_fingerprint};

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
