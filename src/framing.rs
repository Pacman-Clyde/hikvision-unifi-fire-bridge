//! Byte-level extraction of `<EventNotificationAlert>...</EventNotificationAlert>`
//! documents from the Hikvision ISAPI multipart alert stream.
//!
//! The stream interleaves multipart boundaries, part headers, and XML
//! documents, and network chunks can split anything anywhere — including in
//! the middle of a UTF-8 character or an XML tag. So this module never
//! decodes text: it scans raw bytes for complete documents and hands them to
//! the XML parser only once whole.

use bytes::{Buf, BytesMut};

const OPEN_TAG: &[u8] = b"<EventNotificationAlert";
const CLOSE_TAG: &[u8] = b"</EventNotificationAlert>";

#[derive(Debug, PartialEq, Eq)]
pub struct BufferOverflow {
    pub buffered: usize,
    pub max: usize,
}

impl std::fmt::Display for BufferOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "frame buffer exceeded safety limit ({} > {} bytes) without a closing tag",
            self.buffered, self.max
        )
    }
}

impl std::error::Error for BufferOverflow {}

pub struct FrameExtractor {
    buf: BytesMut,
    max: usize,
}

impl FrameExtractor {
    pub fn new(max: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(16 * 1024),
            max,
        }
    }

    /// Append a network chunk and return every complete XML document it
    /// completes, in order. Returns an error if the residual buffer exceeds
    /// the safety limit (a closing tag that never arrives must not consume
    /// unbounded memory).
    ///
    /// The chunk is ingested in slices with extraction between them, so even
    /// an adversarially large chunk cannot grow memory much past the limit
    /// before the overflow trips.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, BufferOverflow> {
        const SLICE: usize = 64 * 1024;
        let mut frames = Vec::new();
        for piece in chunk.chunks(SLICE) {
            self.buf.extend_from_slice(piece);
            while let Some(frame) = self.next_frame() {
                frames.push(frame);
            }
            if self.buf.len() > self.max {
                return Err(BufferOverflow {
                    buffered: self.buf.len(),
                    max: self.max,
                });
            }
        }
        Ok(frames)
    }

    fn next_frame(&mut self) -> Option<Vec<u8>> {
        let start = match find(&self.buf, OPEN_TAG) {
            Some(start) => start,
            None => {
                // No opening tag: discard noise (multipart boundaries, part
                // headers) but keep enough tail bytes to recognise an opening
                // tag split across chunks.
                let retain = OPEN_TAG.len() - 1;
                if self.buf.len() > retain {
                    let discard = self.buf.len() - retain;
                    self.buf.advance(discard);
                }
                return None;
            }
        };
        if start > 0 {
            self.buf.advance(start);
        }
        let end = find(&self.buf, CLOSE_TAG)?;
        Some(self.buf.split_to(end + CLOSE_TAG.len()).to_vec())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &[u8] =
        b"<EventNotificationAlert><eventType>fireDetection</eventType></EventNotificationAlert>";

    fn extractor() -> FrameExtractor {
        FrameExtractor::new(1024)
    }

    #[test]
    fn whole_document_in_one_chunk() {
        let frames = extractor().push(DOC).unwrap();
        assert_eq!(frames, vec![DOC.to_vec()]);
    }

    #[test]
    fn document_surrounded_by_multipart_noise() {
        let mut input = Vec::new();
        input.extend_from_slice(b"--boundary\r\nContent-Type: application/xml\r\n\r\n");
        input.extend_from_slice(DOC);
        input.extend_from_slice(b"\r\n--boundary\r\n");
        let frames = extractor().push(&input).unwrap();
        assert_eq!(frames, vec![DOC.to_vec()]);
    }

    #[test]
    fn document_split_across_many_chunks() {
        let mut ex = extractor();
        let mut collected = Vec::new();
        // Split at every 7 bytes: guaranteed to split tags mid-way.
        for chunk in DOC.chunks(7) {
            collected.extend(ex.push(chunk).unwrap());
        }
        assert_eq!(collected, vec![DOC.to_vec()]);
    }

    #[test]
    fn open_tag_split_exactly_across_a_noise_boundary() {
        let mut ex = extractor();
        // Noise then half an opening tag; the tail must be retained.
        assert!(ex.push(b"noise noise <EventNotifica").unwrap().is_empty());
        let frames = ex.push(b"tionAlert>x</EventNotificationAlert>").unwrap();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].starts_with(OPEN_TAG));
        assert!(frames[0].ends_with(CLOSE_TAG));
    }

    #[test]
    fn multiple_documents_in_one_chunk() {
        let mut input = DOC.to_vec();
        input.extend_from_slice(b"\r\n--b\r\n");
        input.extend_from_slice(DOC);
        let frames = extractor().push(&input).unwrap();
        assert_eq!(frames.len(), 2);
    }

    #[test]
    fn pure_noise_is_discarded_and_does_not_accumulate() {
        let mut ex = FrameExtractor::new(64);
        for _ in 0..100 {
            // 100 x 32 bytes of noise would overflow a 64-byte cap if kept.
            assert!(
                ex.push(b"0123456789abcdef0123456789abcdef")
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn missing_close_tag_overflows_instead_of_growing_forever() {
        let mut ex = FrameExtractor::new(64);
        ex.push(b"<EventNotificationAlert>").unwrap();
        let err = ex
            .push(&[b'x'; 128])
            .expect_err("an unterminated document must trip the safety limit");
        assert!(err.buffered > err.max);
    }

    #[test]
    fn open_tag_with_attributes_is_recognised() {
        let doc = b"<EventNotificationAlert version=\"2.0\" \
                    xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\
                    <eventType>fireDetection</eventType></EventNotificationAlert>";
        let frames = extractor().push(doc).unwrap();
        assert_eq!(frames, vec![doc.to_vec()]);
    }
}
