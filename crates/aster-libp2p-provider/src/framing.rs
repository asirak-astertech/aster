use futures::io::{AsyncRead, AsyncWrite};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

const LENGTH_PREFIX_BYTES: usize = 4;
const MAX_IO_OPS_PER_POLL: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameLimits {
    pub max_frame_bytes: usize,
    pub max_queued_frames: usize,
    pub max_queued_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnqueueError {
    InvalidLength,
    FrameCapacity,
    ByteCapacity,
}

#[derive(Debug)]
pub(crate) enum ReadFrameError {
    CleanEof,
    Truncated,
    InvalidLength(usize),
    Io(io::Error),
}

#[derive(Debug, Default)]
pub(crate) struct FrameReader {
    prefix: [u8; LENGTH_PREFIX_BYTES],
    prefix_read: usize,
    body: Option<Vec<u8>>,
    body_read: usize,
}

impl FrameReader {
    pub(crate) fn clear(&mut self) {
        self.prefix = [0; LENGTH_PREFIX_BYTES];
        self.prefix_read = 0;
        self.body_read = 0;
        self.body.take();
    }

    fn fail(&mut self, error: ReadFrameError) -> Poll<Result<Vec<u8>, ReadFrameError>> {
        self.clear();
        Poll::Ready(Err(error))
    }

    #[cfg(test)]
    pub(crate) fn is_clear(&self) -> bool {
        self.prefix == [0; LENGTH_PREFIX_BYTES]
            && self.prefix_read == 0
            && self.body.is_none()
            && self.body_read == 0
    }

    pub(crate) fn poll_frame<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        cx: &mut Context<'_>,
        max_frame_bytes: usize,
    ) -> Poll<Result<Vec<u8>, ReadFrameError>> {
        let mut operations = 0;
        loop {
            if operations == MAX_IO_OPS_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            operations += 1;

            if self.prefix_read < LENGTH_PREFIX_BYTES {
                let buffer = &mut self.prefix[self.prefix_read..];
                match Pin::new(&mut *stream).poll_read(cx, buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        return self.fail(ReadFrameError::Io(error));
                    }
                    Poll::Ready(Ok(0)) if self.prefix_read == 0 => {
                        return self.fail(ReadFrameError::CleanEof);
                    }
                    Poll::Ready(Ok(0)) => return self.fail(ReadFrameError::Truncated),
                    Poll::Ready(Ok(read)) => self.prefix_read += read,
                }
                if self.prefix_read < LENGTH_PREFIX_BYTES {
                    continue;
                }
                let length = u32::from_be_bytes(self.prefix) as usize;
                if length == 0 || length > max_frame_bytes {
                    return self.fail(ReadFrameError::InvalidLength(length));
                }
                self.body = Some(vec![0; length]);
                self.body_read = 0;
            }

            let body = self.body.as_mut().expect("body allocated after prefix");
            match Pin::new(&mut *stream).poll_read(cx, &mut body[self.body_read..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return self.fail(ReadFrameError::Io(error)),
                Poll::Ready(Ok(0)) => return self.fail(ReadFrameError::Truncated),
                Poll::Ready(Ok(read)) => self.body_read += read,
            }
            if self.body_read == body.len() {
                self.prefix = [0; LENGTH_PREFIX_BYTES];
                self.prefix_read = 0;
                self.body_read = 0;
                let bytes = self.body.take().expect("completed body exists");
                return Poll::Ready(Ok(bytes));
            }
        }
    }
}

#[derive(Debug)]
struct QueuedFrame {
    prefix: [u8; LENGTH_PREFIX_BYTES],
    prefix_written: usize,
    frame: Vec<u8>,
    body_written: usize,
}

#[derive(Debug, Default)]
pub(crate) struct FrameWriter {
    queue: VecDeque<QueuedFrame>,
    queued_bytes: usize,
}

impl FrameWriter {
    pub(crate) fn enqueue(
        &mut self,
        frame: Vec<u8>,
        limits: FrameLimits,
    ) -> Result<(), EnqueueError> {
        if frame.is_empty() || frame.len() > limits.max_frame_bytes {
            return Err(EnqueueError::InvalidLength);
        }
        if self.queue.len() >= limits.max_queued_frames {
            return Err(EnqueueError::FrameCapacity);
        }
        if self.queued_bytes.saturating_add(frame.len()) > limits.max_queued_bytes {
            return Err(EnqueueError::ByteCapacity);
        }
        let length = u32::try_from(frame.len()).map_err(|_| EnqueueError::InvalidLength)?;
        self.queued_bytes += frame.len();
        self.queue.push_back(QueuedFrame {
            prefix: length.to_be_bytes(),
            prefix_written: 0,
            frame,
            body_written: 0,
        });
        Ok(())
    }

    pub(crate) fn poll_write<S: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, io::Error>> {
        let Some(frame) = self.queue.front_mut() else {
            return Poll::Pending;
        };

        let mut operations = 0;
        loop {
            if operations == MAX_IO_OPS_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            operations += 1;

            if frame.prefix_written < LENGTH_PREFIX_BYTES {
                let buffer = &frame.prefix[frame.prefix_written..];
                match Pin::new(&mut *stream).poll_write(cx, buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(written)) => frame.prefix_written += written,
                }
                continue;
            }

            if frame.body_written < frame.frame.len() {
                let buffer = &frame.frame[frame.body_written..];
                match Pin::new(&mut *stream).poll_write(cx, buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(written)) => frame.body_written += written,
                }
                continue;
            }

            match Pin::new(&mut *stream).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let completed = self.queue.pop_front().expect("front frame exists");
                    let bytes = completed.frame.len();
                    self.queued_bytes = self.queued_bytes.saturating_sub(bytes);
                    return Poll::Ready(Ok(bytes));
                }
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.queue.clear();
        self.queued_bytes = 0;
    }

    #[cfg(test)]
    pub(crate) fn queued_frames(&self) -> usize {
        self.queue.len()
    }

    #[cfg(test)]
    pub(crate) fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{io::Cursor, task::noop_waker_ref};

    #[derive(Debug, Default)]
    struct GatedWriter {
        blocked: bool,
        bytes: Vec<u8>,
    }

    impl AsyncWrite for GatedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.get_mut();
            if this.blocked {
                return Poll::Pending;
            }
            this.bytes.extend_from_slice(buffer);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            if self.get_mut().blocked {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    const LIMITS: FrameLimits = FrameLimits {
        max_frame_bytes: 16,
        max_queued_frames: 2,
        max_queued_bytes: 20,
    };

    #[test]
    fn framing_round_trip_is_length_delimited() {
        let mut writer = FrameWriter::default();
        writer.enqueue(vec![1, 2, 3], LIMITS).unwrap();
        let mut encoded = Cursor::new(Vec::new());
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            writer.poll_write(&mut encoded, &mut cx),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(encoded.get_ref(), &[0, 0, 0, 3, 1, 2, 3]);

        encoded.set_position(0);
        let mut reader = FrameReader::default();
        assert!(matches!(
            reader.poll_frame(&mut encoded, &mut cx, LIMITS.max_frame_bytes),
            Poll::Ready(Ok(frame)) if frame == [1, 2, 3]
        ));
    }

    #[test]
    fn oversized_prefix_is_rejected_before_body_allocation() {
        let bytes = 17_u32.to_be_bytes().to_vec();
        let mut input = Cursor::new(bytes);
        let mut reader = FrameReader::default();
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            reader.poll_frame(&mut input, &mut cx, LIMITS.max_frame_bytes),
            Poll::Ready(Err(ReadFrameError::InvalidLength(17)))
        ));
        assert!(reader.body.is_none());
    }

    #[test]
    fn outbound_frame_and_byte_bounds_are_independent() {
        let mut writer = FrameWriter::default();
        writer.enqueue(vec![0; 10], LIMITS).unwrap();
        writer.enqueue(vec![0; 10], LIMITS).unwrap();
        assert_eq!(
            writer.enqueue(vec![1], LIMITS),
            Err(EnqueueError::FrameCapacity)
        );

        let byte_limited = FrameLimits {
            max_queued_frames: 3,
            ..LIMITS
        };
        assert_eq!(
            writer.enqueue(vec![1], byte_limited),
            Err(EnqueueError::ByteCapacity)
        );
    }

    #[test]
    fn blocked_writer_stays_bounded_and_recovers_when_writable() {
        let limits = FrameLimits {
            max_frame_bytes: 16,
            max_queued_frames: 3,
            max_queued_bytes: 20,
        };
        let frame_limited = FrameLimits {
            max_queued_frames: 2,
            max_queued_bytes: 32,
            ..limits
        };
        let mut writer = FrameWriter::default();
        writer.enqueue(vec![1; 10], limits).unwrap();
        writer.enqueue(vec![2; 10], limits).unwrap();
        let mut sink = GatedWriter {
            blocked: true,
            ..GatedWriter::default()
        };
        let mut cx = Context::from_waker(noop_waker_ref());

        assert!(matches!(
            writer.poll_write(&mut sink, &mut cx),
            Poll::Pending
        ));
        assert_eq!(writer.queued_frames(), 2);
        assert_eq!(writer.queued_bytes(), 20);
        assert_eq!(
            writer.enqueue(vec![3], limits),
            Err(EnqueueError::ByteCapacity)
        );
        assert_eq!(
            writer.enqueue(vec![3], frame_limited),
            Err(EnqueueError::FrameCapacity)
        );
        assert_eq!(writer.queued_frames(), 2);
        assert_eq!(writer.queued_bytes(), 20);

        sink.blocked = false;
        assert!(matches!(
            writer.poll_write(&mut sink, &mut cx),
            Poll::Ready(Ok(10))
        ));
        assert_eq!(writer.queued_frames(), 1);
        assert_eq!(writer.queued_bytes(), 10);
        writer.enqueue(vec![3], limits).unwrap();
        assert!(matches!(
            writer.poll_write(&mut sink, &mut cx),
            Poll::Ready(Ok(10))
        ));
        assert!(matches!(
            writer.poll_write(&mut sink, &mut cx),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(writer.queued_frames(), 0);
        assert_eq!(writer.queued_bytes(), 0);
        let mut expected = 10_u32.to_be_bytes().to_vec();
        expected.extend_from_slice(&[1; 10]);
        expected.extend_from_slice(&10_u32.to_be_bytes());
        expected.extend_from_slice(&[2; 10]);
        expected.extend_from_slice(&1_u32.to_be_bytes());
        expected.push(3);
        assert_eq!(sink.bytes, expected);
    }

    #[test]
    fn mid_frame_eof_is_truncated_and_reader_is_reusable() {
        let mut truncated = 5_u32.to_be_bytes().to_vec();
        truncated.extend_from_slice(&[1, 2]);
        let mut input = Cursor::new(truncated);
        let mut reader = FrameReader::default();
        let mut cx = Context::from_waker(noop_waker_ref());

        assert!(matches!(
            reader.poll_frame(&mut input, &mut cx, LIMITS.max_frame_bytes),
            Poll::Ready(Err(ReadFrameError::Truncated))
        ));
        assert!(reader.is_clear());

        let mut valid = 3_u32.to_be_bytes().to_vec();
        valid.extend_from_slice(&[7, 8, 9]);
        let mut input = Cursor::new(valid);
        assert!(matches!(
            reader.poll_frame(&mut input, &mut cx, LIMITS.max_frame_bytes),
            Poll::Ready(Ok(frame)) if frame == [7, 8, 9]
        ));
        assert!(reader.is_clear());
    }
}
