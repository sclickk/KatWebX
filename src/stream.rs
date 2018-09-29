// Copied from actix-web::fs, with minor modifications.
// Original source: https://actix.rs/api/actix-web/stable/src/actix_web/fs.rs.html#485-534
extern crate futures;
extern crate futures_cpupool;
extern crate actix_web;

use futures::{Async, Future, Poll, Stream};
use bytes::Bytes;
use std::{io, io::Seek, fs::File, cmp, io::Read};

pub struct ChunkedReadFile {
    pub size: u64,
    pub offset: u64,
    pub cpu_pool: futures_cpupool::CpuPool,
    pub file: Option<File>,
    pub fut: Option<futures_cpupool::CpuFuture<(File, Bytes), io::Error>>,
    pub counter: u64,
}

impl Stream for ChunkedReadFile {
    type Item = Bytes;
    type Error = actix_web::Error;

    fn poll(&mut self) -> Poll<Option<Bytes>, actix_web::Error> {
        if self.fut.is_some() {
            return match self.fut.as_mut().unwrap().poll()? {
                Async::Ready((file, bytes)) => {
                    self.fut.take();
                    self.file = Some(file);
                    self.offset += bytes.len() as u64;
                    self.counter += bytes.len() as u64;
                    Ok(Async::Ready(Some(bytes)))
                }
                Async::NotReady => Ok(Async::NotReady),
            };
        }

        let size = self.size;
        let offset = self.offset;
        let counter = self.counter;

        if size == counter {
            Ok(Async::Ready(None))
        } else {
            let mut file = self.file.take().expect("Use after completion");
            self.fut = Some(self.cpu_pool.spawn_fn(move || {
                let max_bytes: usize;
                max_bytes = cmp::min(size.saturating_sub(counter), 65_536) as usize;
                let mut buf = Vec::with_capacity(max_bytes);
                file.seek(io::SeekFrom::Start(offset))?;
                let nbytes = file.by_ref().take(max_bytes as u64).read_to_end(&mut buf)?;
                if nbytes == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                Ok((file, Bytes::from(buf)))
            }));
            self.poll()
        }
    }
}
