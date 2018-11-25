// Mostly copied from actix-web. Actix Copyright (c) 2017 Nikolay Kim
// Original source: https://github.com/actix/actix-web/blob/v0.7.8/src/fs.rs
#![cfg_attr(feature = "cargo-clippy", allow(pedantic))]
extern crate lazy_static;
extern crate actix_web;
extern crate futures;
extern crate futures_cpupool;
extern crate brotli;

use futures::{Async, Future, Poll, Stream};
use bytes::Bytes;
use std::{io, io::{Error, Seek, Read}, fs::File, cmp, path::Path};
use actix_web::{HttpRequest, http::header};
use self::brotli::{BrotliCompress, enc::encode::BrotliEncoderInitParams};

lazy_static! {
	pub static ref gztypes: Vec<&'static str> = vec!["application/javascript", "application/json", "application/x-javascript", "image/svg+xml", "text/css", "text/csv", "text/html", "text/plain", "text/xml"];
}

pub fn get_compressed_file(path: &str, mime: &str) -> Result<String, Error> {
	if Path::new(&[path, ".br"].concat()).exists() {
		return Ok([path, ".br"].concat())
	}

	if Path::new(&path).exists() && !Path::new(&[&path, ".br"].concat()).exists() && gztypes.binary_search(&&*mime).is_ok() {
		let mut fileold = File::open(path)?;
		let mut filenew = File::create(&[path, ".br"].concat())?;
		let _ = BrotliCompress(&mut fileold, &mut filenew, &BrotliEncoderInitParams())?;
		return Ok([path, ".br"].concat())
	}

	Ok(path.to_string())
}

pub fn calculate_ranges(req: &HttpRequest, length: u64) -> (u64, u64) {
	if let Some(ranges) = req.headers().get(header::RANGE) {
		if let Ok(rangesheader) = ranges.to_str() {
			if let Ok(rangesvec) = HttpRange::parse(rangesheader, length) {
				return (rangesvec[0].length, rangesvec[0].start)
			} else {
				return (length, 0);
			};
		} else {
			return (length, 0);
		};
	};
	(length, 0)
}

#[derive(Debug, Clone, Copy)]
pub struct HttpRange {
    pub start: u64,
    pub length: u64,
}

static PREFIX: &'static str = "bytes=";
const PREFIX_LEN: usize = 6;

impl HttpRange {
    pub fn parse(header: &str, size: u64) -> Result<Vec<Self>, ()> {
        if header.is_empty() {
            return Ok(Vec::new());
        }
        if !header.starts_with(PREFIX) {
            return Err(());
        }

        let size_sig = size as i64;
        let mut no_overlap = false;

        let all_ranges: Vec<Option<Self>> = header[PREFIX_LEN..]
            .split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|ra| {
                let mut start_end_iter = ra.split('-');

                let start_str = start_end_iter.next().ok_or(())?.trim();
                let end_str = start_end_iter.next().ok_or(())?.trim();

                if start_str.is_empty() {
                    let mut length: i64 = try!(end_str.parse().map_err(|_| ()));

                    if length > size_sig {
                        length = size_sig;
                    }

                    Ok(Some(Self {
                        start: (size_sig - length) as u64,
                        length: length as u64,
                    }))
                } else {
                    let start: i64 = start_str.parse().map_err(|_| ())?;

                    if start < 0 {
                        return Err(());
                    }
                    if start >= size_sig {
                        no_overlap = true;
                        return Ok(None);
                    }

                    let length = if end_str.is_empty() {
                        size_sig - start
                    } else {
                        let mut end: i64 = end_str.parse().map_err(|_| ())?;

                        if start > end {
                            return Err(());
                        }

                        if end >= size_sig {
                            end = size_sig - 1;
                        }

                        end - start + 1
                    };

                    Ok(Some(Self {
                        start: start as u64,
                        length: length as u64,
                    }))
                }
            }).collect::<Result<_, _>>()?;

        let ranges: Vec<Self> = all_ranges.into_iter().filter_map(|x| x).collect();

        if no_overlap && ranges.is_empty() {
            return Err(());
        }

        Ok(ranges)
    }
}

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
