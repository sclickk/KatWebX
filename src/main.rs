extern crate bytes;
extern crate futures;
extern crate actix_web;
extern crate openssl;
extern crate mime;
extern crate mime_guess;
extern crate mime_sniffer;
use actix_web::{middleware, server, App, HttpRequest, HttpResponse, AsyncResponder, Error, http::StatusCode};
use openssl::ssl::{SslMethod, SslAcceptor, SslFiletype};
use futures::future::{Future, result};
use std::{cmp, fs::File, io::Read};
use mime_sniffer::MimeTypeSniffer;

fn read_file(path: &str) -> Result<Vec<u8>, Error> {
	let mut f = File::open(path)?;
	let mut buffer = Vec::new();
	f.read_to_end(&mut buffer)?;

	return Ok(buffer)
}

fn index(_req: &HttpRequest) -> Box<Future<Item=HttpResponse, Error=Error>> {
	let mut pathd = [_req.path()].concat();
	if pathd.ends_with("/") {
		pathd = [pathd, "index.html".to_string()].concat();
	}
	let path = &pathd;
	println!("{}", path);

	let hosthead = _req.headers().get("host");
	let mut host = "html";
	if !hosthead.is_none() {
		host = hosthead.unwrap().to_str().unwrap()
	}
	println!("{:?}",host);
	if host == "ssl" || host.len() < 1 || host[0..1] == ".".to_string() || host.contains("/") || host.contains("\\") | host.contains("¥") {
		host = "html"
	}
	println!("{:?}",host);

	if path.contains("..") {
		return result(Ok(
			HttpResponse::Ok()
				.status(StatusCode::FORBIDDEN)
				.content_type("text/plain")
				.body("403 Forbidden")))
				.responder();
	}

	let f = read_file(&("html".to_owned() + path)).unwrap_or("404".as_bytes().to_vec());
	if f == "404".as_bytes() {
		return result(Ok(
			HttpResponse::Ok()
				.status(StatusCode::NOT_FOUND)
				.content_type("text/plain")
				.body("404 Not Found")))
				.responder();
	}

	let mut mime = mime_guess::guess_mime_type(path).to_string();
	if mime == "application/octet-stream" {
		let mreq = mime_sniffer::HttpRequest {
			content: &f[0..cmp::min(512, f.len())].to_vec(),
			url: &["http://localhost", path].concat(),
			type_hint: "unknown/unknown",
		};

		mime = mreq.sniff_mime_type().unwrap_or("text/plain; charset=utf-8").to_string();
	}
	if mime == "unknown/unknown" {
		mime = "application/octet-stream".to_string()
	}
	if mime.starts_with("text/") && !mime.contains("charset") {
		mime = [mime, "; charset=utf-8".to_string()].concat();
	}
	println!("{:?}",mime);

	result(Ok(
		HttpResponse::Ok()
	        .content_type(mime)
            .body(f)))
        	.responder()
}

fn main() {
	let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
	/*builder.set_cipher_list(
		"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:\
		ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    ).unwrap();
	builder.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
	builder.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256").unwrap();*/
	builder.set_private_key_file("ssl/key.pem", SslFiletype::PEM).unwrap();
	builder.set_certificate_chain_file("ssl/cert.pem").unwrap();

    server::new(|| {
        vec![
			App::new()
				.middleware(
					middleware::DefaultHeaders::new()
						.header("Cache-Control", "max-age=14400, public, stale-while-revalidate=3600")
						.header("Referrer-Policy", "no-referrer")
						.header("X-Content-Type-Options", "nosniff")
						.header("Content-Security-Policy", "default-src https: data: 'unsafe-inline' 'unsafe-eval' 'self'; frame-ancestors 'self'")
						.header("X-XSS-Protection", "1; mode=block")
						.header("Server", "KatWebX-Alpha"))
				.default_resource(|r| r.f(index))
		]
	})
		.keep_alive(120)
		.shutdown_timeout(30)
		.bind_ssl("[::]:8181", builder)
        .unwrap()
		.bind("[::]:8080")
		.unwrap()
        .run();
}
