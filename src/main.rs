#[macro_use]
extern crate lazy_static;
extern crate bytes;
extern crate futures;
extern crate actix_web;
extern crate openssl;
extern crate mime;
extern crate mime_guess;
extern crate mime_sniffer;
extern crate json;
use actix_web::{server, server::ServerFlags, App, HttpRequest, HttpResponse, AsyncResponder, Error, Body, http::StatusCode, server::OpensslAcceptor};
use openssl::ssl::{SslMethod, SslAcceptor, SslFiletype};
use futures::future::{Future, result};
use bytes::Bytes;
use futures::stream::once;
use std::{process, cmp, fs, fs::File, io::Read, path::Path};
use mime_sniffer::MimeTypeSniffer;

fn read_file(path: &str) -> Result<Vec<u8>, Error> {
	let mut f = File::open(path)?;
	let mut buffer = Vec::new();
	f.read_to_end(&mut buffer)?;

	return Ok(buffer)
}

fn get_mime(data: &Vec<u8>, path: &str) -> String {
	let mut mime = mime_guess::guess_mime_type(path).to_string();
	if mime == "application/octet-stream" {
		let mreq = mime_sniffer::HttpRequest {
			content: data,
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

	return mime
}

lazy_static! {
	static ref confraw: String = fs::read_to_string("conf.json").unwrap_or("{\"cachingTimeout\": 4,\"streamTimeout\": 10,\"hide\": [\"src\"],\"advanced\": {\"protect\": true,\"httpPort\": 80,\"tlsPort\": 443}}".to_string());
	static ref config: json::JsonValue<> = json::parse(&confraw).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to parse configuration!");
		process::exit(1);
	});
}

fn index(_req: &HttpRequest) -> Box<Future<Item=HttpResponse, Error=Error>> {
	let mut pathd = [_req.path()].concat();
	if pathd.ends_with("/") {
		pathd = [pathd, "index.html".to_string()].concat();
	}
	let path = &pathd;

	let conn_info = _req.connection_info();
	let mut host = conn_info.host();
	if host == "ssl" || host.len() < 1 || host[0..1] == ".".to_string() || host.contains("/") || host.contains("\\") || config["hide"].contains(host) {
		host = "html"
	}
	println!("{:?}",[host, path].concat());
	if !Path::new(host).exists() {
		host = "html"
	}

	if path.contains("..") {
		return result(Ok(
			HttpResponse::Ok()
				.status(StatusCode::FORBIDDEN)
				.content_type("text/plain")
				.body("403 Forbidden")))
				.responder();
	}

	let f = read_file(&[host, path].concat()).unwrap_or("404".as_bytes().to_vec());
	if f == "404".as_bytes() {
		return result(Ok(
			HttpResponse::Ok()
				.status(StatusCode::NOT_FOUND)
				.content_type("text/plain")
				.body("404 Not Found")))
				.responder();
	}

	let sniffer_data = &f[0..cmp::min(512, f.len())].to_vec();
	let body = once(Ok(Bytes::from(f)));
	let cache_int = config["cachingTimeout"].as_i64().unwrap_or(0);
	result(Ok(
		HttpResponse::Ok()
	        .content_type(get_mime(sniffer_data, &[host, path].concat()))
			.if_true(cache_int == 0, |builder| {
				builder.header("Cache-Control", "no-store, must-revalidate");
			})
			.if_true(cache_int != 0, |builder| {
				builder.header("Cache-Control", ["max-age=".to_string(), (cache_int*3600).to_string(), ", public, stale-while-revalidate=".to_string(), (cache_int*900).to_string()].concat());
			})
			.if_true(config["advanced"]["protect"].as_bool().unwrap_or(false), |builder| {
				builder.header("Referrer-Policy", "no-referrer");
				builder.header("X-Content-Type-Options", "nosniff");
				builder.header("Content-Security-Policy", "default-src https: data: 'unsafe-inline' 'unsafe-eval' 'self'; frame-ancestors 'self'");
				builder.header("X-XSS-Protection", "1; mode=block");
			})
			.header("Server", "KatWebX-Alpha")
            .body(Body::Streaming(Box::new(body)))))
        	.responder()
}

fn main() {
	fs::write("conf.json", config.pretty(2)).unwrap_or_else(|_err| {
		println!("[Warn]: Unable to write configuration!");
	});

	let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to create OpenSSL builder!");
		process::exit(1);
	});
	builder.set_private_key_file("ssl/key.pem", SslFiletype::PEM).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to load ssl/key.pem!");
		process::exit(1);
	});
	builder.set_certificate_chain_file("ssl/cert.pem").unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to load ssl/cert.pem!");
		process::exit(1);
	});
	let acceptor = OpensslAcceptor::with_flags(builder, ServerFlags::HTTP1 | ServerFlags::HTTP2).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to create OpenSSL acceptor!");
		process::exit(1);
	});

    server::new(|| {
        vec![
			App::new()
				.default_resource(|r| r.f(index))
		]
	})
		.keep_alive(config["streamTimeout"].as_usize().unwrap_or(0)*4)
		.shutdown_timeout(config["streamTimeout"].as_u16().unwrap_or(10))
		.bind_with(["[::]:".to_string(), config["advanced"]["tlsPort"].as_u16().unwrap_or(443).to_string()].concat(), acceptor)
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to port ".to_string(), config["advanced"]["tlsPort"].as_u16().unwrap_or(443).to_string(), "!".to_string()].concat());
			process::exit(1);
		})
		.bind(["[::]:".to_string(), config["advanced"]["httpPort"].as_u16().unwrap_or(80).to_string()].concat())
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to port ".to_string(), config["advanced"]["httpPort"].as_u16().unwrap_or(80).to_string(), "!".to_string()].concat());
			process::exit(1);
		})
        .run();
}
