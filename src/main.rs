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
mod stream;
mod ui;
use actix_web::{server, App, HttpRequest, HttpResponse, AsyncResponder, Error, http::StatusCode, http::header, http::Method, http::header::HeaderValue, http::ContentEncoding};
use openssl::ssl::{SslMethod, SslAcceptor, SslFiletype};
use futures::future::{Future, result};
use std::{process, cmp, fs, fs::File, path::Path, io::Read, collections::HashMap};
use mime_sniffer::MimeTypeSniffer;

// Generate the correct host and path, from the raw data.
fn handle_path(mut path: String, mut host: String) -> (String, String, Option<String>) {
	host = trim_port(host);


	match path {
		_ if path.ends_with("/index.html") => return ("./".to_owned(), "redir".to_owned(), None),
		_ if path.contains("..") => return ("..".to_owned(), "redir".to_owned(), None),
		_ if path.ends_with("/") => path.push_str("index.html"),
		_ => (),
	}

	let fp = &[&*host, &*path].concat();

	println!("{:?}", fp);

	match host {
	 	_ if host.len() < 1 || host[..1] == ".".to_owned() || host.contains("/") || host.contains("\\") => host = "html".to_string(),
		_ if hidden.binary_search(&host.to_owned()).is_ok() => host = "html".to_string(),
		_ if lredir.binary_search(fp).is_ok() => {
			match redirmap.get(fp) {
				Some(link) => return (link.to_string(), "redir".to_string(), None),
				None => (),
			};
		},
		_ if lproxy.binary_search(fp).is_ok() => {
			match proxymap.get(fp) {
				Some(link) => return (link.to_string(), "proxy".to_string(), None),
				None => (),
			};
		},
		_ if !Path::new(&host).exists() => host = "html".to_string(),
		_ => (),
	}

	let full_path = &[&*host, &*path].concat();

	return (path, host, Some(full_path.to_string()))
}

// Trim the port from an IPv4 address, IPv6 address, or domain:port.
fn trim_port(path: String) -> String {
	if path.contains("[") && path.contains("]:") {
		match path.rfind("]:") {
			Some(i) => return path[0..i+1].to_string(),
			None => return path,
		}
	}

	match path.rfind(":") {
		Some(i) => return path[0..i].to_string(),
		None => return path,
	}
}

// Open both a file, and the file's metadata.
fn open_meta(path: &str) -> Result<(fs::File, fs::Metadata), Error> {
	let f = File::open(path)?;
	let m =  f.metadata()?;
	return Ok((f, m));
}

// Do a HTTP permanent redirect.
fn redir(path: &str) -> Box<Future<Item=HttpResponse, Error=Error>> {
	return result(Ok(
		HttpResponse::Ok()
			.status(StatusCode::PERMANENT_REDIRECT)
			.header(header::LOCATION, path)
			.content_type("text/html; charset=utf-8")
			.body(["<a href='", path, "'>Click here</a>"].concat())))
			.responder();
}

// Guess the MIME type based on file extension. If the file extension is not known, attempt to guess the mime type.
fn get_mime(data: &Vec<u8>, path: &str) -> String {
	let mut mime = mime_guess::guess_mime_type(path).to_string();
	if mime == "application/octet-stream" {
		let mreq = mime_sniffer::HttpRequest {
			content: data,
			url: &["http://localhost", path].concat(),
			type_hint: "",
		};

		mime = mreq.sniff_mime_type().unwrap_or("").to_string();
	}
	if mime.starts_with("text/") && !mime.contains("charset") {
		return [mime, "; charset=utf-8".to_string()].concat();
	}

	return mime
}

// Turn a JSON array into a sorted Vec<String>.
fn sort_json(array: &json::Array, attr: &str) -> Vec<String> {
	let mut tmp = Vec::new();
	for item in array {
		if attr == "" {
			tmp.push(item.as_str().unwrap_or("").to_string())
		} else {
			tmp.push(item[attr].as_str().unwrap_or("").to_string())
		}
	}
	tmp.sort_unstable();
	println!("{:?}", tmp);
	return tmp
}

// Turn a JSON array into a HashMap<String, String>.
fn map_json(array: &json::Array, attr1: &str, attr2: &str) -> HashMap<String, String> {
	let mut tmp = HashMap::new();
	for item in array {
		tmp.insert(item[attr1].as_str().unwrap_or("").to_string(), item[attr2].as_str().unwrap_or("").to_string());
	}
	println!("{:?}", tmp);
	return tmp
}

// Global constants generated at runtime.
lazy_static! {
	static ref confraw: String = fs::read_to_string("conf.json").unwrap_or(r#"{"cachingTimeout":4,"proxy":[{"location":"localhost/proxy","host":"https://kittyhacker101.tk"}],"redir":[{"location":"localhost/redir","dest":"https://kittyhacker101.tk"}],"hide":["src"],"advanced":{"protect":true,"httpAddr":"[::]:80","tlsAddr":"[::]:443"}}"#.to_string());
	static ref config: json::JsonValue<> = json::parse(&confraw).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to parse configuration!");
		process::exit(1);
	});
	static ref hidden: Vec<String> = match &config["hide"] {
		json::JsonValue::Array(array) => {
			let mut tmp = sort_json(array, "");
			tmp.push("ssl".to_string());
			tmp.push("redir".to_string());
			tmp.sort_unstable();
			return tmp;
		},
		_ => Vec::new(),
	};
	static ref lredir: Vec<String> = match &config["redir"] {
		json::JsonValue::Array(array) => sort_json(array, "location"),
		_ => Vec::new(),
	};
	static ref redirmap: HashMap<String, String> = match &config["redir"] {
		json::JsonValue::Array(array) => map_json(array, "location", "dest"),
		_ => HashMap::new(),
	};
	static ref lproxy: Vec<String> = match &config["proxy"] {
		json::JsonValue::Array(array) => sort_json(array, "location"),
		_ => Vec::new(),
	};
	static ref proxymap: HashMap<String, String> = match &config["proxy"] {
		json::JsonValue::Array(array) => map_json(array, "location", "host"),
		_ => HashMap::new(),
	};
	static ref blankheader: HeaderValue = HeaderValue::from_static("");
}

// HTTP(S) request handling.
fn index(_req: &HttpRequest) -> Box<Future<Item=HttpResponse, Error=Error>> {
	let conn_info = _req.connection_info();

	let (path, host, fp) = handle_path(_req.path().to_string(), conn_info.host().to_string());

	if _req.method() != Method::GET && _req.method() != Method::HEAD {
		return ui::http_error(StatusCode::METHOD_NOT_ALLOWED, "405 Method Not Allowed", "Only GET and HEAD methods are supported.")
	}

	if host == "redir" {
		if path == "forbid" {
			return ui::http_error(StatusCode::FORBIDDEN, "403 Forbidden", "You do not have permission to access this resource.")
		}
		return redir(&path);
	}
	if host == "proxy" {
		return redir(&path);
	}

	let full_path = match fp {
		Some(pf) => pf,
		None => [&*host, &*path].concat(),
	};

	let (mut f, finfo);

	match open_meta(&full_path) {
		Ok((fi, m)) => {f = fi; finfo = m},
		Err(_) => {
			if path.ends_with("/index.html") {
				return ui::dir_listing(&[&*host, _req.path()].concat(), &host)
			}

			return ui::http_error(StatusCode::NOT_FOUND, "404 Not Found", &["The resource ", _req.path(), " could not be found."].concat())
		}
	}

	if finfo.is_dir() {
		return redir(&[_req.path(), "/"].concat());
	}

	let mut sniffer_data = vec![0; cmp::min(512, finfo.len() as usize)];
	f.read_exact(&mut sniffer_data).unwrap_or(());

	let (length, offset) = stream::calculate_ranges(_req, finfo.len());

	let reader = stream::ChunkedReadFile {
		offset: offset,
		size: length,
		cpu_pool: _req.cpu_pool().clone(),
		file: Some(f),
		fut: None,
		counter: 0,
	};

	let cache_int = config["cachingTimeout"].as_i64().unwrap_or(0);
	result(Ok(
		HttpResponse::Ok()
	        .content_type(get_mime(&sniffer_data, &full_path))
			.header(header::ACCEPT_RANGES, "bytes")
			.content_encoding(ContentEncoding::Identity)
			.if_true(offset != 0, |builder| {
				builder.header(header::CONTENT_RANGE, ["bytes ", &offset.to_string(), "-", &(offset+length-1).to_string(), "/", &finfo.len().to_string()].concat());
			})
			.if_true(cache_int == 0, |builder| {
				builder.header(header::CACHE_CONTROL, "no-store, must-revalidate");
			})
			.if_true(cache_int != 0, |builder| {
				builder.header(header::CACHE_CONTROL, ["max-age=".to_string(), (cache_int*3600).to_string(), ", public, stale-while-revalidate=".to_string(), (cache_int*900).to_string()].concat());
			})
			.if_true(config["advanced"]["protect"].as_bool().unwrap_or(false), |builder| {
				builder.header(header::REFERRER_POLICY, "no-referrer");
				builder.header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
				builder.header(header::CONTENT_SECURITY_POLICY, "default-src https: data: 'unsafe-inline' 'unsafe-eval' 'self'; frame-ancestors 'self'");
				builder.header(header::X_XSS_PROTECTION, "1; mode=block");
			})
			.header(header::SERVER, "KatWebX-Alpha")
            .streaming(reader)))
        	.responder()
}

// Load configuration, SSL certs, then attempt to start the program.
fn main() {
	lazy_static::initialize(&hidden);
	lazy_static::initialize(&lredir);
	lazy_static::initialize(&redirmap);
	lazy_static::initialize(&lproxy);
	lazy_static::initialize(&proxymap);

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

    server::new(|| {
        vec![
			App::new()
				.default_resource(|r| r.f(index))
		]
	})
		.keep_alive(15)
		.bind_ssl(config["advanced"]["tlsAddr"].as_str().unwrap_or("[::]:443"), builder)
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to ".to_string(), config["advanced"]["tlsAddr"].as_str().unwrap_or("[::]:443").to_string(), "!".to_string()].concat());
			process::exit(1);
		})
		.bind(config["advanced"]["httpAddr"].as_str().unwrap_or("[::]:80"))
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to ".to_string(), config["advanced"]["httpAddr"].as_str().unwrap_or("[::]:80").to_string(), "!".to_string()].concat());
			process::exit(1);
		})
        .run();
}
