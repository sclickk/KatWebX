#[macro_use]
extern crate lazy_static;
extern crate futures;
extern crate actix;
extern crate actix_web;
extern crate rustls;
extern crate mime;
extern crate mime_guess;
extern crate mime_sniffer;
extern crate json;
extern crate regex;
extern crate bytes;
mod stream;
mod ui;
use actix_web::{actix::{Addr, Actor}, server, server::{RustlsAcceptor, ServerFlags}, client, client::ClientConnector, App, http::{header, header::{HeaderValue, HeaderMap}, Method, ContentEncoding, StatusCode}, HttpRequest, HttpResponse, HttpMessage, AsyncResponder, Error, dev::Payload};
use futures::future::{Future, result};
use std::{process, cmp, fs, fs::File, path::Path, io::Read, io::BufReader, collections::HashMap, time::Duration};
use mime_sniffer::MimeTypeSniffer;
use regex::{Regex, NoExpand, RegexSet};
use rustls::{NoClientAuth, ServerConfig, internal::pemfile::{certs, rsa_private_keys}};

// The default configuration for the server to use.
const DEFAULT_CONFIG: &str = r#"{"cachingTimeout":4,"streamTimeout":20,"hsts":false,"proxy":[{"location":"proxy.local","host":"https://kittyhacker101.tk"},{"location":"r#localhost\/proxy[0-9]","host":"https://kittyhacker101.tk"}],"redir":[{"location":"localhost/redir","dest":"https://kittyhacker101.tk"},{"location":"r#localhost/redir2.*","dest":"https://google.com"}],"hide":["src", "r#tar.*"],"advanced":{"protect":true,"compressfiles":true,"httpAddr":"[::]:80","tlsAddr":"[::]:443"}}"#;

// Generate the correct host and path, from raw data.
// Hidden hosts can be virtual-host based (hidden.local) or regex-based.
// Redirects can be either full path based (localhost/redir) or regex-based.
// Reverse proxying can be either virtual-host based (proxy.local) or regex-based.
fn handle_path(mut path: String, mut host: String) -> (String, String, Option<String>) {
	host = trim_port(host);
	let fp = &[host.to_owned(), path.to_owned()].concat();
	match path {
		_ if path.ends_with("/index.html") => return ("./".to_owned(), "redir".to_owned(), None),
		_ if path.contains("..") => return ("..".to_owned(), "redir".to_owned(), None),
		_ if path.ends_with("/") => path.push_str("index.html"),
		_ => (),
	}

	match host {
	 	_ if host.len() < 1 || host[..1] == ".".to_owned() || host.contains("/") || host.contains("\\") => host = "html".to_owned(),
		_ if lredir.binary_search(fp).is_ok() => {
			match redirmap.get(fp) {
				Some(link) => return (link.to_string(), "redir".to_owned(), None),
				None => (),
			};
		},
		_ if lproxy.binary_search(&host).is_ok() => {
			match proxymap.get(&host) {
				Some(link) => return ([link.to_string(), trim_suffix("index.html".to_owned(), path)].concat(), "proxy".to_owned(), None),
				None => (),
			};
		},
		_ if redirx.is_match(fp) => {
			let mut r = "$x";
			match redirx.matches(fp).iter().next() {
				Some(regx) => r = &lredirx[regx],
				None => (),
			}
			match redirmap.get(&["r#", r].concat()) {
				Some(link) => return ([link.to_string(), trim_regex(r, &fp)].concat(), "redir".to_owned(), None),
				None => (),
			};
		},
		_ if proxyx.is_match(fp) => {
			let mut r = "$x";
			match proxyx.matches(fp).iter().next() {
				Some(regx) => r = &lproxyx[regx],
				None => (),
			}
			match proxymap.get(&["r#", r].concat()) {
				Some(link) => return ([link.to_string(), trim_regex(r, &fp)].concat(), "proxy".to_owned(), None),
				None => (),
			};
		},
		_ if hidden.binary_search(&host.to_owned()).is_ok() => host = "html".to_owned(),
		_ if hiddenx.is_match(&host.to_owned()) => host = "html".to_owned(),
		_ if !Path::new(&host).exists() => host = "html".to_owned(),
		_ => (),
	};

	let full_path = &[&*host, &*path].concat();
	return (path, host, Some(full_path.to_string()))
}

// Reverse proxy a request, passing through any compression.
// This cannot proxy websockets, because it removes the "Connection" HTTP header.
// Hop-by-hop headers are removed, to allow connection reuse.
fn proxy_request(path: String, method: Method, headers: &HeaderMap, body: Payload, mut client_ip: String) -> Box<Future<Item=HttpResponse, Error=Error>> {
	let re = client::ClientRequest::build()
		.with_connector(clientconn.clone())
		.uri(path).method(method).disable_decompress()
		.if_true(true, |req| {
			for (key, value) in headers.iter() {
				match key.to_owned().as_str() {
					"Connection" | "Proxy-Connection" | "Keep-Alive" | "Proxy-Authenticate" | "Proxy-Authorization" | "Te" | "Trailer" | "Transfer-Encoding" | "Upgrade" => (),
					"X-Forwarded-For" => client_ip = [value.to_owned().to_str().unwrap_or("127.0.0.1"), ", ", &client_ip].concat(),
					_ => {
						req.header(key.to_owned(), value.to_owned());
						continue
					},
				};
			}
			req.header("X-Forwarded-For", client_ip);
		})
		.set_header_if_none(header::ACCEPT_ENCODING, "none")
		.set_header_if_none(header::USER_AGENT, "KatWebX-Proxy")
		.streaming(body);

	let req;
	match re {
		Ok(r) => req = r,
		Err(_) => return ui::http_error(StatusCode::BAD_GATEWAY, "502 Bad Gateway", "The server was acting as a proxy and received an invalid response from the upstream server."),
	}

	return req.send().and_then(|resp| {
			Ok(HttpResponse::Ok()
				.status(resp.status())
				.if_true(true, |req| {
					for (key, value) in resp.headers().iter() {
						if key == header::CONTENT_LENGTH {
							continue
						}
						if key == header::CONTENT_ENCODING {
							// We don't want the data to be compressed more than once.
							req.content_encoding(ContentEncoding::Identity);
						}
						req.header(key.to_owned(), value.to_owned());
					}

					match resp.cookies() {
						Ok(c) => {for ck in c.iter() {
							req.cookie(ck.to_owned());
						}},
						Err(_) => (),
					}
				})
				.streaming(resp.payload()))
		}).or_else(|_| {
			return ui::http_error(StatusCode::BAD_GATEWAY, "502 Bad Gateway", "The server was acting as a proxy and received an invalid response from the upstream server.")
		}).responder();
}

// Trim the port from an IPv4 address, IPv6 address, or domain:port.
fn trim_port(path: String) -> String {
	if path.contains("[") && path.contains("]") {
		match path.rfind("]:") {
			Some(i) => return path[..i+1].to_string(),
			None => return path,
		}
	}

	match path.rfind(":") {
		Some(i) => return path[..i].to_string(),
		None => return path,
	}
}

// Trim the host from an IPv4 address, IPv6 address, or domain:port.
fn trim_host(path: String) -> String {
	if path.contains("[") && path.contains("]") {
		match path.rfind("]:") {
			Some(i) => return path[i+1..].to_string(),
			None => return "".to_owned(),
		}
	}

	match path.rfind(":") {
		Some(i) => return path[i..].to_string(),
		None => return "".to_owned(),
	}
}

// Trim a substring (prefix) from the beginning of a string.
fn trim_prefix(prefix: String, root: String) -> String {
	match root.find(&*prefix) {
		Some(i) => return root[i+prefix.len()..].to_string(),
		None => return root,
	}
}

// Trim a substring (suffix) from the end of a string.
fn trim_suffix(suffix: String, root: String) -> String {
	match root.rfind(&*suffix) {
		Some(i) => return root[..i].to_string(),
		None => return root,
	}
}

// Use regex to trim a string.
fn trim_regex(regex: &str, root: &str) -> String {
	let r = Regex::new(regex).unwrap_or(Regex::new("$x").unwrap());
	return r.replace_all(&root, NoExpand("")).to_string();
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
			.content_encoding(ContentEncoding::Auto)
			.header(header::LOCATION, path)
			.header(header::SERVER, "KatWebX")
			.content_type("text/html; charset=utf-8")
			.body(["<a href='", path, "'>If this redirect does not work, click here</a>"].concat())))
			.responder();
}

// Return a MIME type based on file extension.
// If the file extension is not known, attempt to guess the mime type.
fn get_mime(path: &str) -> String {
	let mut mime = mime_guess::guess_mime_type(path).to_string();
	if mime == "application/octet-stream" {
		let (mut f, finfo);
		match open_meta(path) {
			Ok((fi, m)) => {f = fi; finfo = m},
			Err(_) => {
				return mime
			}
		}

		let mut sniffer_data = vec![0; cmp::min(512, finfo.len() as usize)];
		f.read_exact(&mut sniffer_data).unwrap_or(());

		let mreq = mime_sniffer::HttpRequest {
			content: &sniffer_data,
			url: &["http://localhost", path].concat(),
			type_hint: "",
		};

		mime = mreq.sniff_mime_type().unwrap_or("").to_string();
	}
	if mime.starts_with("text/") && !mime.contains("charset") {
		return [mime, "; charset=utf-8".to_owned()].concat();
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
	return tmp
}

// Turn a JSON array into a HashMap<String, String>.
fn map_json(array: &json::Array, attr1: &str, attr2: &str) -> HashMap<String, String> {
	let mut tmp = HashMap::new();
	for item in array {
		tmp.insert(item[attr1].as_str().unwrap_or("").to_string(), item[attr2].as_str().unwrap_or("").to_string());
	}
	return tmp
}

// Turn a JSON array into a Vec<String>, only adding items which contain regex.
// All regex strings must start with r#, so that the program knows they are regex. The r# will be trimmed from the string before the regex is parsed.
fn array_json_regex(array: &json::Array, attr: &str) -> Vec<String> {
	let mut tmp = Vec::new();
	for item in array {
		let itemt;
		if attr == "" {
			itemt = item.as_str().unwrap_or("").to_string();
		} else {
		 	itemt = item[attr].as_str().unwrap_or("").to_string();
		}
		if itemt.starts_with("r#") {
			tmp.push(trim_prefix("r#".to_owned(), itemt))
		}
	}
	tmp.sort_unstable();
	return tmp
}

// Turn a JSON array into parsed regex.
fn parse_json_regex(array: &json::Array, attr: &str) -> Result<RegexSet, regex::Error> {
	return RegexSet::new(&array_json_regex(array, attr));
}

// Global constants generated at runtime.
lazy_static! {
	static ref confraw: String = fs::read_to_string("conf.json").unwrap_or(DEFAULT_CONFIG.to_owned());
	static ref config: json::JsonValue<> = json::parse(&confraw).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to parse configuration!");
		process::exit(1);
	});
	static ref hidden: Vec<String> = match &config["hide"] {
		json::JsonValue::Array(array) => {
			let mut tmp = sort_json(array, "");
			tmp.push("ssl".to_owned());
			tmp.push("redir".to_owned());
			tmp.sort_unstable();
			return tmp;
		},
		_ => Vec::new(),
	};
	static ref hiddenx: RegexSet = match &config["hide"] {
		json::JsonValue::Array(array) => parse_json_regex(array, "").unwrap_or(RegexSet::new(&["$x"]).unwrap()),
		_ => RegexSet::new(&["$x"]).unwrap(),
	};
	static ref lredir: Vec<String> = match &config["redir"] {
		json::JsonValue::Array(array) => sort_json(array, "location"),
		_ => Vec::new(),
	};
	static ref lredirx: Vec<String> = match &config["redir"] {
		json::JsonValue::Array(array) => array_json_regex(array, "location"),
		_ => Vec::new(),
	};
	static ref redirmap: HashMap<String, String> = match &config["redir"] {
		json::JsonValue::Array(array) => map_json(array, "location", "dest"),
		_ => HashMap::new(),
	};
	static ref redirx: RegexSet =  RegexSet::new(lredirx.iter()).unwrap_or(RegexSet::new(&["$x"]).unwrap());
	static ref lproxy: Vec<String> = match &config["proxy"] {
		json::JsonValue::Array(array) => sort_json(array, "location"),
		_ => Vec::new(),
	};
	static ref lproxyx: Vec<String> = match &config["proxy"] {
		json::JsonValue::Array(array) => array_json_regex(array, "location"),
		_ => Vec::new(),
	};
	static ref proxymap: HashMap<String, String> = match &config["proxy"] {
		json::JsonValue::Array(array) => map_json(array, "location", "host"),
		_ => HashMap::new(),
	};
	static ref proxyx: RegexSet =  RegexSet::new(lproxyx.iter()).unwrap_or(RegexSet::new(&["$x"]).unwrap());
	static ref blankheader: HeaderValue = HeaderValue::from_static("");
	static ref clientconn: Addr<ClientConnector> = {
		ClientConnector::default()
			.conn_lifetime(Duration::from_secs(config["streamTimeout"].as_u64().unwrap_or(20)*4))
			.conn_keep_alive(Duration::from_secs(config["streamTimeout"].as_u64().unwrap_or(20)*4))
			.start()
	};
}

// HTTP(S) request handling.
fn index(_req: &HttpRequest) -> Box<Future<Item=HttpResponse, Error=Error>> {
	let conn_info = _req.connection_info();

	if config["hsts"].as_bool().unwrap_or(false) && conn_info.scheme() == "http" {
		let mut host = trim_port(conn_info.host().to_string());
		let tls_host = config["advanced"]["tlsAddr"].as_str().unwrap_or("[::]:443");
		if trim_host(tls_host.to_string()) != ":443" {
			host = host + &trim_host(tls_host.to_string()).to_string();
		}
		return redir(&["https://".to_string(), host, _req.path().to_string()].concat());
	}

	let (path, host, fp) = handle_path(_req.path().to_string(), conn_info.host().to_string());
	//println!("{:?}", [trim_port(conn_info.host().to_string()), _req.path().to_string()].concat());

	if host == "redir" {
		if path == "forbid" {
			return ui::http_error(StatusCode::FORBIDDEN, "403 Forbidden", "You do not have permission to access this resource.")
		}
		return redir(&path);
	}

	if host == "proxy" {
		return proxy_request(path, _req.method().to_owned(), _req.headers(), _req.payload(), conn_info.remote().unwrap_or("127.0.0.1").to_string())
	}

	if _req.method() != Method::GET && _req.method() != Method::HEAD {
		return ui::http_error(StatusCode::METHOD_NOT_ALLOWED, "405 Method Not Allowed", "Only GET and HEAD methods are supported.")
	}

	let mut full_path = match fp {
		Some(pf) => pf,
		None => [&*host, &*path].concat(),
	};

	let mime = get_mime(&full_path);
	let mim = trim_suffix("; charset=utf-8".to_string(), mime.to_string());

	// If the client accepts a brotli compressed response, then modify full_path to send one.
	let be = &HeaderValue::from_static("");
	let ce = _req.headers().get(header::ACCEPT_ENCODING).unwrap_or(be).to_str().unwrap_or("");
	if ce.contains("br") {
		if config["advanced"]["compressfiles"].as_bool().unwrap_or(false) {
			match stream::get_compressed_file(&*full_path, mim) {
				Ok(path) => full_path = path,
				Err(_) => (),
			}
		} else {
			if Path::new(&[&full_path, ".br"].concat()).exists() {
				full_path = [&full_path, ".br"].concat()
			}
		}
	}

	// Open the file specified in full_path. If the file is not present, serve either a directory listing or an error.
	let (f, finfo);
	match open_meta(&full_path) {
		Ok((fi, m)) => {f = fi; finfo = m},
		Err(_) => {
			if path.ends_with("/index.html") {
				return ui::dir_listing(&[&*host, _req.path()].concat(), &host)
			}

			return ui::http_error(StatusCode::NOT_FOUND, "404 Not Found", &["The resource ", _req.path(), " could not be found."].concat());
		}
	}

	if finfo.is_dir() {
		return redir(&[_req.path(), "/"].concat());
	}

	// Parse a ranges header if it is present, and then turn a File into a stream.
	let (length, offset) = stream::calculate_ranges(_req, finfo.len());
	let reader = stream::ChunkedReadFile {
		offset: offset,
		size: length,
		cpu_pool: _req.cpu_pool().clone(),
		file: Some(f),
		fut: None,
		counter: 0,
	};

	// Craft a response.
	let cache_int = config["cachingTimeout"].as_i64().unwrap_or(0);
	result(Ok(
		HttpResponse::Ok()
	        .content_type(&*mime)
			.header(header::ACCEPT_RANGES, "bytes")
			.if_true(full_path.ends_with(".br"), |builder| {
				builder.header(header::CONTENT_ENCODING, "br");
				builder.content_encoding(ContentEncoding::Identity);
			})
			.if_true(!full_path.ends_with(".br") && stream::gztypes.binary_search(&&*mime).is_ok(), |builder| {
				builder.content_encoding(ContentEncoding::Auto);
			})
			.if_true(offset != 0, |builder| {
				builder.header(header::CONTENT_RANGE, ["bytes ", &offset.to_string(), "-", &(offset+length-1).to_string(), "/", &finfo.len().to_string()].concat());
			})
			.if_true(cache_int == 0, |builder| {
				builder.header(header::CACHE_CONTROL, "no-store, must-revalidate");
			})
			.if_true(cache_int != 0, |builder| {
				builder.header(header::CACHE_CONTROL, ["max-age=".to_owned(), (cache_int*3600).to_string(), ", public, stale-while-revalidate=".to_owned(), (cache_int*900).to_string()].concat());
			})
			.if_true(config["hsts"].as_bool().unwrap_or(false), |builder| {
				builder.header(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000;includeSubDomains;preload");
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
	println!("[Info]: Starting KatWebX...");
	let sys = actix::System::new("katwebx");
	lazy_static::initialize(&hidden);
	lazy_static::initialize(&hiddenx);
	lazy_static::initialize(&lredir);
	lazy_static::initialize(&redirmap);
	lazy_static::initialize(&redirx);
	lazy_static::initialize(&lproxy);
	lazy_static::initialize(&proxymap);
	lazy_static::initialize(&proxyx);
	lazy_static::initialize(&clientconn);

	fs::write("conf.json", config.pretty(2)).unwrap_or_else(|_err| {
		println!("[Warn]: Unable to write configuration!");
	});

	let mut tconfig = ServerConfig::new(NoClientAuth::new());
	let cert_file = &mut BufReader::new(File::open("ssl/cert.pem").unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to load ssl/cert.pem!");
		process::exit(1);
	}));
	let key_file = &mut BufReader::new(File::open("ssl/key.pem").unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to load ssl/key.pem!");
		process::exit(1);
	}));
	let cert_chain = certs(cert_file).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to parse tls certificates!");
		process::exit(1);
	});
	let mut keys = rsa_private_keys(key_file).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to parse private key!");
		process::exit(1);
	});
	tconfig.set_single_cert(cert_chain, keys.remove(0)).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to parse private key!");
		process::exit(1);
	});
	let acceptor = RustlsAcceptor::with_flags(
		tconfig,
		ServerFlags::HTTP1 | ServerFlags::HTTP2,
	);

	// HTTPS request handling
    server::new(|| {
		App::new()
			.default_resource(|r| r.f(index))
	})
		.keep_alive(config["streamTimeout"].as_usize().unwrap_or(20))
		.bind_with(config["advanced"]["tlsAddr"].as_str().unwrap_or("[::]:443"), move || acceptor.clone())
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to ".to_owned(), config["advanced"]["tlsAddr"].as_str().unwrap_or("[::]:443").to_string(), "!".to_owned()].concat());
			process::exit(1);
		})
        .start();

	// HTTP request handling
	server::new(|| {
		App::new()
			.default_resource(|r| r.f(index))
	})
		.keep_alive(config["streamTimeout"].as_usize().unwrap_or(20))
		.bind(config["advanced"]["httpAddr"].as_str().unwrap_or("[::]:80"))
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to ".to_owned(), config["advanced"]["httpAddr"].as_str().unwrap_or("[::]:80").to_string(), "!".to_owned()].concat());
			process::exit(1);
		})
	    .start();

	println!("[Info]: Started KatWebX.");
	let _ = sys.run();
}

// Unit tests for critical internal functions.
// WARNING: The config.json file must have default values when running these tests.
#[cfg(test)]
mod tests {
	use *;
	#[test]
	fn test_trim_port() {
		assert_eq!(trim_port("127.0.0.1:8080".to_owned()), "127.0.0.1");
		assert_eq!(trim_port("127.0.0.1".to_owned()), "127.0.0.1");
		assert_eq!(trim_port("[::1]:8081".to_owned()), "[::1]");
		assert_eq!(trim_port("[::1]".to_owned()), "[::1]");
	}
	#[test]
	fn test_trim_host() {
		assert_eq!(trim_host("127.0.0.1:8080".to_owned()), ":8080");
		assert_eq!(trim_host("127.0.0.1".to_owned()), "");
		assert_eq!(trim_host("[::1]:8081".to_owned()), ":8081");
		assert_eq!(trim_host("[::1]".to_owned()), "");
	}
	#[test]
	fn test_trim_prefix() {
		assert_eq!(trim_prefix("str".to_owned(), "string".to_owned()), "ing");
		assert_eq!(trim_prefix("no".to_owned(), "string".to_owned()), "string");
		assert_eq!(trim_prefix("ing".to_owned(), "string".to_owned()), "");
	}
	#[test]
	fn test_trim_suffix() {
		assert_eq!(trim_suffix("ing".to_owned(), "string".to_owned()), "str");
		assert_eq!(trim_suffix("no".to_owned(), "string".to_owned()), "string");
		assert_eq!(trim_suffix("str".to_owned(), "string".to_owned()), "");
	}
	#[test]
	fn test_handle_path_base() {
		assert_eq!(handle_path("/index.html".to_owned(), "localhost".to_owned()), ("./".to_owned(), "redir".to_owned(), None));
		assert_eq!(handle_path("/test/..".to_owned(), "localhost".to_owned()), ("..".to_owned(), "redir".to_owned(), None));

		assert_eq!(handle_path("/".to_owned(), "H".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(handle_path("/".to_owned(), "...".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(handle_path("/".to_owned(), "/home".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(handle_path("/".to_owned(), "C:\\".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));

		assert_eq!(handle_path("/".to_owned(), "ssl".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(handle_path("/".to_owned(), "nonexistenthost".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
	}
	#[test]
	fn test_handle_path_routing() {
		assert_eq!(handle_path("/redir".to_owned(), "localhost".to_owned()), ("https://kittyhacker101.tk".to_owned(), "redir".to_owned(), None));
		assert_eq!(handle_path("/redir2a".to_owned(), "localhost".to_owned()), ("https://google.com".to_owned(), "redir".to_owned(), None));

		assert_eq!(handle_path("/links.html".to_owned(), "proxy.local".to_owned()), ("https://kittyhacker101.tk/links.html".to_owned(), "proxy".to_owned(), None));
		assert_eq!(handle_path("/proxy0/links.html".to_owned(), "localhost".to_owned()), ("https://kittyhacker101.tk/links.html".to_owned(), "proxy".to_owned(), None));

		assert_eq!(handle_path("/".to_owned(), "src".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(handle_path("/".to_owned(), "target".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(handle_path("/".to_owned(), "html".to_owned()), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));

	}
}
