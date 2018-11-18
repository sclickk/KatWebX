// Ui.rs is responsible for creating all server-generated content (error pages, file listings, etc...)
// Most of this should be rewritten before KatWebX's final release.
extern crate actix_web;
extern crate htmlescape;
extern crate number_prefix;
use actix_web::{HttpResponse, AsyncResponder, Error, http::{header, ContentEncoding, StatusCode}};
use futures::future::{Future, result};
use std::{fs, borrow::Borrow};
use self::htmlescape::{encode_minimal, encode_attribute};
use self::number_prefix::{decimal_prefix, Standalone, Prefixed, PrefixNames};

const HEAD: &str = r"<!DOCTYPE HTML><meta content='width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1' name=viewport><style>body *{margin:0;font:300 32px product-sans;color:#404040;text-decoration:none}h1{margin-bottom:8px;font-size:60px}svg{height:60px;position:relative}h1 svg{top:8px;right:5px}a svg{height:32px;top:6px;right:6px}.ok{color:#20b48c;fill:#20b48c}.err{color:#b42020;fill:#b42020}span{color:#828282;font-size:24px}body{margin:40px}.bottom{position:absolute;bottom:32px}@media all and (min-width:900px){.btmright{position:fixed;bottom:32px;right:32px}}.righthov{left:356px;position:absolute;padding-top:8px}@media all and (max-width:440px){.righthov{display:none}}@font-face{font-family:'product-sans';src:url(data:application/font-woff2;charset=utf-8;base64,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) format('woff2')}</style>";

const ERRSVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M11 15h2v2h-2zm0-8h2v6h-2zm1-5a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16z" fill="#b42020"/></svg>"##;

const BACKSVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M11 9l1 1-3 4h9V4h2v12H9l3 4-1 1-6-6 6-6z" fill="#404040"/></svg>"##;

const FILESVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M13.5-4.4H-1.6A2.5 2.5 0 0 0-4.2-2v17.7h2.6V-2h15.1v-2.5zm-1.3 5l7.6 7.6v12.6c0 1.4-1.1 2.5-2.5 2.5H3.4a2.5 2.5 0 0 1-2.5-2.5V3.2C.9 1.8 2 .6 3.4.6h8.8zM11 9.5h7l-7-7v7z"/></svg>"##;

const FOLDERSVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" style="right: 8px"><path d="M20 6h-8l-2-2H4a2 2 0 0 0-2 2v12c0 1.1.9 2 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2zm0 12H4V8h16v10z"/></svg>"##;

pub fn dir_listing(path: &str, trim: &str) -> Box<Future<Item=HttpResponse, Error=Error>> {
	let f;

	match fs::read_dir(path) {
		Ok(fi) => {f = fi},
		Err(_) => {
			return http_error(StatusCode::NOT_FOUND, "404 Not Found", &["The resource ", path, " could not be found."].concat())
		}
	}

	let mut html = [HEAD, "<title>Directory listing of ", &path[trim.len()..], "</title><h1 class=ok>", FOLDERSVG, "Directory listing of ", &path[trim.len()..], "</h1><span style='left: 64px;position: absolute'>Name</span><span class=righthov style='padding-top:0px'>Size</span></br><a href='..'>", BACKSVG, "Back</a></br>"].concat();
	for fpath in f {
		let fstr = fpath.unwrap().path();
		let (name, size, icon);
		match fstr.file_name() {
			Some(fst) => {name = fst.to_string_lossy()},
			None => {
				return http_error(StatusCode::NOT_FOUND, "500 Internal Server Error", "An unexpected condition was encountered.")
			}
		}
		match fstr.metadata() {
			Ok(fmeta) => {
				size = fmeta.len();
				if fmeta.is_dir() {
					icon = FOLDERSVG
				} else {
					icon = FILESVG
				}
			},
			Err(_) => {
				size = 0;
				icon = FILESVG
			}
		}

		let mut sizestr = "".to_owned();
		if icon != FOLDERSVG {
			match decimal_prefix(size as f64) {
				Standalone(bytes)   => {sizestr = [bytes.to_string(), "b".to_owned()].concat()}
				Prefixed(prefix, n) => {sizestr = [&((n*10_f64).round()/10_f64).to_string(), prefix.symbol()].concat()}
			}
		}

		html = [&html, "<a href='", &encode_attribute(fstr.to_string_lossy()[trim.len()..].borrow()), "'>", icon, &encode_minimal(name.borrow()), "<span class=righthov>", &sizestr, "</span></a></br>"].concat()
	}

	html = [html, "<span class=btmright>Powered by KatWebX</span>".to_owned()].concat();

	return result(Ok(
		HttpResponse::Ok()
			.content_encoding(ContentEncoding::Auto)
			.header(header::SERVER, "KatWebX")
			.content_type("text/html; charset=utf-8")
			.body(html)))
			.responder();
}

pub fn http_error(status: StatusCode, header: &str, body: &str) -> Box<Future<Item=HttpResponse, Error=Error>> {
	return result(Ok(
		HttpResponse::Ok()
			.status(status)
			.content_encoding(ContentEncoding::Auto)
			.header(header::SERVER, "KatWebX")
			.content_type("text/html; charset=utf-8")
			.body([HEAD, "<title>", header, "</title><h1 class=err>", ERRSVG, &encode_minimal(header), "</h1><p>", &encode_minimal(body), "</p><span class=bottom>Powered by KatWebX</span>"].concat())))
			.responder();
}
