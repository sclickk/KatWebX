// Ui.rs is responsible for creating all server-generated content (error pages, file listings, etc...)
// Most of this should be rewritten before KatWebX's final release.
extern crate actix_web;
extern crate htmlescape;
extern crate number_prefix;
use actix_web::{HttpResponse, AsyncResponder, Error, http::StatusCode};
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

		let mut sizestr = "".to_string();
		if icon != FOLDERSVG {
			match decimal_prefix(size as f64) {
				Standalone(bytes)   => {sizestr = [bytes.to_string(), "b".to_string()].concat()}
				Prefixed(prefix, n) => {sizestr = [&((n*10_f64).round()/10_f64).to_string(), prefix.symbol()].concat()}
			}
		}

		html = [&html, "<a href='", &encode_attribute(fstr.to_string_lossy()[trim.len()..].borrow()), "'>", icon, &encode_minimal(name.borrow()), "<span class=righthov>", &sizestr, "</span></a></br>"].concat()
	}

	html = [html, "<span class=btmright>Powered by KatWebX</span>".to_string()].concat();

	return result(Ok(
		HttpResponse::Ok()
			.content_type("text/html; charset=utf-8")
			.body(html)))
			.responder();
}

pub fn http_error(status: StatusCode, header: &str, body: &str) -> Box<Future<Item=HttpResponse, Error=Error>> {
	return result(Ok(
		HttpResponse::Ok()
			.status(status)
			.content_type("text/html; charset=utf-8")
			.body([HEAD, "<title>", header, "</title><h1 class=err>", ERRSVG, &encode_minimal(header), "</h1><p>", &encode_minimal(body), "</p><span class=bottom>Powered by KatWebX</span>"].concat())))
			.responder();
}
