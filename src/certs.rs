extern crate rustls;
extern crate webpki;
use std::{collections, fs::File, io::BufReader, sync::Arc};
use rustls::{sign, ResolvesServerCert, SignatureScheme, sign::{any_supported_type, CertifiedKey}, internal::pemfile::{certs, pkcs8_private_keys}};

#[derive(Clone)]
pub struct ResolveCert {
    by_name: collections::HashMap<String, sign::CertifiedKey>,
	cert_folder: String,
}

impl ResolveCert {
    pub fn new(folder: String) -> Self {
        Self { cert_folder: folder, by_name: collections::HashMap::new() }
    }

	pub fn load(&mut self, name: String) -> Result<(), String> {
		let pre = &[self.clone().cert_folder, name.to_owned()].concat();
		let (mut cert_file, mut key_file, cert_chain, mut keys, key);

		if let Ok(f) = File::open([pre, ".crt"].concat()) {
			cert_file = BufReader::new(f);
		} else {
			return Err(["Unable to open ", pre, ".crt!"].concat())
		}

		if let Ok(f) = File::open([pre, ".pem"].concat()) {
			key_file = BufReader::new(f);
		} else {
			return Err(["Unable to open ", pre, ".pem!"].concat())
		}

		if let Ok(c) = certs(&mut cert_file) {
			cert_chain = c;
		} else {
			return Err(["Unable to parse ", pre, ".crt!"].concat())
		}

		if let Ok(k) = pkcs8_private_keys(&mut key_file) {
			keys = k;
		} else {
			return Err(["Unable to parse ", pre, ".pem!"].concat())
		}

		if keys.is_empty() {
			return Err([pre, ".pem contains no valid pkcs8 keys!\n\nNote: You can convert your keyfile into pkcs8 using the command below.\nopenssl pkcs8 -topk8 -nocrypt -in oldkey.pem -out newkey.pem"].concat())
		}

		if let Ok(k) = any_supported_type(&keys.remove(0)) {
			key = k;
		} else {
			return Err(["Unable to parse ", pre, ".pem!"].concat())
		}

		self.by_name.insert(name, CertifiedKey::new(cert_chain, Arc::new(key)));
		Ok(())
	}
}

impl ResolvesServerCert for ResolveCert {
    fn resolve(&self,
            server_name: Option<webpki::DNSNameRef>,
            _sigschemes: &[SignatureScheme])
            -> Option<sign::CertifiedKey> {
        if let Some(name) = server_name {
            self.by_name.get(name.into()).cloned()
        } else {
			self.by_name.get("default").cloned()
        }
    }
}
