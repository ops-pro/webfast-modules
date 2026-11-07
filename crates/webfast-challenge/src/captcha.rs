//! The CAPTCHA providers: Cloudflare Turnstile, hCaptcha and reCAPTCHA v2. The page loads the
//! provider's widget (the CSP names its origin), the widget's token comes back as the answer, and
//! the server asks the provider's `siteverify` whether it is good (an HTTPS POST through
//! webfast_core::fetch, 5 s, with the client's address as `remoteip` and nothing else).
//!
//! The providers in use are a process-wide list, filled at configuration time and deduplicated
//! (provider, site key, secret): a nonce names its provider by index, so the answer endpoint, which
//! serves every site, finds the keys that verify it; a reload with the same keys keeps the index.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

/// The verification's timeout, and what it may answer at most.
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ANSWER: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Turnstile,
    Hcaptcha,
    Recaptcha,
}

impl Provider {
    /// The name the directive and the page use.
    pub fn name(self) -> &'static str {
        match self {
            Provider::Turnstile => "turnstile",
            Provider::Hcaptcha => "hcaptcha",
            Provider::Recaptcha => "recaptcha",
        }
    }

    pub fn parse(text: &str) -> Option<Provider> {
        Some(match text {
            "turnstile" => Provider::Turnstile,
            "hcaptcha" => Provider::Hcaptcha,
            "recaptcha" => Provider::Recaptcha,
            _ => return None,
        })
    }

    /// Where the answer is verified.
    pub fn verify_url(self) -> &'static str {
        match self {
            Provider::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Provider::Hcaptcha => "https://api.hcaptcha.com/siteverify",
            Provider::Recaptcha => "https://www.google.com/recaptcha/api/siteverify",
        }
    }

    /// The origins the page may load scripts from, frame and connect to, for the CSP.
    pub fn csp_origins(self) -> &'static str {
        match self {
            Provider::Turnstile => "https://challenges.cloudflare.com",
            Provider::Hcaptcha => "https://js.hcaptcha.com https://*.hcaptcha.com",
            Provider::Recaptcha => "https://www.google.com https://www.gstatic.com https://www.recaptcha.net",
        }
    }
}

/// A provider with a site's keys.
pub struct Captcha {
    pub provider: Provider,
    pub site_key: String,
    secret: String,
}

impl std::fmt::Debug for Captcha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nothing of the secret.
        f.debug_struct("Captcha")
            .field("provider", &self.provider)
            .field("site_key", &self.site_key)
            .finish_non_exhaustive()
    }
}

/// The providers registered, in order of first registration; a nonce's `provider` byte is
/// `index + 1` (0: none).
static REGISTERED: Mutex<Vec<Arc<Captcha>>> = Mutex::new(Vec::new());

/// The verifying client, made at first use (the TLS roots are built in).
static CLIENT: OnceLock<Option<webfast_core::fetch::Client>> = OnceLock::new();

impl Captcha {
    pub fn new(provider: Provider, site_key: String, secret: String) -> Captcha {
        Captcha {
            provider,
            site_key,
            secret,
        }
    }

    /// This provider and keys in the process-wide list: the one registered before with the same
    /// provider, site key and secret, or this one added.
    pub fn register(self) -> Arc<Captcha> {
        let mut list = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = list
            .iter()
            .find(|c| c.provider == self.provider && c.site_key == self.site_key && c.secret == self.secret)
        {
            return found.clone();
        }
        let registered = Arc::new(self);
        list.push(registered.clone());
        registered
    }

    /// The byte a nonce carries for this provider: its index + 1; 0 when it was never registered
    /// (an `Asking` built without `register`), or the list is longer than a byte counts.
    pub fn index(&self) -> u8 {
        let list = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
        list.iter()
            .position(|c| std::ptr::eq(c.as_ref(), self))
            .and_then(|i| u8::try_from(i + 1).ok())
            .unwrap_or(0)
    }

    /// The provider a nonce names.
    pub fn by_index(index: u8) -> Option<Arc<Captcha>> {
        if index == 0 {
            return None;
        }
        let list = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
        list.get(usize::from(index) - 1).cloned()
    }

    /// Asks the provider whether `token` is a good answer from `remote_ip`: `Ok(true)` when it
    /// is, `Ok(false)` when the provider says no, `Err` when the provider could not be asked.
    pub async fn verify(&self, token: &str, remote_ip: std::net::IpAddr) -> anyhow::Result<bool> {
        let client = CLIENT
            .get_or_init(|| webfast_core::fetch::client().ok())
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no HTTPS client for the CAPTCHA verification"))?;
        let uri: http::Uri = self.provider.verify_url().parse()?;
        let form = format!(
            "secret={}&response={}&remoteip={}",
            encode_form(&self.secret),
            encode_form(token),
            remote_ip
        );
        let fetched = webfast_core::fetch::post_form(client, &uri, form, MAX_ANSWER, TIMEOUT).await?;
        if !fetched.status.is_success() {
            anyhow::bail!("{} answered {}", self.provider.name(), fetched.status);
        }
        Ok(success(&fetched.body))
    }
}

/// Whether the provider's JSON says `"success": true`.
fn success(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("success")?.as_bool())
        .unwrap_or(false)
}

/// `application/x-www-form-urlencoded` of one value.
fn encode_form(text: &str) -> String {
    const KEEP: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(text, KEEP).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_are_registered_once_and_found_by_index() {
        let a = Captcha::new(Provider::Turnstile, "k1".into(), "s1".into()).register();
        let again = Captcha::new(Provider::Turnstile, "k1".into(), "s1".into()).register();
        assert!(Arc::ptr_eq(&a, &again), "the same keys: the same entry");
        let b = Captcha::new(Provider::Hcaptcha, "k1".into(), "s1".into()).register();
        assert!(!Arc::ptr_eq(&a, &b));
        assert_ne!(a.index(), 0);
        assert_ne!(a.index(), b.index());
        assert!(Arc::ptr_eq(&Captcha::by_index(a.index()).unwrap(), &a));
        assert!(Captcha::by_index(0).is_none());
        let loose = Captcha::new(Provider::Recaptcha, "k9".into(), "s9".into());
        assert_eq!(loose.index(), 0, "never registered");
        assert_eq!(Provider::parse("turnstile"), Some(Provider::Turnstile));
        assert_eq!(Provider::parse("Turnstile"), None);
        assert!(success(br#"{"success": true, "challenge_ts": "x"}"#));
        assert!(!success(
            br#"{"success": false, "error-codes": ["invalid-input-response"]}"#
        ));
        assert!(!success(b"not json"));
        assert_eq!(encode_form("a b&c=d"), "a%20b%26c%3Dd");
        assert!(!format!("{:?}", a).contains("s1"), "the secret stays out of Debug");
    }
}
