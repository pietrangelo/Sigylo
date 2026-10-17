//! The terms of service and the privacy notice live on the public site: the
//! shell opens them in the system browser, so a secret open in the app keeps
//! its view. Only these two fixed addresses can ever be opened.

pub fn page_url(page: &str) -> Option<&'static str> {
    match page {
        "terms" => Some("https://sigylo.net/#/terms"),
        "privacy" => Some("https://sigylo.net/#/privacy"),
        _ => None,
    }
}
