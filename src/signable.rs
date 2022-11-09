use anyhow::Result;
use lazy_regex::*;
use regex::{Captures, Regex};
use sha2::{Digest, Sha512};
use std::borrow::Cow;
use urlencoding::{decode, encode};

pub static SQUEEZE_REGEX: Lazy<Regex> = lazy_regex!(r"//+");
pub static PERCENT_CASE_REGEX: Lazy<Regex> = lazy_regex!(r"%[a-f0-9]{2}");
pub static SINGLE_DOT_REGEX: Lazy<Regex> = lazy_regex!(r"/(\./)+");
pub static DOUBLE_DOT_REGEX: Lazy<Regex> = lazy_regex!(r"(/[^/]+|\A)/\.\./?");

pub(crate) struct Signable<'a> {
    verb: String,
    path: String,
    query: String,
    body: &'a [u8],
    timestamp: String,
    app_uuid: String,
}

impl<'a> Signable<'a> {
    pub fn new(
        verb: impl Into<String>,
        path: impl Into<String>,
        query: impl Into<String>,
        body: &'a [u8],
        timestamp: impl Into<String>,
        app_uuid: impl Into<String>,
    ) -> Self {
        Self {
            verb: verb.into(),
            path: path.into(),
            query: query.into(),
            body,
            timestamp: timestamp.into(),
            app_uuid: app_uuid.into(),
        }
    }

    pub fn signing_string_v1(&self) -> Result<Vec<u8>> {
        let mut hasher = Sha512::default();

        hasher.update(&self.verb);
        hasher.update("\n");
        hasher.update(&self.path);
        hasher.update("\n");
        hasher.update(&self.body);
        hasher.update("\n");
        hasher.update(&self.app_uuid);
        hasher.update("\n");
        hasher.update(&self.timestamp);

        Ok(hex::encode(hasher.finalize()).into_bytes())
    }

    pub fn signing_string_v2(&self) -> Result<Vec<u8>> {
        let encoded_query: String = Self::encode_query(&self.query)?;
        let body_digest = hex::encode(Sha512::digest(self.body));

        Ok(format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.verb,
            Self::normalize_url(&self.path),
            body_digest,
            &self.app_uuid,
            &self.timestamp,
            &encoded_query
        )
        .into_bytes())
    }

    fn encode_query(qstr: &str) -> Result<String> {
        if qstr.is_empty() {
            return Ok("".to_string());
        }
        let mut temp_param_list = qstr
            .split('&')
            .map(Self::split_equal_and_decode)
            .collect::<Result<Vec<[String; 2]>>>()?;

        temp_param_list.sort();

        Ok(temp_param_list
            .iter()
            .map(|part| [encode(&part[0]), encode(&part[1])].join("="))
            .collect::<Vec<String>>()
            .join("&"))
    }

    fn normalize_url(url: &str) -> Cow<str> {
        if url.contains("//") || url.contains('%') || url.contains("/.") {
            let url = SQUEEZE_REGEX.replace_all(url, "/");
            let url = PERCENT_CASE_REGEX.replace_all(&url, |c: &Captures| c[0].to_uppercase());
            let url = SINGLE_DOT_REGEX.replace_all(&url, "/");

            Cow::from(Self::normalize_double_dot(url))
        } else {
            Cow::Borrowed(url)
        }
    }

    fn normalize_double_dot(url: Cow<str>) -> String {
        let new_url = DOUBLE_DOT_REGEX.replace(&url, "/");
        match new_url == url {
            true => new_url.to_string(),
            false => Self::normalize_double_dot(new_url),
        }
    }

    fn split_equal_and_decode(value: &str) -> Result<[String; 2]> {
        let (k, v) = value.split_once('=').unwrap_or((value, ""));
        Ok([
            Self::replace_plus_and_decode(k)?,
            Self::replace_plus_and_decode(v)?,
        ])
    }

    fn replace_plus_and_decode(value: &str) -> Result<String> {
        Ok(decode(&value.replace('+', " "))?.into_owned())
    }
}
