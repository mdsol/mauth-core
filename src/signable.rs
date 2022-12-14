use anyhow::Result;
use lazy_regex::*;
use regex::{Captures, Regex};
use sha2::{Digest, Sha512};
use std::borrow::Cow;
use urlencoding::{decode, encode};

pub static SQUEEZE_REGEX: Lazy<Regex> = lazy_regex!(r"//+");
pub static PERCENT_CASE_REGEX: Lazy<Regex> = lazy_regex!(r"%[a-f0-9]{2}");
pub static SINGLE_DOT_REGEX: Lazy<Regex> = lazy_regex!(r"/(\./|\.\z)+");
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
        hasher.update(self.body);
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
        if new_url == url {
            new_url.to_string()
        } else {
            Self::normalize_double_dot(new_url)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest(
        query,
        expected,
        case(
            "key=-_.~!@#$%^*(){}|:\"'`<>?",
            "key=-_.~%21%40%23%24%25%5E%2A%28%29%7B%7D%7C%3A%22%27%60%3C%3E%3F"
        ),
        case("∞=v&キ=v&0=v&a=v", "0=v&a=v&%E2%88%9E=v&%E3%82%AD=v"),
        case("a=b&a=c&a=a", "a=a&a=b&a=c"),
        case("key2=value2&key=value", "key=value&key2=value2"),
        case("k=&k=v", "k=&k=v"),
        case("", ""),
        case(
            "key=-_.%21%40%23%24%25%5E%2A%28%29%20%7B%7D%7C%3A%22%27%60%3C%3E%3F",
            "key=-_.%21%40%23%24%25%5E%2A%28%29%20%7B%7D%7C%3A%22%27%60%3C%3E%3F"
        ),
        case("k=%7E", "k=~"),
        case("k=+", "k=%20"),
        case("k=%7E&k=~&k=%40&k=a", "k=%40&k=a&k=~&k=~")
    )]
    fn encode_query_test(query: &str, expected: &str) {
        assert_eq!(Signable::encode_query(query).unwrap(), expected);
    }

    #[rstest(
        url,
        expected,
        case("/./example/./.", "/example/"),
        case("/example/sample/..", "/example/"),
        case("/example/sample/../../../..", "/"),
        case("/%2b", "/%2B"),
        case("//example///sample", "/example/sample"),
        case("/example/", "/example/")
    )]
    fn normalize_url_test(url: &str, expected: &str) {
        assert_eq!(Signable::normalize_url(url), expected);
    }
}
