const RSA_PRIVATE_KEY_HEADER: &str = "-----BEGIN RSA PRIVATE KEY-----";
const RSA_PRIVATE_KEY_FOOTER: &str = "-----END RSA PRIVATE KEY-----";

pub fn normalize_rsa_private_key(key: impl Into<String>) -> String {
    let key = key.into();

    match key.contains('\n') {
        true => key,
        false => {
            let body = key
                .trim()
                .trim_start_matches(RSA_PRIVATE_KEY_HEADER)
                .trim_end_matches(RSA_PRIVATE_KEY_FOOTER)
                .trim();

            let body = match body.contains(' ') {
                true => body.replace(' ', "\n"),
                false => body
                    .chars()
                    .collect::<Vec<char>>()
                    .chunks(64)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<String>>()
                    .join("\n"),
            };
            format!(
                "{}\n{}\n{}",
                RSA_PRIVATE_KEY_HEADER, body, RSA_PRIVATE_KEY_FOOTER
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rsa_private_key_test() {
        let rsa_private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00\n-----END RSA PRIVATE KEY-----";
        let rsa_private_key_with_space = rsa_private_key.replace('\n', " ");
        let rsa_private_key_without_newline = rsa_private_key.replace('\n', "");

        assert_eq!(normalize_rsa_private_key(rsa_private_key), rsa_private_key);
        assert_eq!(
            normalize_rsa_private_key(rsa_private_key_with_space),
            rsa_private_key
        );
        assert_eq!(
            normalize_rsa_private_key(rsa_private_key_without_newline),
            rsa_private_key
        );
    }
}
