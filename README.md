# MAuth Core

A library to generate and verify MAuth signatures

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
mauth-core = "0.4"
```

Here is an example of generating and verifying a signature:

```rust
use mauth_core::signer::Signer;
use mauth_core::verifier::Verifier;
use mauth_core::error::Error;

let mauth_version = 2;
let private_key_data = std::fs::read_to_string("tests/mauth-protocol-test-suite/signing-params/rsa-key").unwrap();
let public_key_data = std::fs::read_to_string("tests/mauth-protocol-test-suite/signing-params/rsa-key-pub").unwrap();
let app_uuid = "101c139a-236c-11ef-b5e3-125eb8485a60".to_string();
let verb = "GET";
let path = "/item";
let query = "page=2";
let body = b"";
let timestamp = "2024-01-28T19:11:35.000";

let signer = Signer::new(app_uuid.clone(), private_key_data);
assert!(signer.is_ok());
let signature = signer.unwrap().sign_string(mauth_version, verb, path, query, body, timestamp);
assert!(signature.is_ok());

let verifier = Verifier::new(app_uuid.clone(), public_key_data);
assert!(verifier.is_ok());
let result = verifier.unwrap().verify_signature(mauth_version, verb, path, query, body, timestamp, signature.unwrap());
assert!(result.is_ok());
```

You can find an example of binding MAuth Core to Ruby [here](./doc/binding_to_ruby.md).

## Contributing
See [CONTRIBUTING](CONTRIBUTING.md).
