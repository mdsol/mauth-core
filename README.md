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

let mauth_version = 2

let signer = Signer::new(app_uuid, private_key_data)?;
let signiture = signer.sign_string(mauth_version, verb, path, query, body, timestamp)?

let verifier = Verifier::new(app_uuid, public_key_data)?;
let is_valid = verifier.verify_signature(mauth_version, verb, path, query, body, timestamp, signature)?;
```

You can find an example of binding MAuth Core to Ruby [here](./doc/binding_to_ruby.md).

## Contributing
See [CONTRIBUTING](CONTRIBUTING.md).
