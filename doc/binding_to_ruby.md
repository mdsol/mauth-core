# Example of binding MAuth Core to Ruby

This document is an example of how to bind MAuth Core in [MAuth-Client ruby](https://github.com/mdsol/mauth-client-ruby).

## Required Ruby Gems

The following Ruby gems are used to bind:
- [Magnus](https://github.com/matsadler/magnus)
- [rb-sys](https://github.com/oxidize-rb/rb-sys)
- [rake-compiler](https://github.com/rake-compiler/rake-compiler)

## Modifying MAuth-Client ruby

Add the following gems to [mauth-client.gemspec](https://github.com/mdsol/mauth-client-ruby/blob/master/mauth-client.gemspec):

```
  spec.add_dependency "rake-compiler"
  spec.add_dependency "rb_sys"
```

And update [Rakefile](https://github.com/mdsol/mauth-client-ruby/blob/master/Rakefile) to add the following extension task:

```
require "rake/extensiontask"

task build: :compile

Rake::ExtensionTask.new("mauth_core_binder") do |ext|
  ext.lib_dir = "lib/mauth"
  ext.source_pattern = "*.{rs,toml}"
end

task default: %i[compile spec]
```

## Generate extension library

Prepare an extension directory and create a new Cargo package to bind mauth-core:

```sh
mkdir -p ext/mauth_core_binder
cd ext/mauth_core_binder

cargo init . --lib
cargo add rb-sys rb-allocator
cargo add magnus --features rb-sys-interop
```

Set the crate-type attribute to `cdylib` in Cargo.toml:

```
[lib]
crate-type = ["cdylib"]
```

Add `ext/mauth_core_binder/extconf.rb` file:

```ruby
require "mkmf"
require "rb_sys/mkmf"

create_rust_makefile("mauth_core_binder/mauth_core_binder")
```

At this point, you are ready to compile the rust extension by calling:
```
bundle exec rake compile
```

Add the `mauth-core` crate to Cargo.toml:

```
[dependencies]
mauth-core = "0.4"
```

Then, add some Rust code to the `lib.rs` file to call mauth-core:

```rust
use magnus::{define_class, exception, function, method, prelude::*, Error};
use rb_allocator::ruby_global_allocator;

use mauth_core::signer::Signer;
use mauth_core::verifier::Verifier;

ruby_global_allocator!();

#[magnus::wrap(class = "MAuthCore")]
struct MAuthCore {
    signer: Signer,
}

impl MAuthCore {
    fn new(app_uuid: String, private_key_data: String) -> Self {
        let signer =
            Signer::new(app_uuid, private_key_data).expect("Failed to initialize MAuthCore");

        Self { signer }
    }

    fn sign_string(
        &self,
        version: u8,
        verb: String,
        path: String,
        query: String,
        body: magnus::Value,
        timestamp: String,
    ) -> Result<String, magnus::Error> {

        let body = magnus::RString::from_value(body).ok_or_else(|| Error::new(
            exception::standard_error(),
            "expected string",
        ))?;

        let body_as_slice;
        unsafe {
            body_as_slice = body.as_slice();
        }

        self.signer
            .sign_string(version, verb, path, query, body_as_slice, timestamp)
            .map_err(|err| {
                Error::new(
                    exception::standard_error(),
                    format!("Failed to generate sigunatures: {:?}", err),
                )
            })
    }

    fn verify_signature(
        &self,
        app_uuid: String,
        public_key_data: String,
        version: u8,
        verb: String,
        path: String,
        query: String,
        body: magnus::Value,
        timestamp: String,
        signature: String,
    ) -> Result<bool, magnus::Error> {

        let body = magnus::RString::from_value(body).ok_or_else(|| Error::new(
            exception::standard_error(),
            "expected string",
        ))?;

        let body_as_slice;
        unsafe {
            body_as_slice = body.as_slice();
        }

        match Verifier::new(app_uuid, public_key_data) {
            Ok(verifier) => verifier
                .verify_signature(version, verb, path, query, body, timestamp, signature)
                .map_err(|err| {
                    Error::new(
                        exception::standard_error(),
                        format!("Failed to verify sigunatures: {:?}", err),
                    )
                }),
            Err(err) => Err(Error::new(
                exception::standard_error(),
                format!("Failed to initialize verifier: {:?}", err),
            )),
        }
    }
}

#[magnus::init]
fn init() -> Result<(), Error> {
    let class = define_class("MAuthCore", Default::default())?;
    class.define_singleton_method("new", function!(MAuthCore::new, 2))?;
    class.define_method("sign_string", method!(MAuthCore::sign_string, 6))?;
    class.define_method("verify_signature", method!(MAuthCore::verify_signature, 9))?;

    Ok(())
}
```

By adding the `#[magnus::wrap(class = "MAuthCore")]`  annotation, the MAuthCore struct is wrapped in a Ruby object and it is callable from Ruby.

Using the `#[magnus::init]` attribute to mark the init function so it can be correctly exposed to Ruby.

Now you can call `mauth-core` from Ruby code by doing this:

```ruby
mauth_core = MAuthCore.new(app_uuid, public_key_data)
mauth_core.sign_string(mauth_version, verb, path, query, body, timestamp)
```
