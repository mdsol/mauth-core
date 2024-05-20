# Contributing

## Requirements

* Rust

## Installation

This repo contains the submodule `mauth-protocol-test-suite` so requires a flag when initially cloning in order to clone and init submodules.

```
git clone --recurse-submodules git@github.com:mdsol/mauth-core.git
```

## General Information

* Check out the latest develop to make sure the feature hasn't been implemented or the bug hasn't been fixed yet
* Check out the issue tracker to make sure someone already hasn't requested it and/or contributed it
* Fork the project
* Start a feature/bugfix branch
* Commit and push until you are happy with your contribution
* Make sure to add tests for it. This is important so I don't break it in a future version unintentionally.

## Running Tests

```
cargo test --verbose
```

## Running Benchmark

If you make changes which could affect performance, please run the benchmark before and after the change as a sanity check.

```
cargo bench
```
