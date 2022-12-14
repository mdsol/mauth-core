use criterion::{criterion_group, criterion_main, Criterion};
use mauth_core::signer::Signer;
use mauth_core::verifier::Verifier;
use openssl::rsa::Rsa;

const APP_UUID: &str = "8ac278af-e761-479b-9e7a-10bcc2f30304";
const TIMESTAMP: &str = "1669858655";
const QS: &str = "don=quixote&quixote=don";

fn bench_signer(c: &mut Criterion) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let signer = Signer::new(APP_UUID, private_key).unwrap();

    let short_body = "Somewhere in La Mancha, in a place I do not care to remember".as_bytes();
    let average_body: &[u8] = &short_body.repeat(1000);
    let huge_body: &[u8] = &average_body.repeat(100);

    println!(
        "A short request has a body of 60 chars.\n\
        An average request has a body of 60,000 chars.\n\
        A huge request has a body of 6,000,000 chars.\n\
        A qs request has a body of 60 chars and a query string with two k/v pairs.\n"
    );

    let mut group = c.benchmark_group("signer");
    group.bench_function("v1-sign-short", |b| {
        b.iter(|| signer.sign_string(1, "PUT", "/", "", short_body, TIMESTAMP))
    });
    group.bench_function("v2-sign-short", |b| {
        b.iter(|| signer.sign_string(2, "PUT", "/", "", short_body, TIMESTAMP))
    });
    group.bench_function("v1-sign-average", |b| {
        b.iter(|| signer.sign_string(1, "PUT", "/", "", average_body, TIMESTAMP))
    });
    group.bench_function("v2-sign-average", |b| {
        b.iter(|| signer.sign_string(2, "PUT", "/", "", average_body, TIMESTAMP))
    });
    group.bench_function("v2-sign-qs", |b| {
        b.iter(|| signer.sign_string(2, "PUT", "/", QS, average_body, TIMESTAMP))
    });
    group.bench_function("v1-sign-huge", |b| {
        b.iter(|| signer.sign_string(1, "PUT", "/", "", huge_body, TIMESTAMP))
    });
    group.bench_function("v2-sign-huge", |b| {
        b.iter(|| signer.sign_string(2, "PUT", "/", "", huge_body, TIMESTAMP))
    });

    group.finish();
}

fn bench_verifier(c: &mut Criterion) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
    let public_key = String::from_utf8(rsa.public_key_to_pem().unwrap()).unwrap();
    let signer = Signer::new(APP_UUID, private_key).unwrap();
    let verifier = Verifier::new(APP_UUID, public_key).unwrap();

    let short_body = "Somewhere in La Mancha, in a place I do not care to remember".as_bytes();
    let average_body: &[u8] = &short_body.repeat(1000);
    let huge_body: &[u8] = &average_body.repeat(100);

    let v1_short_signed_request = &signer
        .sign_string(1, "PUT", "/", "", short_body, TIMESTAMP)
        .unwrap();
    let v2_short_signed_request = &signer
        .sign_string(2, "PUT", "/", "", short_body, TIMESTAMP)
        .unwrap();
    let v1_average_signed_request = &signer
        .sign_string(1, "PUT", "/", "", average_body, TIMESTAMP)
        .unwrap();
    let v2_average_signed_request = &signer
        .sign_string(2, "PUT", "/", "", average_body, TIMESTAMP)
        .unwrap();
    let v2_qs_signed_request = &signer
        .sign_string(2, "PUT", "/", QS, short_body, TIMESTAMP)
        .unwrap();
    let v1_huge_signed_request = &signer
        .sign_string(1, "PUT", "/", "", huge_body, TIMESTAMP)
        .unwrap();
    let v2_huge_signed_request = &signer
        .sign_string(2, "PUT", "/", "", huge_body, TIMESTAMP)
        .unwrap();

    let mut group = c.benchmark_group("verifier");
    group.bench_function("v1-authenticate-short", |b| {
        b.iter(|| {
            verifier.verify_signature(
                1,
                "PUT",
                "/",
                "",
                short_body,
                TIMESTAMP,
                v1_short_signed_request,
            )
        })
    });
    group.bench_function("v2-authenticate-short", |b| {
        b.iter(|| {
            verifier.verify_signature(
                2,
                "PUT",
                "/",
                "",
                short_body,
                TIMESTAMP,
                v2_short_signed_request,
            )
        })
    });
    group.bench_function("v1-authenticate-average", |b| {
        b.iter(|| {
            verifier.verify_signature(
                1,
                "PUT",
                "/",
                "",
                average_body,
                TIMESTAMP,
                v1_average_signed_request,
            )
        })
    });
    group.bench_function("v2-authenticate-average", |b| {
        b.iter(|| {
            verifier.verify_signature(
                2,
                "PUT",
                "/",
                "",
                average_body,
                TIMESTAMP,
                v2_average_signed_request,
            )
        })
    });
    group.bench_function("v2-authenticate-qs", |b| {
        b.iter(|| {
            verifier.verify_signature(
                2,
                "PUT",
                "/",
                QS,
                average_body,
                TIMESTAMP,
                v2_qs_signed_request,
            )
        })
    });
    group.bench_function("v1-authenticate-huge", |b| {
        b.iter(|| {
            verifier.verify_signature(
                1,
                "PUT",
                "/",
                "",
                huge_body,
                TIMESTAMP,
                v1_huge_signed_request,
            )
        })
    });
    group.bench_function("v2-authenticate-huge", |b| {
        b.iter(|| {
            verifier.verify_signature(
                2,
                "PUT",
                "/",
                "",
                huge_body,
                TIMESTAMP,
                v2_huge_signed_request,
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_signer, bench_verifier);
criterion_main!(benches);
