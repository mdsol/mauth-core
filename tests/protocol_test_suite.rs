extern crate mauth_core;

use mauth_core::signer::Signer;
use mauth_core::verifier::Verifier;
use serde::Deserialize;
use std::fs;
use std::path::Path;

const TEST_SUITE_PATH: &str = "tests/mauth-protocol-test-suite/";

#[derive(Deserialize)]
struct RequestShape {
    verb: String,
    url: String,
    body: Option<String>,
    body_filepath: Option<String>,
}

#[derive(Deserialize)]
struct Config {
    app_uuid: String,
    request_time: u64,
    private_key_file: String,
}

fn test_singer(
    singer: &Signer,
    version: u8,
    timestamp: &str,
    protocol_path: &Path,
    test_case: &str,
) -> Result<(), String> {
    let test_case_path = protocol_path.join(test_case);
    let req_path = test_case_path.join(format!("{test_case}.req"));
    let sig_path = test_case_path.join(format!("{test_case}.sig"));
    let req: RequestShape =
        serde_json::from_slice(&fs::read(Path::new(&req_path)).unwrap()).unwrap();
    let sig = match fs::read_to_string(Path::new(&sig_path)) {
        Ok(sig) => sig,
        _ => {
            return Ok(());
        }
    };

    let (path, query) = req.url.split_once('?').unwrap_or((&req.url, ""));

    let body_data = match (req.body, req.body_filepath) {
        (Some(direct_str), None) => direct_str.as_bytes().to_vec(),
        (None, Some(filename_str)) => fs::read(test_case_path.join(filename_str)).unwrap(),
        _ => vec![],
    };

    let result = singer
        .sign_string(version, req.verb, path, query, &body_data, timestamp)
        .unwrap();

    if sig == result {
        Ok(())
    } else {
        Err(format!("[{test_case}] result: {result}, expected: {sig}"))
    }
}

fn test_verifier(
    verifier: &Verifier,
    version: u8,
    timestamp: &str,
    protocol_path: &Path,
    test_case: &str,
) -> Result<(), String> {
    let test_case_path = protocol_path.join(test_case);
    let req_path = test_case_path.join(format!("{test_case}.req"));
    let sig_path = test_case_path.join(format!("{test_case}.sig"));
    let req: RequestShape =
        serde_json::from_slice(&fs::read(Path::new(&req_path)).unwrap()).unwrap();
    let sig = match fs::read_to_string(Path::new(&sig_path)) {
        Ok(sig) => sig,
        _ => {
            return Ok(());
        }
    };

    let (path, query) = req.url.split_once('?').unwrap_or((&req.url, ""));

    let body_data = match (req.body, req.body_filepath) {
        (Some(direct_str), None) => direct_str.as_bytes().to_vec(),
        (None, Some(filename_str)) => fs::read(test_case_path.join(filename_str)).unwrap(),
        _ => vec![],
    };

    let result = verifier
        .verify_signature(version, req.verb, path, query, &body_data, timestamp, sig)
        .unwrap();

    if result {
        Ok(())
    } else {
        Err(format!("[{test_case}] failed"))
    }
}

// #[test]
// fn mws_protocol_signer_test() -> Result<(), String> {
//     let test_suite_path = Path::new(TEST_SUITE_PATH);
//     let protocols_path = test_suite_path.join("protocols");
//     let protocol_path = protocols_path.join("MWS");

//     let config_path = test_suite_path.join("signing-config.json");
//     let config: Config = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
//     let private_key =
//         fs::read_to_string(Path::new(&test_suite_path.join(config.private_key_file))).unwrap();
//     let singer = Signer::new(config.app_uuid, private_key).unwrap();
//     let timestamp = config.request_time.to_string();

//     fs::read_dir(&protocol_path)
//         .unwrap()
//         .map(|r| {
//             let r_path = r.unwrap().path();
//             (
//                 r_path.clone(),
//                 r_path.file_name().unwrap().to_str().unwrap().to_string(),
//             )
//         })
//         .try_for_each(|(_, name)| {
//             test_singer(&singer, 1, &timestamp, protocol_path.as_path(), &name)
//         })?;

//     Ok(())
// }

#[test]
fn mwsv2_protocol_signer_test() -> Result<(), String> {
    let test_suite_path = Path::new(TEST_SUITE_PATH);
    let protocols_path = test_suite_path.join("protocols");
    let protocol_path = protocols_path.join("MWSV2");

    let config_path = test_suite_path.join("signing-config.json");
    let config: Config = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
    let private_key =
        fs::read_to_string(Path::new(&test_suite_path.join(config.private_key_file))).unwrap();
    let singer = Signer::new(config.app_uuid, private_key).unwrap();
    let timestamp = config.request_time.to_string();

    fs::read_dir(&protocol_path)
        .unwrap()
        .map(|r| {
            let r_path = r.unwrap().path();
            (
                r_path.clone(),
                r_path.file_name().unwrap().to_str().unwrap().to_string(),
            )
        })
        .try_for_each(|(_, name)| {
            test_singer(&singer, 2, &timestamp, protocol_path.as_path(), &name)
        })?;

    Ok(())
}

// #[test]
// fn mws_protocol_verifier_test() -> Result<(), String> {
//     let test_suite_path = Path::new(TEST_SUITE_PATH);
//     let protocols_path = test_suite_path.join("protocols");
//     let protocol_path = protocols_path.join("MWS");

//     let config_path = test_suite_path.join("signing-config.json");
//     let config: Config = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
//     let public_key = fs::read_to_string(Path::new(
//         &test_suite_path.join("signing-params/rsa-key-pub"),
//     ))
//     .unwrap();
//     let verifier = Verifier::new(config.app_uuid, public_key).unwrap();
//     let timestamp = config.request_time.to_string();

//     fs::read_dir(&protocol_path)
//         .unwrap()
//         .map(|r| {
//             let r_path = r.unwrap().path();
//             (
//                 r_path.clone(),
//                 r_path.file_name().unwrap().to_str().unwrap().to_string(),
//             )
//         })
//         .try_for_each(|(_, name)| {
//             test_verifier(&verifier, 1, &timestamp, protocol_path.as_path(), &name)
//         })?;

//     Ok(())
// }

#[test]
fn mwsv2_protocol_verifier_test() -> Result<(), String> {
    let test_suite_path = Path::new(TEST_SUITE_PATH);
    let protocols_path = test_suite_path.join("protocols");
    let protocol_path = protocols_path.join("MWSV2");

    let config_path = test_suite_path.join("signing-config.json");
    let config: Config = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
    let public_key = fs::read_to_string(Path::new(
        &test_suite_path.join("signing-params/rsa-key-pub"),
    ))
    .unwrap();
    let verifier = Verifier::new(config.app_uuid, public_key).unwrap();
    let timestamp = config.request_time.to_string();

    fs::read_dir(&protocol_path)
        .unwrap()
        .map(|r| {
            let r_path = r.unwrap().path();
            (
                r_path.clone(),
                r_path.file_name().unwrap().to_str().unwrap().to_string(),
            )
        })
        .try_for_each(|(_, name)| {
            test_verifier(&verifier, 2, &timestamp, protocol_path.as_path(), &name)
        })?;

    Ok(())
}
