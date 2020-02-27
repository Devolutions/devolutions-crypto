extern crate clap;
extern crate devolutions_crypto;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;

fn main() {
    let matches = App::new("Devolutions Crypto")
        .setting(AppSettings::SubcommandRequired)
        .version(env!("CARGO_PKG_VERSION"))
        .author("Philippe Dugre <pdugre@devolutions.net>")
        .about("Gives a CLI interface to Devolutions Crypto Library")
        .subcommand(
            SubCommand::with_name("generate")
                .about("Generate a random key of given length")
                .arg(
                    Arg::with_name("LENGTH")
                        .help("Length of the key to generate")
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("derive")
                .about("Derive a password or key into an encryption key")
                .arg(
                    Arg::with_name("DATA")
                        .help("The password or key to derive)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("salt")
                        .short("s")
                        .long("salt")
                        .takes_value(true)
                        .help("The salt to use for derivation"),
                )
                .arg(
                    Arg::with_name("iterations")
                        .short("i")
                        .long("iterations")
                        .takes_value(true)
                        .help("The number of iteration for the derivation algorithm"),
                )
                .arg(
                    Arg::with_name("length")
                        .short("l")
                        .long("length")
                        .takes_value(true)
                        .help("The desired length of the key"),
                ),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .about("Encrypt data")
                .arg(Arg::with_name("DATA").help("The plaintext").required(true))
                .arg(Arg::with_name("KEY").help("The key to use").required(true))
                .arg(
                    Arg::with_name("version")
                        .short("v")
                        .long("version")
                        .takes_value(true)
                        .help("The version to use"),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("Decrypt data")
                .arg(Arg::with_name("DATA").help("The ciphertext").required(true))
                .arg(Arg::with_name("KEY").help("The key to use").required(true)),
        )
        .subcommand(
            SubCommand::with_name("hash-password")
                .about("Hash a password")
                .arg(
                    Arg::with_name("PASSWORD")
                        .help("The password to hash")
                        .required(true),
                )
                .arg(
                    Arg::with_name("iterations")
                        .short("i")
                        .long("iterations")
                        .takes_value(true)
                        .help("The number of iteration for the derivation algorithm"),
                ),
        )
        .subcommand(
            SubCommand::with_name("verify-password")
                .about("Verify a password from its hash")
                .arg(
                    Arg::with_name("PASSWORD")
                        .help("The password to verify")
                        .required(true)
                )
                .arg(
                    Arg::with_name("HASH")
                        .help("The hash to validate the password sagainst")
                        .required(true)
                )
        )
        .subcommand(
            SubCommand::with_name("generate-key-exchange")
                .about("Generate a Key Exchange")
        )
        .subcommand(
            SubCommand::with_name("mix-key-exchange")
                .about("Mix a key exchange")
                .arg(
                    Arg::with_name("PRIVATE")
                        .help("Your private key")
                        .required(true)
                )
                .arg(
                    Arg::with_name("PUBLIC")
                        .help("The other user's public key")
                        .required(true)
                )
        )
        .subcommand(
            SubCommand::with_name("generate-shared-key")
                .about("Generate secret key with parts shared accross multiple parties.")
                .arg(
                    Arg::with_name("shares").short("s").long("shares").takes_value(true).required(true).help("The number of shares to generate.")
                )
                .arg(
                    Arg::with_name("threshold").short("t").long("threshold").takes_value(true).required(true).help("The minimum number of shares required to regenerate the secret.")
                )
                .arg(
                    Arg::with_name("length").short("l").long("length").takes_value(true).help("The length of the shared secret")
                )
        )
        .subcommand(
            SubCommand::with_name("join-shares")
                .about("Regenerate a secret key from multiple shares")
                .arg(
                    Arg::with_name("SHARE").takes_value(true).multiple(true).required(true).help("The shares to merge")
                )
        )
        .get_matches();

    match matches.subcommand() {
        ("generate", Some(matches)) => generate_key(matches),
        ("derive", Some(matches)) => derive_key(matches),
        ("encrypt", Some(matches)) => encrypt(matches),
        ("decrypt", Some(matches)) => decrypt(matches),
        ("hash-password", Some(matches)) => hash_password(matches),
        ("verify-password", Some(matches)) => verify_password(matches),
        ("generate-key-exchange", Some(matches)) => generate_key_exchange(matches),
        ("mix-key-exchange", Some(matches)) => mix_key_exchange(matches),
        ("generate-shared-key", Some(matches)) => generate_shared_key(matches),
        ("join-shares", Some(matches)) => join_shares(matches),
        _ => unreachable!(),
    }
}

fn generate_key(matches: &ArgMatches) {
    let length = matches
        .value_of("LENGTH")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(32);

    let key = base64::encode(&devolutions_crypto::utils::generate_key(length));
    println!("{}", key);
}

fn derive_key(matches: &ArgMatches) {
    let data = matches.value_of("DATA").unwrap().as_bytes();
    let salt = base64::decode(&matches.value_of("salt").unwrap_or("")).unwrap_or(vec![0u8; 0]);

    let iterations = matches
        .value_of("iterations")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(10000);

    let length = matches
        .value_of("length")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(32);

    let key = devolutions_crypto::utils::derive_key(data, &salt, iterations, length);
    println!("{}", base64::encode(&key));
}

fn encrypt(matches: &ArgMatches) {
    let data = matches.value_of("DATA").unwrap();
    let key = base64::decode(&matches.value_of("KEY").unwrap()).unwrap();

    let version = matches
        .value_of("version")
        .unwrap_or("")
        .parse::<u16>()
        .ok();

    let data: Vec<u8> = devolutions_crypto::DcDataBlob::encrypt(data.as_bytes(), &key, version)
        .unwrap()
        .into();
    println!("{}", base64::encode(&data));
}

fn decrypt(matches: &ArgMatches) {
    let data = base64::decode(matches.value_of("DATA").unwrap()).unwrap();
    let data = devolutions_crypto::DcDataBlob::try_from(data.as_slice()).unwrap();
    let key = base64::decode(&matches.value_of("KEY").unwrap()).unwrap();

    let data: Vec<u8> = devolutions_crypto::DcDataBlob::decrypt(&data, &key).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}

fn hash_password(matches: &ArgMatches) {
    let iterations = matches
        .value_of("iterations")
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(10000);

    let password = matches.value_of("PASSWORD").unwrap();

    let hash: Vec<u8> = devolutions_crypto::DcDataBlob::hash_password(&password.as_bytes(), iterations).unwrap().into();
    println!("{}", base64::encode(&hash));
}

fn verify_password(matches: &ArgMatches) {
    let password = matches.value_of("PASSWORD").unwrap();

    let hash = devolutions_crypto::DcDataBlob::try_from(base64::decode(matches.value_of("HASH").unwrap()).unwrap().as_slice()).unwrap();

    println!("{}", hash.verify_password(password.as_bytes()).unwrap());
}

fn generate_key_exchange(_matches: &ArgMatches) {
    let (private, public) = devolutions_crypto::DcDataBlob::generate_key_exchange().unwrap();

    println!("Private Key: {}\nPublic Key: {}", base64::encode(&Vec::<u8>::from(private)), base64::encode(&Vec::<u8>::from(public)));
}

fn mix_key_exchange(matches: &ArgMatches) {
    let private = devolutions_crypto::DcDataBlob::try_from(base64::decode(matches.value_of("PRIVATE").unwrap().as_bytes()).unwrap().as_slice()).unwrap();
    let public = devolutions_crypto::DcDataBlob::try_from(base64::decode(matches.value_of("PUBLIC").unwrap().as_bytes()).unwrap().as_slice()).unwrap();

    println!("{}", base64::encode(&devolutions_crypto::DcDataBlob::mix_key_exchange(private, public).unwrap()))
}

fn generate_shared_key(matches: &ArgMatches) {
    let n_shares = matches.value_of("shares").unwrap().parse::<u8>().unwrap();
    let threshold = matches.value_of("threshold").unwrap().parse::<u8>().unwrap();

    let length = matches
        .value_of("length")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(32);

    let shares = devolutions_crypto::DcDataBlob::generate_shared_key(n_shares, threshold, length).unwrap();

    for (i, s) in shares.into_iter().map(Into::<Vec<u8>>::into).enumerate() {
        let s = base64::encode(&s);
        println!("Share {}: {}", i, s);
    }
}

fn join_shares(matches: &ArgMatches) {
    let shares: Vec<devolutions_crypto::DcDataBlob> = matches.values_of("SHARE").unwrap().map(|s| devolutions_crypto::DcDataBlob::try_from(base64::decode(&s).unwrap().as_slice()).unwrap()).collect();
    let secret_key = devolutions_crypto::DcDataBlob::join_shares(&shares).unwrap();

    println!("{}", base64::encode(&secret_key));
}