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
            SubCommand::with_name("generate-keypair")
                .about("Generate a random keypair")
        )
        .subcommand(
            SubCommand::with_name("generate-argon2parameters")
                .about("Generate parameters to derive a password")
                .arg(
                    Arg::with_name("memory")
                        .short("m")
                        .long("memory")
                        .takes_value(true)
                        .help("The amount, in kilobytes, of memory to use for the derivation"),
                )
                .arg(
                    Arg::with_name("lanes")
                        .long("lanes")
                        .takes_value(true)
                        .help("The number lanes. Should be the same as the number of threads on the most commonly used password for the hash(1 for webassembly)"),
                )
                .arg(
                    Arg::with_name("iterations")
                        .short("i")
                        .long("iterations")
                        .takes_value(true)
                        .help("The number of iteration(time parameters)"),
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
            SubCommand::with_name("derive-keypair")
                .about("Derive a password or key into a keypair")
                .arg(
                    Arg::with_name("DATA")
                        .help("The password or key to derive")
                        .required(true),
                )
                .arg(
                    Arg::with_name("parameters")
                        .required(true)
                        .help("The parameters to use for derivation"),
                )
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
            SubCommand::with_name("encrypt-asymmetric")
                .about("Encrypt data using a public key")
                .arg(Arg::with_name("DATA").help("The plaintext").required(true))
                .arg(Arg::with_name("KEY").help("The public key to use").required(true))
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
            SubCommand::with_name("decrypt-asymmetric")
                .about("Decrypt data using a private key")
                .arg(Arg::with_name("DATA").help("The ciphertext").required(true))
                .arg(Arg::with_name("KEY").help("The private key to use").required(true)),
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
        .subcommand(
            SubCommand::with_name("print-header")
                .about("Print the header information")
                .arg(
                    Arg::with_name("DATA").takes_value(true).required(true).help("The data to check, in base64")
                )
        )
        .get_matches();

    match matches.subcommand() {
        ("generate", Some(matches)) => generate_key(matches),
        ("generate-argon2parameters", Some(matches)) => generate_argon2parameters(matches),
        ("derive", Some(matches)) => derive_key(matches),
        ("derive-keypair", Some(matches)) => derive_keypair(matches),
        ("encrypt", Some(matches)) => encrypt(matches),
        ("encrypt-asymmetric", Some(matches)) => encrypt_asymmetric(matches),
        ("decrypt", Some(matches)) => decrypt(matches),
        ("decrypt-asymmetric", Some(matches)) => decrypt_asymmetric(matches),
        ("hash-password", Some(matches)) => hash_password(matches),
        ("verify-password", Some(matches)) => verify_password(matches),
        ("generate-keypair", Some(matches)) => generate_keypair(matches),
        ("mix-key-exchange", Some(matches)) => mix_key_exchange(matches),
        ("generate-shared-key", Some(matches)) => generate_shared_key(matches),
        ("join-shares", Some(matches)) => join_shares(matches),
        ("print-header", Some(matches)) => print_header(matches),
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

fn generate_argon2parameters(matches: &ArgMatches) {
    let memory = matches.value_of("memory").unwrap_or("").parse::<u32>();

    let iterations = matches.value_of("iterations").unwrap_or("").parse::<u32>();

    let lanes = matches.value_of("lanes").unwrap_or("").parse::<u32>();

    let length = matches.value_of("length").unwrap_or("").parse::<u32>();

    let mut parameters = devolutions_crypto::Argon2Parameters::default();

    if let Ok(memory) = memory {
        parameters.memory = memory;
    };

    if let Ok(iterations) = iterations {
        parameters.iterations = iterations;
    };

    if let Ok(lanes) = lanes {
        parameters.lanes = lanes;
    };

    if let Ok(length) = length {
        parameters.length = length;
    };

    let parameters: Vec<u8> = parameters.into();
    println!("{}", base64::encode(&parameters));
}

fn derive_key(matches: &ArgMatches) {
    let data = matches.value_of("DATA").unwrap().as_bytes();
    let salt =
        base64::decode(&matches.value_of("salt").unwrap_or("")).unwrap_or_else(|_| vec![0u8; 0]);

    let iterations = matches
        .value_of("iterations")
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(10000);

    let length = matches
        .value_of("length")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(32);

    let key = devolutions_crypto::utils::derive_key_pbkdf2(data, &salt, iterations, length);
    println!("{}", base64::encode(&key));
}

fn derive_keypair(matches: &ArgMatches) {
    let data = matches.value_of("DATA").unwrap().as_bytes();
    let parameters = base64::decode(&matches.value_of("parameters").unwrap()).unwrap();

    let parameters = devolutions_crypto::Argon2Parameters::try_from(parameters.as_slice()).unwrap();
    let keypair =
        devolutions_crypto::key::derive_keypair(data, &parameters, Default::default()).unwrap();

    println!(
        "Private Key: {}\nPublic Key: {}",
        base64::encode(&Vec::<u8>::from(keypair.private_key)),
        base64::encode(&Vec::<u8>::from(keypair.public_key))
    );
}

fn encrypt(matches: &ArgMatches) {
    let data = matches.value_of("DATA").unwrap();
    let key = base64::decode(&matches.value_of("KEY").unwrap()).unwrap();

    let version = matches
        .value_of("version")
        .unwrap_or("0")
        .parse::<u16>()
        .unwrap();

    let version = devolutions_crypto::CiphertextVersion::try_from(version).unwrap();

    let data: Vec<u8> = devolutions_crypto::ciphertext::encrypt(data.as_bytes(), &key, version)
        .unwrap()
        .into();
    println!("{}", base64::encode(&data));
}

fn encrypt_asymmetric(matches: &ArgMatches) {
    let data = matches.value_of("DATA").unwrap();
    let key = base64::decode(&matches.value_of("KEY").unwrap()).unwrap();

    let version = matches
        .value_of("version")
        .unwrap_or("0")
        .parse::<u16>()
        .unwrap();

    let version = devolutions_crypto::CiphertextVersion::try_from(version).unwrap();

    let key = devolutions_crypto::key::PublicKey::try_from(key.as_slice()).unwrap();

    let data: Vec<u8> =
        devolutions_crypto::ciphertext::encrypt_asymmetric(data.as_bytes(), &key, version)
            .unwrap()
            .into();
    println!("{}", base64::encode(&data));
}

fn decrypt(matches: &ArgMatches) {
    let data = base64::decode(matches.value_of("DATA").unwrap()).unwrap();
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice()).unwrap();
    let key = base64::decode(&matches.value_of("KEY").unwrap()).unwrap();

    let data: Vec<u8> = data.decrypt(&key).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}

fn decrypt_asymmetric(matches: &ArgMatches) {
    let data = base64::decode(matches.value_of("DATA").unwrap()).unwrap();
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice()).unwrap();
    let key = base64::decode(&matches.value_of("KEY").unwrap()).unwrap();
    let key = devolutions_crypto::key::PrivateKey::try_from(key.as_slice()).unwrap();

    let data: Vec<u8> = data.decrypt_asymmetric(&key).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}

fn hash_password(matches: &ArgMatches) {
    let iterations = matches
        .value_of("iterations")
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(10000);

    let password = matches.value_of("PASSWORD").unwrap();

    let hash: Vec<u8> = devolutions_crypto::password_hash::hash_password(
        &password.as_bytes(),
        iterations,
        Default::default(),
    )
    .into();
    println!("{}", base64::encode(&hash));
}

fn verify_password(matches: &ArgMatches) {
    let password = matches.value_of("PASSWORD").unwrap();

    let hash = devolutions_crypto::password_hash::PasswordHash::try_from(
        base64::decode(matches.value_of("HASH").unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    println!("{}", hash.verify_password(password.as_bytes()));
}

fn generate_keypair(_matches: &ArgMatches) {
    let keypair = devolutions_crypto::key::generate_keypair(Default::default());

    println!(
        "Private Key: {}\nPublic Key: {}",
        base64::encode(&Vec::<u8>::from(keypair.private_key)),
        base64::encode(&Vec::<u8>::from(keypair.public_key))
    );
}

fn mix_key_exchange(matches: &ArgMatches) {
    let private = devolutions_crypto::key::PrivateKey::try_from(
        base64::decode(matches.value_of("PRIVATE").unwrap().as_bytes())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let public = devolutions_crypto::key::PublicKey::try_from(
        base64::decode(matches.value_of("PUBLIC").unwrap().as_bytes())
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    println!(
        "{}",
        base64::encode(&devolutions_crypto::key::mix_key_exchange(&private, &public).unwrap())
    )
}

fn generate_shared_key(matches: &ArgMatches) {
    let n_shares = matches.value_of("shares").unwrap().parse::<u8>().unwrap();
    let threshold = matches
        .value_of("threshold")
        .unwrap()
        .parse::<u8>()
        .unwrap();

    let length = matches
        .value_of("length")
        .unwrap_or("")
        .parse::<usize>()
        .unwrap_or(32);

    let shares = devolutions_crypto::secret_sharing::generate_shared_key(
        n_shares,
        threshold,
        length,
        Default::default(),
    )
    .unwrap();

    for (i, s) in shares.into_iter().map(Into::<Vec<u8>>::into).enumerate() {
        let s = base64::encode(&s);
        println!("Share {}: {}", i, s);
    }
}

fn join_shares(matches: &ArgMatches) {
    let shares: Vec<devolutions_crypto::secret_sharing::Share> = matches
        .values_of("SHARE")
        .unwrap()
        .map(|s| {
            devolutions_crypto::secret_sharing::Share::try_from(
                base64::decode(&s).unwrap().as_slice(),
            )
            .unwrap()
        })
        .collect();
    let secret_key = devolutions_crypto::secret_sharing::join_shares(&shares).unwrap();

    println!("{}", base64::encode(&secret_key));
}

fn print_header(matches: &ArgMatches) {
    let data = base64::decode(matches.value_of("DATA").unwrap().as_bytes()).unwrap();

    match devolutions_crypto::DataType::try_from(data[2] as u16) {
        Ok(devolutions_crypto::DataType::Ciphertext) => {
            if let Ok(header) = devolutions_crypto::Header::<
                devolutions_crypto::ciphertext::Ciphertext,
            >::try_from(&data[0..8])
            {
                println!("{:?}", &header);
            } else {
                println!("Invalid Header");
            }
        }
        Ok(devolutions_crypto::DataType::PasswordHash) => {
            if let Ok(header) = devolutions_crypto::Header::<
                devolutions_crypto::password_hash::PasswordHash,
            >::try_from(&data[0..8])
            {
                println!("{:?}", &header);
            } else {
                println!("Invalid Header");
            }
        }
        Ok(devolutions_crypto::DataType::Share) => {
            if let Ok(header) = devolutions_crypto::Header::<
                devolutions_crypto::secret_sharing::Share,
            >::try_from(&data[0..8])
            {
                println!("{:?}", &header);
            } else {
                println!("Invalid Header");
            }
        }
        Ok(devolutions_crypto::DataType::Key) => {
            if let Ok(h) =
                devolutions_crypto::Header::<devolutions_crypto::key::PublicKey>::try_from(
                    &data[0..8],
                )
            {
                println!("{:?}", &h);
            } else if let Ok(h) =
                devolutions_crypto::Header::<devolutions_crypto::key::PrivateKey>::try_from(
                    &data[0..8],
                )
            {
                println!("{:?}", &h);
            } else {
                println!("Invalid Header");
            }
        }
        _ => println!("Invalid Header"),
    }
}
