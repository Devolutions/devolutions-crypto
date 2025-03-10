use clap::{Parser, Subcommand};
use std::{borrow::Borrow, convert::TryFrom};

/// Gives a CLI interface to Devolutions Crypto Library
#[derive(Debug, Parser)]
#[command(name = "devolutions-crypto-cli")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "Philippe Dugre <pdugre@devolutions.net>")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a random key of given length
    #[command(arg_required_else_help = true)]
    Generate {
        /// Length of the key to generate
        length: Option<usize>,
    },

    /// Generate a random keypair"
    GenerateKeypair,

    /// Generate secret key with parts shared accross multiple parties.
    #[command(arg_required_else_help = true)]
    GenerateSharedKey {
        /// The number of shares to generate.
        #[arg(short, long)]
        shares: u8,

        /// The minimum number of shares required to regenerate the secret.
        #[arg(short, long)]
        threshold: u8,

        /// The length of the shaared secret
        #[arg(short, long)]
        length: Option<usize>,
    },

    /// Generate parameters to derive a password
    #[command(arg_required_else_help = true)]
    GenerateArgon2Parameters {
        /// The amount, in kilobytes, of memory to use for the derivation
        #[arg(short, long)]
        memory: Option<u32>,

        /// The number of lanes. Should be the same as the number of threads on the most commonly used password for the hash(1 for webassembly)
        #[arg(long)]
        lanes: Option<u32>,

        /// The number of iteration(time parameters)
        #[arg(short, long)]
        iterations: Option<u32>,

        /// The desired length of the key
        #[arg(short, long)]
        length: Option<u32>,
    },

    /// Derive a password or key into an encryption key
    #[command(arg_required_else_help = true)]
    Derive {
        /// The password or key to derive
        data: String,

        /// The salt to use for derivation
        #[arg(short, long)]
        salt: Option<String>,

        /// The number of iteration for the derivation algorithm
        #[arg(short, long)]
        iterations: Option<u32>,

        /// The desired length of the key
        #[arg(short, long)]
        length: Option<usize>,
    },

    /// Encrypt data
    #[command(arg_required_else_help = true)]
    Encrypt {
        /// The plaintext to encrypt
        data: String,

        /// The key to use
        key: String,

        /// The version to use
        #[arg(short, long)]
        version: Option<u16>,
    },

    /// Decrypt data
    #[command(arg_required_else_help = true)]
    Decrypt {
        /// The ciphertext to decrypt
        data: String,

        /// The key to use
        key: String,
    },

    /// Encrypt data using a public key
    #[command(arg_required_else_help = true)]
    EncryptAsymmetric {
        /// The plaintext to encrypt
        data: String,

        /// The key to use
        key: String,

        /// The version to use
        #[arg(short, long)]
        version: Option<u16>,
    },

    /// Decrypt data using a private key
    #[command(arg_required_else_help = true)]
    DecryptAsymmetric {
        /// The ciphertext to decrypt
        data: String,

        /// The key to use
        key: String,
    },

    /// Hash a password
    #[command(arg_required_else_help = true)]
    HashPassword {
        /// The password to hash
        password: String,

        /// The number of iteration for the derivation algorithm
        #[arg(short, long)]
        iterations: Option<u32>,
    },

    /// Verify a password from its hash
    #[command(arg_required_else_help = true)]
    VerifyPassword {
        /// The password to verify
        password: String,

        /// The hash to validate the password against
        hash: String,
    },

    /// Mix a key exchange
    #[command(arg_required_else_help = true)]
    MixKeyExchange {
        /// Your private key
        private: String,

        /// The other user's public key
        public: String,
    },

    /// Regenerate a secret key from multiple shares
    #[command(arg_required_else_help = true)]
    JoinShares {
        /// The shares to merge
        shares: Vec<String>,
    },

    /// Print the header information
    #[command(arg_required_else_help = true)]
    PrintHeader {
        /// The data to check, in base64
        data: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { length } => generate_key(length),
        Commands::GenerateKeypair => generate_keypair(),
        Commands::GenerateArgon2Parameters {
            memory,
            lanes,
            iterations,
            length,
        } => generate_argon2parameters(memory, lanes, iterations, length),
        Commands::GenerateSharedKey {
            shares,
            threshold,
            length,
        } => generate_shared_key(shares, threshold, length),
        Commands::Derive {
            data,
            salt,
            iterations,
            length,
        } => derive_key(data, salt, iterations, length),
        Commands::Encrypt { data, key, version } => encrypt(data, key, version),
        Commands::EncryptAsymmetric { data, key, version } => {
            encrypt_asymmetric(data, key, version)
        }
        Commands::Decrypt { data, key } => decrypt(data, key),
        Commands::DecryptAsymmetric { data, key } => decrypt_asymmetric(data, key),
        Commands::HashPassword {
            password,
            iterations,
        } => hash_password(password, iterations),
        Commands::VerifyPassword { password, hash } => verify_password(hash, password),
        Commands::MixKeyExchange { private, public } => mix_key_exchange(private, public),
        Commands::JoinShares { shares } => join_shares(shares),
        Commands::PrintHeader { data } => print_header(data),
    }
}

fn generate_key(length: Option<usize>) {
    let length = length.unwrap_or(32);

    let key = base64::encode(&devolutions_crypto::utils::generate_key(length).unwrap());
    println!("{}", key);
}

fn generate_argon2parameters(
    memory: Option<u32>,
    lanes: Option<u32>,
    iterations: Option<u32>,
    length: Option<u32>,
) {
    let mut parameters = devolutions_crypto::Argon2Parameters::default();

    if let Some(memory) = memory {
        parameters.memory = memory;
    };

    if let Some(iterations) = iterations {
        parameters.iterations = iterations;
    };

    if let Some(lanes) = lanes {
        parameters.lanes = lanes;
    };

    if let Some(length) = length {
        parameters.length = length;
    };

    let parameters: Vec<u8> = parameters.borrow().into();
    println!("{}", base64::encode(&parameters));
}

fn derive_key(data: String, salt: Option<String>, iterations: Option<u32>, length: Option<usize>) {
    let data = data.as_bytes();
    let salt = match salt {
        Some(s) => base64::decode(&s).unwrap(),
        None => vec![0u8; 0],
    };

    let iterations = iterations.unwrap_or(10000);

    let length = length.unwrap_or(32);

    let key = devolutions_crypto::utils::derive_key_pbkdf2(data, &salt, iterations, length);
    println!("{}", base64::encode(&key));
}

fn encrypt(data: String, key: String, version: Option<u16>) {
    let key = base64::decode(&key).unwrap();

    let version = version.unwrap_or(0);

    let version = devolutions_crypto::CiphertextVersion::try_from(version).unwrap();

    let data: Vec<u8> = devolutions_crypto::ciphertext::encrypt(data.as_bytes(), &key, version)
        .unwrap()
        .into();
    println!("{}", base64::encode(&data));
}

fn encrypt_asymmetric(data: String, key: String, version: Option<u16>) {
    let key = base64::decode(&key).unwrap();

    let version = version.unwrap_or(0);

    let version = devolutions_crypto::CiphertextVersion::try_from(version).unwrap();

    let key = devolutions_crypto::key::PublicKey::try_from(key.as_slice()).unwrap();

    let data: Vec<u8> =
        devolutions_crypto::ciphertext::encrypt_asymmetric(data.as_bytes(), &key, version)
            .unwrap()
            .into();
    println!("{}", base64::encode(&data));
}

fn decrypt(data: String, key: String) {
    let data = base64::decode(&data).unwrap();
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice()).unwrap();
    let key = base64::decode(&key).unwrap();

    let data: Vec<u8> = data.decrypt(&key).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}

fn decrypt_asymmetric(data: String, key: String) {
    let data = base64::decode(&data).unwrap();
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice()).unwrap();
    let key = base64::decode(&key).unwrap();
    let key = devolutions_crypto::key::PrivateKey::try_from(key.as_slice()).unwrap();

    let data: Vec<u8> = data.decrypt_asymmetric(&key).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}

fn hash_password(password: String, iterations: Option<u32>) {
    let iterations = iterations.unwrap_or(10000);

    let hash: Vec<u8> = devolutions_crypto::password_hash::hash_password(
        &password.as_bytes(),
        iterations,
        Default::default(),
    )
    .unwrap()
    .into();
    println!("{}", base64::encode(&hash));
}

fn verify_password(hash: String, password: String) {
    let hash = devolutions_crypto::password_hash::PasswordHash::try_from(
        base64::decode(&hash).unwrap().as_slice(),
    )
    .unwrap();

    println!("{}", hash.verify_password(password.as_bytes()));
}

fn generate_keypair() {
    let keypair = devolutions_crypto::key::generate_keypair(Default::default());

    println!(
        "Private Key: {}\nPublic Key: {}",
        base64::encode(&Vec::<u8>::from(keypair.private_key)),
        base64::encode(&Vec::<u8>::from(keypair.public_key))
    );
}

fn mix_key_exchange(private: String, public: String) {
    let private =
        devolutions_crypto::key::PrivateKey::try_from(base64::decode(&private).unwrap().as_slice())
            .unwrap();
    let public =
        devolutions_crypto::key::PublicKey::try_from(base64::decode(&public).unwrap().as_slice())
            .unwrap();

    println!(
        "{}",
        base64::encode(&devolutions_crypto::key::mix_key_exchange(&private, &public).unwrap())
    )
}

fn generate_shared_key(shares: u8, threshold: u8, length: Option<usize>) {
    let length = length.unwrap_or(32);

    let shares = devolutions_crypto::secret_sharing::generate_shared_key(
        shares,
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

fn join_shares(shares: Vec<String>) {
    let shares: Vec<devolutions_crypto::secret_sharing::Share> = shares
        .into_iter()
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

fn print_header(data: String) {
    let data = base64::decode(&data).unwrap();

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
