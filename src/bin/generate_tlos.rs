use clap::Parser;
use tlos::generate_tlos;

#[derive(Parser, Debug)]
#[command(name = "generate_tlos")]
#[command(about = "Generate TLOS deployment data")]
struct Args {
    #[arg(long, help = "Secret as 64-character hex string")]
    secret: String,

    #[arg(long, default_value = "0", help = "Circuit seed")]
    seed: u64,

    #[arg(long, help = "Output circuit data to file")]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();

    let secret_hex = args.secret.strip_prefix("0x").unwrap_or(&args.secret);
    let secret_bytes = hex::decode(secret_hex).expect("Invalid hex for secret");
    if secret_bytes.len() != 32 {
        eprintln!("Error: secret must be exactly 32 bytes (64 hex chars)");
        std::process::exit(1);
    }
    let secret: [u8; 32] = secret_bytes.try_into().unwrap();

    let deployment = generate_tlos(secret, args.seed);

    println!("TLOS Deployment Generated");
    println!("========================");
    println!("Wires: {}", deployment.num_wires);
    println!("Gates: {}", deployment.num_gates);
    println!("Circuit data size: {} bytes", deployment.circuit_data.len());
    println!(
        "Expected output hash: 0x{}",
        hex::encode(deployment.expected_output_hash)
    );
    println!(
        "Circuit seed: 0x{}",
        hex::encode(deployment.circuit_seed)
    );
    println!("Expected wire binding output (4 x u256, as lo|hi u128 pairs):");
    for (i, (lo, hi)) in deployment.expected_binding_output.words.iter().enumerate() {
        println!("  [{i}]: lo=0x{lo:032x} hi=0x{hi:032x}");
    }

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &deployment.circuit_data)
            .expect("Failed to write circuit data");
        println!("Circuit data written to: {}", output_path);
    } else {
        println!("\nCircuit data (hex, first 200 bytes):");
        println!("{}", hex::encode(&deployment.circuit_data[..200]));
    }
}
