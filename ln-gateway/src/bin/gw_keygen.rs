use rand::thread_rng;
use secp256k1::SecretKey;

fn main() {
    let mut rng = thread_rng();
    let ctx = secp256k1::Secp256k1::new();
    let (sk_ln, pk_ln) = ctx.generate_keypair(&mut rng);
    let (sk_fed, pk_fed) = ctx.generate_schnorrsig_keypair(&mut rng);

    println!("Fed sk: {}", SecretKey::from_keypair(&sk_fed));
    println!("Fed pk: {}", pk_fed);
    println!();
    println!("Ln sk:  {}", sk_ln);
    println!("Ln pk:  {}", pk_ln);
}
