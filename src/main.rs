mod bitcoin_service;
mod hd_wallt;
mod mnemonic;

use crate::hd_wallt::*;
use crate::mnemonic::*;

use bitcoin::Network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let num = 24;
    let mnemonic = mnemonic_generate(num)?;
    println!(" mnemonic: {mnemonic}");
    let derivation_path = "m/84'/0'/0'/0/0";
    let network = Network::Bitcoin;
    let passphrase = "";
    let (xpk, xprix) = generate_hd_wallt(network, passphrase, &mnemonic, derivation_path)?;
    // let derived_testnet_address = generate_testnet_address(network, &xpk)?;
    // let testnet_address = derived_testnet_address.to_string();
    // println!(" testnet_address: {testnet_address}");
    println!(" xprix: {xprix}");
    let derived_bitcoin_address = generate_bitcoin_address_by(network, "bc1", &xpk)?;
    let bitcoin_address = derived_bitcoin_address.to_string();
    println!(" bitcoin_address: {bitcoin_address}");
    Ok(())
}
