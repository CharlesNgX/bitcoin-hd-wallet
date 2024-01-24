use bip39::Mnemonic;
use bitcoin::ecdsa::Signature;
use bitcoin::script::Builder;
use bitcoin::PrivateKey;
use bitcoin::{
    absolute,
    bip32::{DerivationPath, Xpriv, Xpub},
    sighash::SighashCache,
    transaction, Address, Amount, EcdsaSighashType, Network, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness,
};
use secp256k1::hashes::Hash;
use secp256k1::{Message, Secp256k1, SecretKey, Signing};

const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(82_088);
const SPEND_AMOUNT: Amount = Amount::from_sat(10_000);
const CHANGE_AMOUNT: Amount = Amount::from_sat(40_000); // 1000 sat fee.

/// passphrase: ""
/// derivationPath: "m/84'/0'/0'/0/0"
pub fn generate_hd_wallt(
    network: Network,
    passphrase: &str,
    mnemonic: &Mnemonic,
    derivation_path: &str,
) -> Result<(Xpub, Xpriv), Box<dyn std::error::Error>> {
    // Generate seed by mnemonic
    let seed = mnemonic.to_seed(passphrase);

    let master_key = Xpriv::new_master(network, &seed)?;

    let secp = Secp256k1::new();
    let derivation_path = derivation_path.parse::<DerivationPath>()?;

    let derived_priv_key = master_key.derive_priv(&secp, &derivation_path)?;
    let derived_pub_key = Xpub::from_priv(&secp, &derived_priv_key);

    Ok((derived_pub_key, derived_priv_key))
}

/// Use p2pkh to generate "1" prefix bitcoin address
/// Use p2shwpkh to generate "3" prefix bitcoin address
/// Use p2wpkh to generate "bc1" prefix bitcoin address
pub fn generate_bitcoin_address_by(
    network: Network,
    prefix: &str,
    derived_pub_key: &Xpub,
) -> Result<Address, bitcoin::address::error::Error> {
    match prefix {
        "1" => {
            let pk = derived_pub_key.to_pub();
            Ok(Address::p2pkh(&pk, network))
        }
        "3" => {
            let pk = derived_pub_key.to_pub();
            let address = Address::p2shwpkh(&pk, network)?;
            Ok(address)
        }
        "bc1" => {
            let pk = derived_pub_key.to_pub();
            let address = Address::p2wpkh(&pk, network)?;
            Ok(address)
        }
        _ => Err(bitcoin::address::error::Error::UnrecognizedScript),
    }
}

/// Generate testnet address
pub fn generate_testnet_address(
    network: Network,
    derived_pub_key: &Xpub,
) -> Result<Address, bitcoin::address::error::Error> {
    let pk = derived_pub_key.to_pub();
    let addr = Address::p2wpkh(&pk, network)?;
    Ok(addr)
}

pub fn sign_tx_segwit(xpriv: Xpriv, address: Address) -> Transaction {
    let secp = Secp256k1::new();

    let (sk, wpkh) = senders_keys(xpriv, &secp);

    let (utxo_out_point, utxo) = dummy_unspent_transaction_output(&wpkh);

    let wif = xpriv.to_priv().to_wif();
    let signing_key = PrivateKey::from_wif(wif.as_str()).unwrap();
    let script_sig = Builder::new()
        .push_key(&signing_key.public_key(&secp))
        .into_script();

    let input = TxIn {
        previous_output: utxo_out_point,
        script_sig: script_sig, // For a p2wpkh script_sig is empty.
        sequence: Sequence::MAX,
        witness: Witness::default(), // Filled in after signing.
    };

    let spend = TxOut {
        value: SPEND_AMOUNT,
        script_pubkey: address.script_pubkey(),
    };

    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
    };

    let mut unsigned_tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![spend, change],
    };

    let input_index = 0;

    let sighash_type = EcdsaSighashType::All;
    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .p2wpkh_signature_hash(input_index, &utxo.script_pubkey, SPEND_AMOUNT, sighash_type)
        .expect("failed to create sighash");

    let msg = Message::from(sighash);
    let signature = secp.sign_ecdsa(&msg, &sk);

    let signature = Signature {
        sig: signature,
        hash_ty: sighash_type,
    };
    let pk = sk.public_key(&secp);
    *sighasher.witness_mut(input_index).unwrap() = Witness::p2wpkh(&signature, &pk);

    let tx = sighasher.into_transaction();
    return tx.clone();
}

fn senders_keys<C: Signing>(xpriv: Xpriv, secp: &Secp256k1<C>) -> (SecretKey, WPubkeyHash) {
    let sk = xpriv.private_key;
    let pk = bitcoin::PublicKey::new(sk.public_key(secp));
    let wpkh = pk.wpubkey_hash().expect("key is compressed");

    (sk, wpkh)
}

fn dummy_unspent_transaction_output(wpkh: &WPubkeyHash) -> (OutPoint, TxOut) {
    let script_pubkey = ScriptBuf::new_p2wpkh(wpkh);
    let dummy_txid = Txid::all_zeros();
    let out_point = OutPoint {
        txid: dummy_txid,
        vout: 0,
    };

    let utxo = TxOut {
        value: DUMMY_UTXO_AMOUNT,
        script_pubkey,
    };
    (out_point, utxo)
}
