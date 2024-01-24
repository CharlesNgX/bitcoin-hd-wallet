use bip39::{Language, Mnemonic};
use rand::RngCore;
use std::str::FromStr;

/// Menemonic count：12、15、18、21 or 24
pub fn mnemonic_generate(count: usize) -> Result<Mnemonic, bip39::Error> {
    if count % 3 != 0 {
        return Err(bip39::Error::BadEntropyBitCount(count));
    }
    let entropy_bytes_num = count / 3 * 4;
    let mut entropy = vec![0u8; entropy_bytes_num];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    Ok(mnemonic)
}

/// Recover mnemonic by words
pub fn mnemonic_by(words: &str) -> Result<Mnemonic, bip39::Error> {
    let mnemonic = Mnemonic::from_str(words)?;
    Ok(mnemonic)
}
