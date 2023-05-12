extern crate core;

mod consts;
mod algo;

use std::env;
use algo::AES128;

fn main() {
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    if args.len() == 0 {
        panic!("Hey, give me some text man(woman,they,them... idk who you are)");
    }
    let key = args.remove(0);
    if key.as_bytes().len() != 16 {
        panic!("I'm waiting 16 bytes length key");
    }
    let aes = AES128::new(key);

    for text in args.iter() {
        println!("Plain text is \"{}\"", text);
        if text.len() != 16 {
            println!("But text is not 16 bytes len :(");
            continue;
        }
        let plaintext = text.as_bytes();

        let enc = aes.encrypt(plaintext);

        let dec = aes.decrypt(enc.as_ref());

        println!("Encrypted: {:?}\nDecrypted: {:?}\nMatching: {}", enc, String::from_utf8(dec.clone()).unwrap(), plaintext==dec);
    }
}


