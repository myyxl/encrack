use std::{fs, process, thread};
use std::fs::File;
use std::io::{ Read, Write };
use base64::{engine, Engine};
use flate2::read::GzDecoder;
use libaes::Cipher;
use sha1_smol::Sha1;
use crate::enc::enc::Bruteforce;
use crate::util::{format_radix, get_xml_tag};

pub struct ENC2018 {
    pub thread_count: u64
}

impl ENC2018 {
    pub fn new(thread_count: u8) -> Self {
        ENC2018 {
            thread_count: thread_count.into()
        }
    }

    /*
        Microsoft's .NET implementation of PBKDF1 with 2 iterations
        SHA(SHA(password + salt)) + SHA("1" + SHA(password + salt))
     */
    pub fn derive_key(password: String) -> [u8; 32] {
        let password_salt: &[u8] = &[password.as_bytes(), &"s@1tCSCAG".as_bytes()].concat();
        let mut base_hash = Sha1::new();
        base_hash.update(password_salt);

        let mut first = Sha1::new();
        first.update(&base_hash.digest().bytes());

        let mut second = Sha1::new();
        second.update(&["1".as_bytes(), &base_hash.digest().bytes()].concat());

        let result: [u8; 40] = [first.digest().bytes(), second.digest().bytes()].concat().try_into().unwrap();
        <[u8; 32]>::try_from(&result[..32]).unwrap()
    }

}

impl Bruteforce for ENC2018 {

    /*
        Optimized by:
            1. Using base-8 for looping instead of base-10
            2. Multithreading
            3. Only decrypt the first block instead of the whole blob
     */
    fn crack(self, encrypted_file: &str) {
        let file_content = fs::read_to_string(encrypted_file).expect("Could not read the provided file name");
        let base64_content = get_xml_tag(&file_content, "Data");
        let mut encrypted_data: Vec<u8> = vec![];
        engine::general_purpose::STANDARD.decode_vec(base64_content, &mut encrypted_data).expect("Could not decode encrypted data");
        println!("Starting attack with {} threads..", self.thread_count);
        let mut threads = vec![];
        for thread_id in 0..self.thread_count {
            let part = (16777215.0 / self.thread_count as f64).ceil() as u64;
            let cloned_encrypted_data = encrypted_data.clone();
            threads.push(
                thread::spawn(move || {
                    for n in (thread_id * part)..((thread_id + 1) * part) + 1 {
                        let password = format!("{:0>8}", format_radix(n as u32, 8));
                        let derived_key = ENC2018::derive_key(password);
                        let cipher =  Cipher::new_256(&derived_key);
                        let gzip_header = cipher.cbc_decrypt("@1B2c2D5e5F6g0H9".as_bytes(), &cloned_encrypted_data.as_slice()[..16*5]);
                        if hex::encode(gzip_header).starts_with("1f8b0800000000000400") {
                            println!("Successfully cracked file!");
                            let decrypted_gzip = cipher.cbc_decrypt("@1B2c2D5e5F6g0H9".as_bytes(), &cloned_encrypted_data);
                            let mut decompressed_content = String::new();
                            GzDecoder::new(decrypted_gzip.as_slice()).read_to_string(&mut decompressed_content).expect("Could not decompress file");
                            let mut output = File::create("./decrypted.xml").expect("Could not create output file");
                            write!(output, "{}", decompressed_content).expect("Could not write to output file");
                            println!("Saved decrypted data as decrypted.xml");
                            process::exit(0);
                        }
                    }
                }));
        }
        for thread in threads {
            thread.join().unwrap()
        }
    }

}