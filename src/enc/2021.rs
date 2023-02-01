use std::fs::{File, OpenOptions};
use std::{fs, process, thread};
use std::time::SystemTime;
use fastpbkdf2::pbkdf2_hmac_sha256;
use std::io::{BufRead, BufReader, Read, Write};
use base64::{engine, Engine};
use flate2::read::GzDecoder;
use libaes::Cipher;
use crate::enc::enc::RainbowTable;
use crate::util::{format_radix, get_xml_tag};

pub struct ENC2021 {
    pub salt: [u8; 42],
    pub iterations: u32,
    pub thread_count: u64
}

impl ENC2021 {
    pub fn new(thread_count: u8) -> Self {
        ENC2021 {
            salt: [0x33,0x30,0x34,0x39,0x38,0x33,0x65,0x66,0x6a,0x61,0x70,0x3f,0x6f,0x33,0x69,0x36,0x35,0x32,0x38,0x61,0x70,0x73,0x69,0x65,0x64,0x66,0x39,0x32,0x66,0x71,0x70,0x77,0x39,0x33,0x39,0x32,0x71,0x77,0x70,0x61,0x39,0x33],
            iterations: 400000,
            thread_count: thread_count.into()
        }
    }
}

impl RainbowTable for ENC2021 {
    fn generate_rainbow_table(self) {
        println!("Starting generation with {} threads..", self.thread_count);
        let mut threads = vec![];
        for thread_id in 0..self.thread_count {
            let part = (16777215.0 / self.thread_count as f64).ceil() as u64;
            threads.push(
                thread::spawn(move || {
                    let mut file = OpenOptions::new().create(true).append(true).open(format!("thread_{}.txt", thread_id)).unwrap();
                    for n in (thread_id * part)..((thread_id + 1) * part) + 1 {
                        let password = format!("{:0>8}", format_radix(n as u32, 8));
                        let mut out = [0u8; 32];
                        pbkdf2_hmac_sha256(password.as_bytes(), &self.salt, self.iterations, &mut out);
                        writeln!(file, "{}:{}", password, hex::encode(out)).unwrap();
                    }
                }));
        }
        for thread in threads {
            thread.join().unwrap()
        }
        println!("Finished generating");
    }

    fn test_generation_time(self) {
        println!("Testing generation of 10k hashes with {} threads", self.thread_count);
        let mut threads = vec![];
        let start_time = SystemTime::now();
        for _ in 0..self.thread_count {
            let part = (10000.0 / self.thread_count as f64).ceil() as u64;
            threads.push(
                thread::spawn(move || {
                    let password = b"00000000";
                    for _ in 1..part {
                        let mut out = [0u8; 32];
                        pbkdf2_hmac_sha256(password, &self.salt, self.iterations, &mut out);
                    }
                }));
        }
        for thread in threads {
            thread.join().unwrap()
        }
        let time = SystemTime::now().duration_since(start_time).unwrap().as_secs() as f64;
        let generation_time = (time / 10000.0) * 16777215.0;
        println!("Generation of rainbow table with {} threads will take approximately {}s / {}h / {}d", self.thread_count, generation_time as i64, (generation_time / 60_f64 / 60_f64) as i64, (generation_time / 60_f64 / 60_f64 / 24_f64).round() as i64);
    }

    fn crack(self, encrypted_file: &str, rainbow_table: &str) {
        let file_content = fs::read_to_string(encrypted_file).expect("Could not read the provided file name");
        let base64_content = get_xml_tag(&file_content, "Data");
        let mut encrypted_data: Vec<u8> = vec![];
        engine::general_purpose::STANDARD.decode_vec(base64_content, &mut encrypted_data).expect("Could not decode encrypted data");

        let rainbow_table_file = File::open(rainbow_table).unwrap();
        let reader = BufReader::new(rainbow_table_file);
        println!("Loading rainbow table into memory..");
        let list: Vec<String> = reader.lines().filter_map(|result| result.ok()).collect();
        let chunk_size = (16777215.0 / self.thread_count as f64).ceil() as usize;
        let chunks: Vec<Vec<String>> = list.chunks(chunk_size).map(|s| s.into()).collect();

        println!("Starting attack with {} threads..", self.thread_count);
        let mut threads = vec![];
        for thread_id in 0..self.thread_count as usize {
            let chunk = chunks[thread_id].clone();
            let cloned_encrypted_data = encrypted_data.clone();
            threads.push(
                thread::spawn(move || {
                    for line in chunk {
                        let string_key = line.split(":").collect::<Vec<&str>>()[1].trim();
                        let key: [u8; 32] = hex::decode(string_key).unwrap().as_slice().try_into().unwrap();
                        let cipher =  Cipher::new_256(&key);
                        let gzip_header = cipher.cbc_decrypt("$Ikdj8372NSUdzE%".as_bytes(), &cloned_encrypted_data.as_slice()[..16*7]);
                        if hex::encode(gzip_header).starts_with("1f8b0800000000000400") {
                            println!("Successfully cracked file!");
                            let decrypted_gzip = cipher.cbc_decrypt("$Ikdj8372NSUdzE%".as_bytes(), &cloned_encrypted_data);
                            let mut decompressed_content = String::new();
                            GzDecoder::new(decrypted_gzip.as_slice()).read_to_string(&mut decompressed_content).expect("Could not decompress file");
                            let mut output = File::create("./decrypted.xml").expect("Could not create output file");
                            write!(output, "{}", decompressed_content).expect("Could not write to output file");
                            println!("Saved decrypted data as decrypted.xml");
                            process::exit(0);
                        }
                    }
                })
            );
        }
        for thread in threads {
            thread.join().unwrap();
        }
    }
}