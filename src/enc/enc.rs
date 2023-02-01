pub trait Bruteforce {
    fn crack(self, encrypted_file: &str);
}

pub trait RainbowTable {
    fn generate_rainbow_table(self);
    fn test_generation_time(self);
    fn crack(self, encrypted_file: &str, rainbow_table: &str);
}