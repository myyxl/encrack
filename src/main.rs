extern crate core;
use clap::{Parser, Subcommand};
use crate::enc::enc::{Bruteforce, RainbowTable};
use crate::enc::version_2018::ENC2018;
use crate::enc::version_2021::ENC2021;

mod enc;
mod util;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ENC version file was encrypted for
    #[arg(short, long, value_name = "2018|2021", required = true)]
    enc: String,

    /// Thread count
    #[arg(short, long, value_name = "threads", required = true)]
    threads: u8,

    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    /// Crack the xml file
    Crack {
        /// path to encrypted xml file
        #[arg(short, long, value_name = "encrypted-file", required = true)]
        file: String,
        /// path to rainbow table
        #[arg(short, long, value_name = "rainbow-table")]
        rainbow_table: String,
    },
    /// Generate the rainbow table
    Generate,
    /// Estimate the generation time
    TestGenerate
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Crack { file, rainbow_table } => {
            match cli.enc.as_str() {
                "2018" => ENC2018::new(cli.threads).crack(file),
                "2021" => ENC2021::new(cli.threads).crack(file, rainbow_table),
                _ => {}
            }
        },
        Commands::Generate => {
            match cli.enc.as_str() {
                "2021" => ENC2021::new(cli.threads).generate_rainbow_table(),
                _ => {}
            }
        },
        Commands::TestGenerate => {
            match cli.enc.as_str() {
                "2021" => ENC2021::new(cli.threads).test_generation_time(),
                _ => {}
            }
        }
    }

}
