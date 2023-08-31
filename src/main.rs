use clap::Parser;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use xxhash_rust::const_xxh3::const_custom_default_secret;
use xxhash_rust::xxh3::{
    xxh3_128_with_secret, xxh3_128_with_seed, xxh3_128,
    xxh3_64_with_secret, xxh3_64_with_seed, xxh3_64,
};
use xxhash_rust::xxh32::xxh32;

#[derive(clap::ValueEnum, Clone, Debug)]
enum Algorithm {
   Xx128,
   Xx64,
   Xx32,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File name to hash
    #[arg(short = 'f', long)]
    filename: String,
    #[arg(short = 's', long, default_value="131072")]
    size: u64,
    #[clap(value_enum, short = 'a', long, default_value_t=Algorithm::Xx128)]
    algorithm: Algorithm,
    #[arg(short = 'e', long, default_value="0")]
    seed: u64,
    #[arg(short = 'r', long, default_value="")]
    secret: String,
    #[arg(short = 'g', long)]
    generatesecret: bool,
    #[arg(short = 'p', long)]
    print: bool,
}

fn main() {
    let args = Args::parse();

    let binding = args.filename.trim();
    let input_path = Path::new(&binding);
    let path_canonicalized = match input_path.canonicalize() {
        Ok(result) => result,
        Err(e) => {
            println!("Error while canonicalizing {:?}", e);
            return;
        }
    };
    let path_os_string = path_canonicalized.as_os_str();
    if args.print {
        println!("Hash on file : {:#?}", path_os_string);
    }
    let f = match File::open(path_os_string) {
        Ok(result) => result,
        Err(e) => {
            println!("Error while opening the file {:?}", e);
            return;
        }
    };
    let mut reader = BufReader::new(f);
    let size = match reader.seek(SeekFrom::End(0)) {
        Ok(result) => result,
        Err(e) => {
            println!("Error while seeking {:?}", e);
            return;
        }
    };
    if args.print {
        println!("File size : {}", size);
    }

    let mut default_seed: u64 = 345456657563;

    let mut secret: String = args.secret.clone();
    let mut seed: u64 = 0;

    if args.seed != 0 {
        default_seed = args.seed;
        seed = args.seed;
    }

    if args.generatesecret {
        let secretarr = const_custom_default_secret(default_seed);
        secret = match std::str::from_utf8(&secretarr) {
            Ok(r) => r.to_string(),
            Err(e) => {
                println!("Error while generating default secrt {:?}", e);
                return;
            }
        };
    }

    if args.print {
        println!("Defalt seed : {}", default_seed);
        println!("Input seed : {}", seed);
        println!("Input Secret : {}", args.secret);
        println!("Calculated Secret : {}", secret);
    }

    match args.algorithm {
        Algorithm::Xx128 => {
            let mut pos: u64 = 0;
            while pos <= size {
                let mut buffer = vec![0u8; args.size as usize];
                let _ = match reader.seek(SeekFrom::Start(pos)) {
                    Ok(result) => result,
                    Err(e) => {
                        println!("Error while seeking {:?} at pos {}", e, pos);
                        return;
                    }
                };
                if args.print {
                    print!("Reading from {}-{},", pos, buffer.len());
                }
                match reader.read(buffer.as_mut_slice()) {
                    Ok(readsize) => {
                        if args.print {
                            // println!("Content {:#?} [read: {}]", buffer.as_slice().clone(), readsize);
                            println!("[read: {}]", readsize);
                        }
                        if !secret.is_empty() {
                            let r = xxh3_128_with_secret(buffer.as_slice(), secret.as_bytes());
                            if args.print {
                                println!("{} - {}: {}", pos, pos + args.size, r);
                            }
                        } else if seed != 0 {
                            let r = xxh3_128_with_seed(buffer.as_slice(), seed);
                            if args.print {
                                println!("{} - {}: {}", pos, pos + args.size, r);
                            }
                        } else {
                            let r = xxh3_128(buffer.as_slice());
                            if args.print {
                                println!("{} - {}: {}", pos, pos + args.size, r);
                            }
                        }
                        pos = pos + args.size;
                    },
                    Err(e) => {
                        println!("Error {:?} while reading at offset {}", e, pos);
                        return;
                    }
                };
            }
        },
        Algorithm::Xx64 => {
            let mut pos: u64 = 0;
            while pos <= size {
                let mut buffer = vec![0u8; args.size as usize];
                let _ = match reader.seek(SeekFrom::Start(pos)) {
                    Ok(result) => result,
                    Err(e) => {
                        println!("Error while seeking {:?} at pos {}", e, pos);
                        return;
                    }
                };
                if args.print {
                    print!("Reading from {}-{},", pos, buffer.len());
                }
                match reader.read(buffer.as_mut_slice()) {
                    Ok(readsize) => {
                        if args.print {
                            // println!("Content {:#?} [read: {}]", buffer.as_slice().clone(), readsize);
                            println!("[read: {}]", readsize);
                        }
                        if !secret.is_empty() {
                            let r = xxh3_64_with_secret(buffer.as_slice(), secret.as_bytes());
                            if args.print {
                                println!("{} - {}: {}", pos, pos + args.size, r);
                            }
                        } else if seed != 0 {
                            let r = xxh3_64_with_seed(buffer.as_slice(), seed);
                            if args.print {
                                println!("{} - {}: {}", pos, pos + args.size, r);
                            }
                        } else {
                            let r = xxh3_64(buffer.as_slice());
                            if args.print {
                                println!("{} - {}: {}", pos, pos + args.size, r);
                            }
                        }
                        pos = pos + args.size
                    },
                    Err(e) => {
                        println!("Error {:?} while reading at offset {}", e, pos);
                        return;
                    }
                };
            }
        },
        Algorithm::Xx32 => {
            let mut pos: u64 = 0;
            while pos <= size {
                let mut buffer = vec![0u8; args.size as usize];
                let _ = match reader.seek(SeekFrom::Start(pos)) {
                    Ok(result) => result,
                    Err(e) => {
                        println!("Error while seeking {:?} at pos {}", e, pos);
                        return;
                    }
                };
                if args.print {
                    print!("Reading from {}-{},", pos, buffer.len());
                }
                match reader.read(buffer.as_mut_slice()) {
                    Ok(readsize) => {
                        if args.print {
                            // println!("Content {:#?} [read: {}]", buffer.as_slice().clone(), readsize);
                            println!("[read: {}]", readsize);
                        }
                        let r = xxh32(buffer.as_slice(), (default_seed as u64).try_into().unwrap());
                        if args.print {
                            println!("{} - {}: {}", pos, pos + args.size, r);
                        }
                        pos = pos + args.size
                    },
                    Err(e) => {
                        println!("Error {:?} while reading at offset {}", e, pos);
                        return;
                    }
                };
            }
        },
    };
}
