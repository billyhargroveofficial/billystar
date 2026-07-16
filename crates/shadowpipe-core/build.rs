use std::{env, fs, path::Path};

fn main() {
    // The wire magic is part of the client/server compatibility contract.  In
    // particular, cross-target release artifacts are normally built in
    // separate target directories, so Cargo must rebuild this script whenever
    // the operator changes the shared value.
    println!("cargo:rerun-if-env-changed=SHADOWPIPE_MAGIC");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let dest = Path::new(&out_dir).join("magic.rs");

    let magic: u32 = match env::var("SHADOWPIPE_MAGIC") {
        Ok(seed) => parse_magic(&seed).unwrap_or_else(|_| {
            panic!(
                "invalid SHADOWPIPE_MAGIC {seed:?}: expected a u32 in decimal or 0x-prefixed hex"
            )
        }),
        Err(_) if env::var("PROFILE").as_deref() == Ok("release") => {
            panic!(
                "release builds require an explicit SHADOWPIPE_MAGIC so independently built client/server artifacts and evidence manifests cannot silently diverge"
            )
        }
        Err(_) => random_magic(),
    };

    fs::write(
        &dest,
        format!("pub const BUILD_MAGIC: u32 = {magic:#010x};"),
    )
    .expect("write magic.rs");
}

fn parse_magic(seed: &str) -> Result<u32, ()> {
    let seed = seed.trim();
    if let Some(hex) = seed.strip_prefix("0x").or_else(|| seed.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        seed.parse().map_err(|_| ())
    }
}

fn random_magic() -> u32 {
    use rand::RngCore;
    rand::thread_rng().next_u32()
}
