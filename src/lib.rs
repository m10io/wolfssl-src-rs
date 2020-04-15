//! Source of wolfSSL and logic to build it.
//!
//! Largely based off the [`openssl-src`](https://github.com/alexcrichton/openssl-src-rs) crate.

use bitflags::bitflags;
use std::{
    env,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

bitflags! {
    pub struct FeatureFlags: usize {
        const TLS13 = 0b0001;
        const CURVE25519 = 0b0010;
        const ED25519 = 0b0100;
    }
}

pub fn source_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("wolfssl")
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub struct Build {
    out_dir: Option<PathBuf>,
    target: Option<String>,
    host: Option<String>,
    features: FeatureFlags,
    force_sgx: bool,
}

pub struct Artifacts {
    include_dir: PathBuf,
    lib_dir: PathBuf,
    lib: String,
}

impl Build {
    pub fn new() -> Build {
        Build {
            out_dir: env::var_os("OUT_DIR").map(|s| PathBuf::from(s).join("wolfssl-build")),
            target: env::var("TARGET").ok(),
            host: env::var("HOST").ok(),
            features: FeatureFlags::empty(),
            force_sgx: false,
        }
    }

    pub fn out_dir<P: AsRef<Path>>(&mut self, path: P) -> &mut Build {
        self.out_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn target(&mut self, target: &str) -> &mut Build {
        self.target = Some(target.to_string());
        self
    }

    pub fn host(&mut self, host: &str) -> &mut Build {
        self.host = Some(host.to_string());
        self
    }

    pub fn set_features(&mut self, flags: FeatureFlags) -> &mut Build {
        self.features.insert(flags);
        self
    }

    pub fn clear_features(&mut self, flags: FeatureFlags) -> &mut Build {
        self.features.remove(flags);
        self
    }

    pub fn force_sgx(&mut self, force: bool) -> &mut Build {
        self.force_sgx = force;
        self
    }

    fn cmd_make(&self) -> Command {
        match &self.host.as_ref().expect("HOST dir not set")[..] {
            "x86_64-unknown-dragonfly" => Command::new("gmake"),
            "x86_64-unknown-freebsd" => Command::new("gmake"),
            _ => Command::new("make"),
        }
    }

    pub fn build(&mut self) -> Artifacts {
        let target = &self.target.as_ref().expect("TARGET dir not set")[..];
        let host = &self.host.as_ref().expect("HOST dir not set")[..];
        let out_dir = self.out_dir.as_ref().expect("OUT_DIR not set");
        let build_dir = out_dir.join("build");
        let install_dir = out_dir.join("install");

        if build_dir.exists() {
            fs::remove_dir_all(&build_dir).unwrap();
        }

        if install_dir.exists() {
            fs::remove_dir_all(&install_dir).unwrap();
        }

        // Automatically enable Curve25519 support if Ed25519 support is requested.
        let mut features = self.features;
        if features.intersects(FeatureFlags::ED25519) {
            features.insert(FeatureFlags::CURVE25519);
        }

        let inner_dir = build_dir.join("src");
        fs::create_dir_all(&inner_dir).unwrap();
        cp_r(&source_dir(), &inner_dir);
        apply_patches(features, &inner_dir);

        // Run the custom Makefile instead of using autogen/configure/make for SGX builds.
        if self.force_sgx || target.ends_with("-sgx") {
            let mut make = self.cmd_make();
            make.args(&["-f", "sgx_t_static.mk", "all"])
                .current_dir(inner_dir.join("IDE/LINUX-SGX"));
            self.run_command(make, "building wolfSSL for SGX");

            // Makefile doesn't install to a prefix, so copy build artifacts manually.
            let public_includes = [
                "wolfssl/callbacks.h",
                "wolfssl/certs_test.h",
                "wolfssl/crl.h",
                "wolfssl/error-ssl.h",
                "wolfssl/ocsp.h",
                "wolfssl/sniffer_error.h",
                "wolfssl/sniffer.h",
                "wolfssl/ssl.h",
                "wolfssl/test.h",
                "wolfssl/version.h",
                "wolfssl/wolfio.h",
                "wolfssl/openssl/aes.h",
                "wolfssl/openssl/asn1.h",
                "wolfssl/openssl/bio.h",
                "wolfssl/openssl/bn.h",
                "wolfssl/openssl/buffer.h",
                "wolfssl/openssl/conf.h",
                "wolfssl/openssl/crypto.h",
                "wolfssl/openssl/des.h",
                "wolfssl/openssl/dh.h",
                "wolfssl/openssl/dsa.h",
                "wolfssl/openssl/ec.h",
                "wolfssl/openssl/ec25519.h",
                "wolfssl/openssl/ecdh.h",
                "wolfssl/openssl/ecdsa.h",
                "wolfssl/openssl/ed25519.h",
                "wolfssl/openssl/engine.h",
                "wolfssl/openssl/err.h",
                "wolfssl/openssl/evp.h",
                "wolfssl/openssl/hmac.h",
                "wolfssl/openssl/lhash.h",
                "wolfssl/openssl/md4.h",
                "wolfssl/openssl/md5.h",
                "wolfssl/openssl/objects.h",
                "wolfssl/openssl/ocsp.h",
                "wolfssl/openssl/opensslconf.h",
                "wolfssl/openssl/opensslv.h",
                "wolfssl/openssl/ossl_typ.h",
                "wolfssl/openssl/pem.h",
                "wolfssl/openssl/pkcs12.h",
                "wolfssl/openssl/pkcs7.h",
                "wolfssl/openssl/rand.h",
                "wolfssl/openssl/rc4.h",
                "wolfssl/openssl/ripemd.h",
                "wolfssl/openssl/rsa.h",
                "wolfssl/openssl/sha.h",
                "wolfssl/openssl/ssl.h",
                "wolfssl/openssl/ssl23.h",
                "wolfssl/openssl/stack.h",
                "wolfssl/openssl/tls1.h",
                "wolfssl/openssl/ui.h",
                "wolfssl/openssl/x509_vfy.h",
                "wolfssl/openssl/x509.h",
                "wolfssl/openssl/x509v3.h",
                "wolfssl/wolfcrypt/aes.h",
                "wolfssl/wolfcrypt/arc4.h",
                "wolfssl/wolfcrypt/asn.h",
                "wolfssl/wolfcrypt/asn_public.h",
                "wolfssl/wolfcrypt/blake2.h",
                "wolfssl/wolfcrypt/blake2-impl.h",
                "wolfssl/wolfcrypt/blake2-int.h",
                "wolfssl/wolfcrypt/camellia.h",
                "wolfssl/wolfcrypt/chacha20_poly1305.h",
                "wolfssl/wolfcrypt/chacha.h",
                "wolfssl/wolfcrypt/cmac.h",
                "wolfssl/wolfcrypt/coding.h",
                "wolfssl/wolfcrypt/compress.h",
                "wolfssl/wolfcrypt/cpuid.h",
                "wolfssl/wolfcrypt/cryptocb.h",
                "wolfssl/wolfcrypt/curve25519.h",
                "wolfssl/wolfcrypt/des3.h",
                "wolfssl/wolfcrypt/dh.h",
                "wolfssl/wolfcrypt/dsa.h",
                "wolfssl/wolfcrypt/ecc.h",
                "wolfssl/wolfcrypt/ed25519.h",
                "wolfssl/wolfcrypt/error-crypt.h",
                "wolfssl/wolfcrypt/fe_operations.h",
                "wolfssl/wolfcrypt/fips_test.h",
                "wolfssl/wolfcrypt/ge_operations.h",
                "wolfssl/wolfcrypt/hash.h",
                "wolfssl/wolfcrypt/hc128.h",
                "wolfssl/wolfcrypt/hmac.h",
                "wolfssl/wolfcrypt/idea.h",
                "wolfssl/wolfcrypt/integer.h",
                "wolfssl/wolfcrypt/logging.h",
                "wolfssl/wolfcrypt/md2.h",
                "wolfssl/wolfcrypt/md4.h",
                "wolfssl/wolfcrypt/md5.h",
                "wolfssl/wolfcrypt/memory.h",
                "wolfssl/wolfcrypt/mem_track.h",
                "wolfssl/wolfcrypt/misc.h",
                "wolfssl/wolfcrypt/mpi_class.h",
                "wolfssl/wolfcrypt/mpi_superclass.h",
                "wolfssl/wolfcrypt/pkcs12.h",
                "wolfssl/wolfcrypt/pkcs7.h",
                "wolfssl/wolfcrypt/poly1305.h",
                "wolfssl/wolfcrypt/pwdbased.h",
                "wolfssl/wolfcrypt/rabbit.h",
                "wolfssl/wolfcrypt/random.h",
                "wolfssl/wolfcrypt/ripemd.h",
                "wolfssl/wolfcrypt/rsa.h",
                "wolfssl/wolfcrypt/settings.h",
                "wolfssl/wolfcrypt/sha256.h",
                "wolfssl/wolfcrypt/sha3.h",
                "wolfssl/wolfcrypt/sha512.h",
                "wolfssl/wolfcrypt/sha.h",
                "wolfssl/wolfcrypt/signature.h",
                "wolfssl/wolfcrypt/srp.h",
                "wolfssl/wolfcrypt/tfm.h",
                "wolfssl/wolfcrypt/types.h",
                "wolfssl/wolfcrypt/visibility.h",
                "wolfssl/wolfcrypt/wc_encrypt.h",
                "wolfssl/wolfcrypt/wc_port.h",
                "wolfssl/wolfcrypt/wolfevent.h",
                "wolfssl/wolfcrypt/wolfmath.h",
            ];

            let include_install_dir = install_dir.join("include");
            fs::create_dir_all(include_install_dir.join("wolfssl/openssl")).unwrap();
            fs::create_dir_all(include_install_dir.join("wolfssl/wolfcrypt")).unwrap();
            for &include in &public_includes[..] {
                fs::copy(inner_dir.join(include), include_install_dir.join(include)).unwrap();
            }

            let lib_install_dir = install_dir.join("lib");
            fs::create_dir_all(&lib_install_dir).unwrap();
            fs::copy(
                inner_dir.join("IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a"),
                lib_install_dir.join("libwolfssl.a"),
            )
            .unwrap();
        } else {
            let mut autogen = Command::new("sh");
            autogen.arg("./autogen.sh").current_dir(&inner_dir);
            self.run_command(autogen, "generating configure script");

            let mut configure = Command::new("sh");
            configure.args(&[
                "./configure",
                &format!("--build={}", host),
                &format!("--host={}", target),
                &if host.contains("pc-windows-gnu") {
                    format!("--prefix={}", sanitize_sh(&install_dir))
                } else {
                    format!("--prefix={}", install_dir.display())
                },
                // Build static libraries only (no shared libraries).
                "--enable-static",
                "--disable-shared",
            ]);

            if features.intersects(FeatureFlags::TLS13) {
                configure.arg("--enable-tls13");
            }

            if features.intersects(FeatureFlags::CURVE25519) {
                configure.arg("--enable-curve25519");
            }

            if features.intersects(FeatureFlags::ED25519) {
                configure.arg("--enable-ed25519");
            }

            configure.current_dir(&inner_dir);
            self.run_command(configure, "configuring wolfSSL build");

            let mut build = self.cmd_make();
            build.current_dir(&inner_dir);
            self.run_command(build, "building wolfSSL");

            let mut install = self.cmd_make();
            install.arg("install").current_dir(&inner_dir);
            self.run_command(install, "installing wolfSSL");
        }

        fs::remove_dir_all(&inner_dir).unwrap();

        Artifacts {
            lib_dir: install_dir.join("lib"),
            include_dir: install_dir.join("include"),
            lib: "wolfssl".into(),
        }
    }

    fn run_command(&self, mut command: Command, desc: &str) {
        println!("running {:?}", command);
        let status = command.status().unwrap();
        if !status.success() {
            panic!(
                "
Error {}:
    Command: {:?}
    Exit status: {}
    ",
                desc, command, status
            );
        }
    }
}

impl Default for Build {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

fn cp_r(src: &Path, dst: &Path) {
    for f in fs::read_dir(src).unwrap() {
        let f = f.unwrap();
        let path = f.path();
        let name = path.file_name().unwrap();

        // Skip git metadata as it's been known to cause issues (#26) and
        // otherwise shouldn't be required
        if name.to_str() == Some(".git") {
            continue;
        }

        let dst = dst.join(name);
        if f.file_type().unwrap().is_dir() {
            fs::create_dir_all(&dst).unwrap();
            cp_r(&path, &dst);
        } else {
            let _ = fs::remove_file(&dst);
            fs::copy(&path, &dst).unwrap();
        }
    }
}

fn apply_patches(features: FeatureFlags, inner: &Path) {
    // Manually enable features for SGX that are not part of the default Makefile and settings.
    let mut sgx_files = vec![];
    let mut sgx_defines = vec![];

    if features.intersects(FeatureFlags::TLS13) {
        sgx_defines.push("    #define WOLFSSL_TLS13");
        sgx_defines.push("    #define HAVE_TLS_EXTENSIONS");
        sgx_defines.push("    #define HAVE_SUPPORTED_CURVES");
    }

    if features.intersects(FeatureFlags::CURVE25519) {
        sgx_files.push("$(WOLFSSL_ROOT)/wolfcrypt/src/curve25519.c");
        sgx_defines.push("    #define HAVE_CURVE25519");
    }

    if features.intersects(FeatureFlags::ED25519) {
        sgx_files.push("$(WOLFSSL_ROOT)/wolfcrypt/src/ed25519.c");
        sgx_files.push("$(WOLFSSL_ROOT)/wolfcrypt/src/fe_operations.c");
        sgx_files.push("$(WOLFSSL_ROOT)/wolfcrypt/src/ge_operations.c");
        sgx_defines.push("    #define WOLFSSL_SHA512");
        sgx_defines.push("    #define HAVE_ED25519");
    }

    if !sgx_files.is_empty() {
        do_patch(inner.join("IDE/LINUX-SGX/sgx_t_static.mk"), |buf| {
            *buf = buf.replace(
                "Wolfssl_C_Files :=",
                &format!("Wolfssl_C_Files :={} ", sgx_files.join(" "),),
            );
        });
        do_patch(inner.join("wolfssl/wolfcrypt/settings.h"), |buf| {
            *buf = buf.replace(
                "#endif /* WOLFSSL_SGX */",
                &format!("{}\n#endif /* WOLFSSL_SGX */", sgx_defines.join("\n")),
            );
        });
    }
}

fn do_patch(path: impl AsRef<Path>, f: impl FnOnce(&mut String)) {
    let path_ref = path.as_ref();

    let mut buf = String::new();
    File::open(path_ref)
        .unwrap()
        .read_to_string(&mut buf)
        .unwrap();

    f(&mut buf);

    File::create(path_ref)
        .unwrap()
        .write_all(buf.as_bytes())
        .unwrap();
}

fn sanitize_sh(path: &Path) -> String {
    if !cfg!(windows) {
        return path.to_str().unwrap().to_string();
    }
    let path = path.to_str().unwrap().replace("\\", "/");
    return change_drive(&path).unwrap_or(path);

    fn change_drive(s: &str) -> Option<String> {
        let mut ch = s.chars();
        let drive = ch.next().unwrap_or('C');
        if ch.next() != Some(':') {
            return None;
        }
        if ch.next() != Some('/') {
            return None;
        }
        Some(format!("/{}/{}", drive, &s[drive.len_utf8() + 2..]))
    }
}

impl Artifacts {
    pub fn include_dir(&self) -> &Path {
        &self.include_dir
    }

    pub fn lib_dir(&self) -> &Path {
        &self.lib_dir
    }

    pub fn lib(&self) -> &str {
        &self.lib
    }

    pub fn print_cargo_metadata(&self) {
        println!("cargo:rustc-link-search=native={}", self.lib_dir.display());
        println!("cargo:rustc-link-lib=static={}", self.lib);
        println!("cargo:include={}", self.include_dir.display());
        println!("cargo:lib={}", self.lib_dir.display());
    }
}
