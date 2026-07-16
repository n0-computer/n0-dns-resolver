use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        with_crypto_provider: { any(feature = "tls-ring", feature = "tls-aws-lc-rs") }
    }
}
