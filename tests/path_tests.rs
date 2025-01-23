#[cfg(test)]
mod tests {
    use bn254_bls_keystore::mnemonics::path::path_to_nodes;

    #[test]
    fn test_path_to_nodes_valid() {
        let paths = [
            ("m/12381/3600/0/0/0", true),
            ("x/12381/3600/0/0/0", false),
            ("m/qwert/3600/0/0/0", false),
        ];

        for (path, valid) in &paths {
            if *valid {
                path_to_nodes(path).unwrap();
            } else {
                assert!(path_to_nodes(path).is_err());
            }
        }
    }
}
