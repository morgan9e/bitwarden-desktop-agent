
use bw_proto::oprf;

const SK_SM: &str = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e";

struct Vector {
    name: &'static str,
    input: &'static str,
    blind: &'static str,
    blinded_element: &'static str,
    evaluation_element: &'static str,
    output: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "A.1.1.1",
        input: "00",
        blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        blinded_element: "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
        evaluation_element: "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
        output: "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3\
                 ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
    },
    Vector {
        name: "A.1.1.2",
        input: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        blinded_element: "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
        evaluation_element: "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
        output: "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4\
                 f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73",
    },
];

fn unhex(s: &str) -> Vec<u8> {
    hex_decode(s).unwrap_or_else(|| panic!("bad hex in test vector: {s}"))
}

fn array32(s: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(unhex(s).as_slice()).expect("expected 32 bytes")
}

#[test]
fn blind_matches_the_specification() {
    for v in VECTORS {
        let (_, blinded) = oprf::blind_deterministic(&unhex(v.input), &array32(v.blind))
            .unwrap_or_else(|e| panic!("{}: blind failed: {e}", v.name));
        assert_eq!(
            blinded,
            array32(v.blinded_element),
            "{}: BlindedElement mismatch — the hash-to-group DST is wrong",
            v.name
        );
    }
}

#[test]
fn evaluate_matches_the_specification() {
    let key = array32(SK_SM);
    for v in VECTORS {
        let evaluated = oprf::evaluate(&key, &array32(v.blinded_element))
            .unwrap_or_else(|e| panic!("{}: evaluate failed: {e}", v.name));
        assert_eq!(
            evaluated,
            array32(v.evaluation_element),
            "{}: EvaluationElement mismatch",
            v.name
        );
    }
}

#[test]
fn finalize_matches_the_specification() {
    for v in VECTORS {
        let input = unhex(v.input);
        let (state, _) = oprf::blind_deterministic(&input, &array32(v.blind)).unwrap();
        let output = state
            .finalize(&input, &array32(v.evaluation_element))
            .unwrap_or_else(|e| panic!("{}: finalize failed: {e}", v.name));
        assert_eq!(
            output.as_slice(),
            unhex(v.output).as_slice(),
            "{}: Output mismatch",
            v.name
        );
    }
}

#[test]
fn the_full_exchange_matches_the_specification() {
    let key = array32(SK_SM);
    for v in VECTORS {
        let input = unhex(v.input);
        let (state, blinded) = oprf::blind_deterministic(&input, &array32(v.blind)).unwrap();
        let evaluated = oprf::evaluate(&key, &blinded).unwrap();
        let output = state.finalize(&input, &evaluated).unwrap();
        assert_eq!(output.as_slice(), unhex(v.output).as_slice(), "{}", v.name);
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
