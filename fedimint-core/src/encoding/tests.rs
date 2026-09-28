use std::fmt::Debug;
use std::io::Cursor;

use super::{
    DecodeContext, DecodeError, Duration, MAX_DECODE_SIZE, ModuleDecoderRegistry, UNIX_EPOCH,
    decode_field_from_finite_reader, decode_legacy_option_system_time_from_finite_reader,
    decode_legacy_system_time_from_finite_reader, encode_legacy_option_system_time,
    encode_legacy_system_time, with_decoding_context,
};
use crate::encoding::{Decodable, Encodable};
use crate::module::registry::ModuleRegistry;
use crate::util::FmtCompact as _;

pub(crate) fn test_roundtrip<T>(value: &T)
where
    T: Encodable + Decodable + Eq + Debug,
{
    let mut bytes = Vec::new();
    value.consensus_encode(&mut bytes).unwrap();

    let mut cursor = Cursor::new(bytes);
    let decoded =
        T::consensus_decode_partial(&mut cursor, &ModuleDecoderRegistry::default()).unwrap();
    assert_eq!(value, &decoded);
}

pub(crate) fn test_roundtrip_expected<T>(value: &T, expected: &[u8])
where
    T: Encodable + Decodable + Eq + Debug,
{
    let mut bytes = Vec::new();
    value.consensus_encode(&mut bytes).unwrap();
    assert_eq!(&expected, &bytes);

    let mut cursor = Cursor::new(bytes);
    let decoded =
        T::consensus_decode_partial(&mut cursor, &ModuleDecoderRegistry::default()).unwrap();
    assert_eq!(value, &decoded);
}

#[derive(Debug, Eq, PartialEq, Encodable, Decodable)]
enum NoDefaultEnum {
    Foo,
    Bar(u32, String),
    Baz { baz: u8 },
}

#[derive(Debug, Eq, PartialEq, Encodable, Decodable)]
enum DefaultEnum {
    Foo,
    Bar(u32, String),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

#[test_log::test]
fn test_derive_enum_no_default_roundtrip_success() {
    let enums = [
        NoDefaultEnum::Foo,
        NoDefaultEnum::Bar(
            42,
            "The answer to life, the universe, and everything".to_string(),
        ),
        NoDefaultEnum::Baz { baz: 0 },
    ];

    for e in enums {
        test_roundtrip(&e);
    }
}

#[test_log::test]
fn test_derive_enum_no_default_decode_fail() {
    let unknown_variant = DefaultEnum::Default {
        variant: 42,
        bytes: vec![0, 1, 2, 3],
    };
    let mut unknown_variant_encoding = vec![];
    unknown_variant
        .consensus_encode(&mut unknown_variant_encoding)
        .unwrap();

    let mut cursor = Cursor::new(&unknown_variant_encoding);
    let decode_res =
        NoDefaultEnum::consensus_decode_partial(&mut cursor, &ModuleRegistry::default());

    match decode_res {
        Ok(_) => panic!("Should return error"),
        Err(e) => assert!(e.to_string().contains("Invalid enum variant")),
    }
}

#[test_log::test]
fn test_derive_enum_default_decode_success() {
    let unknown_variant = NoDefaultEnum::Baz { baz: 123 };
    let mut unknown_variant_encoding = vec![];
    unknown_variant
        .consensus_encode(&mut unknown_variant_encoding)
        .unwrap();

    let mut cursor = Cursor::new(&unknown_variant_encoding);
    let decode_res = DefaultEnum::consensus_decode_partial(&mut cursor, &ModuleRegistry::default());

    assert_eq!(
        decode_res.unwrap(),
        DefaultEnum::Default {
            variant: 2,
            bytes: vec![123],
        }
    );
}

#[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
struct TestStruct {
    vec: Vec<u8>,
    num: u32,
}

#[test_log::test]
fn test_derive_struct() {
    let reference = TestStruct {
        vec: vec![1, 2, 3],
        num: 42,
    };
    let bytes = [3, 1, 2, 3, 42];

    test_roundtrip_expected(&reference, &bytes);
}

#[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
struct TestTupleStruct(Vec<u8>, u32);

#[derive(Debug)]
struct TestFiniteReader;

impl Decodable for TestFiniteReader {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let _: Vec<u8> = decode_field_from_finite_reader(
            reader,
            modules,
            "Decoding tuple block TestFiniteReader field field_0",
        )?;
        let _: Vec<u8> = decode_field_from_finite_reader(
            reader,
            modules,
            "Decoding tuple block TestFiniteReader field field_1",
        )?;
        Ok(Self)
    }
}

#[test_log::test]
fn test_derive_tuple_struct() {
    let reference = TestTupleStruct(vec![1, 2, 3], 42);
    let bytes = [3, 1, 2, 3, 42];

    test_roundtrip_expected(&reference, &bytes);
}

#[test_log::test]
fn test_legacy_system_time_encoding() {
    let time = UNIX_EPOCH + Duration::new(42, 100);
    let expected = [42, 100];
    let mut bytes = vec![];
    encode_legacy_system_time(&time, &mut bytes).expect("encoding to a vector cannot fail");
    assert_eq!(bytes, expected);

    let mut cursor = Cursor::new(expected);
    let decoded = decode_legacy_system_time_from_finite_reader(
        &mut cursor,
        &ModuleDecoderRegistry::default(),
    )
    .expect("valid encoding");
    assert_eq!(decoded, time);
}

#[test_log::test]
fn test_client_backup_snapshot_uses_legacy_system_time_encoding() {
    let reference = crate::backup::ClientBackupSnapshot {
        timestamp: UNIX_EPOCH + Duration::new(42, 100),
        data: vec![1, 2, 3],
    };
    let expected = [42, 100, 3, 1, 2, 3];

    test_roundtrip_expected(&reference, &expected);
}

#[test_log::test]
fn test_legacy_optional_system_time_encoding() {
    let time = Some(UNIX_EPOCH + Duration::new(42, 100));
    let expected = [1, 42, 100];
    let mut bytes = vec![];
    encode_legacy_option_system_time(&time, &mut bytes).expect("encoding to a vector cannot fail");
    assert_eq!(bytes, expected);

    let mut cursor = Cursor::new(expected);
    let decoded = decode_legacy_option_system_time_from_finite_reader(
        &mut cursor,
        &ModuleDecoderRegistry::default(),
    )
    .expect("valid encoding");
    assert_eq!(decoded, time);
}

#[test_log::test]
fn test_legacy_optional_system_time_encoding_none() {
    let mut bytes = vec![];
    encode_legacy_option_system_time(&None, &mut bytes).expect("encoding to a vector cannot fail");
    assert_eq!(bytes, [0]);

    let mut cursor = Cursor::new(bytes);
    let decoded = decode_legacy_option_system_time_from_finite_reader(
        &mut cursor,
        &ModuleDecoderRegistry::default(),
    )
    .expect("valid encoding");
    assert_eq!(decoded, None);
}

#[test_log::test]
fn test_legacy_optional_system_time_encoding_rejects_invalid_flag() {
    let error = decode_legacy_option_system_time_from_finite_reader(
        &mut Cursor::new([2]),
        &ModuleDecoderRegistry::default(),
    )
    .expect_err("invalid option flag must fail");
    assert_eq!(
        error.to_string(),
        "Invalid flag for option enum, expected 0 or 1"
    );
}

#[test_log::test]
fn test_legacy_system_time_field_decode_adds_context() {
    let error = with_decoding_context(
        decode_legacy_system_time_from_finite_reader(
            &mut Cursor::new([42]),
            &ModuleDecoderRegistry::default(),
        ),
        "Decoding named block field: Test{ ... timestamp ... }",
    )
    .expect_err("truncated timestamp must fail");
    assert!(
        error
            .to_string()
            .contains("Decoding named block field: Test{ ... timestamp ... }")
    );
}

#[test_log::test]
fn test_legacy_system_time_decode_overflow_is_an_error() {
    // secs = u64::MAX is past what `SystemTime` can represent. No encoder we
    // ship produces it, but a peer can put any u64 on the wire.
    let mut bytes = Vec::new();
    u64::MAX.consensus_encode(&mut bytes).unwrap();
    0u32.consensus_encode(&mut bytes).unwrap();
    decode_legacy_system_time_from_finite_reader(
        &mut Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )
    .expect_err("an unrepresentable timestamp must be a decode error, not a panic");
}

#[test_log::test]
fn test_duration_decode_rejects_out_of_range_nsecs() {
    // secs = u64::MAX with nsecs = 1e9 carries a second and overflows `secs`
    // inside `Duration::new`; it must be rejected instead.
    let reg = ModuleDecoderRegistry::default();
    let mut bad = Vec::new();
    u64::MAX.consensus_encode(&mut bad).unwrap();
    1_000_000_000u32.consensus_encode(&mut bad).unwrap();
    Duration::consensus_decode_partial(&mut Cursor::new(bad), &reg)
        .expect_err("nsecs of one billion must be rejected");

    // The largest canonical nsecs must still decode.
    let mut ok = Vec::new();
    u64::MAX.consensus_encode(&mut ok).unwrap();
    999_999_999u32.consensus_encode(&mut ok).unwrap();
    Duration::consensus_decode_partial(&mut Cursor::new(ok), &reg)
        .expect("the largest canonical nsecs must decode");
}

#[test_log::test]
fn test_finite_reader_shares_decode_limit_between_fields() {
    let field = vec![0u8; MAX_DECODE_SIZE / 2];
    let mut bytes = vec![];
    field
        .consensus_encode(&mut bytes)
        .expect("encoding to a vector cannot fail");
    field
        .consensus_encode(&mut bytes)
        .expect("encoding to a vector cannot fail");

    let error = TestFiniteReader::consensus_decode_partial(
        &mut Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )
    .expect_err("both fields cannot exceed one decode limit");
    assert!(
        error
            .to_string()
            .contains("Decoding tuple block TestFiniteReader field field_1")
    );
}

#[derive(Debug, Encodable, Decodable, Eq, PartialEq)]
enum TestEnum {
    Foo(Option<u64>),
    Bar { bazz: Vec<u8> },
}

#[test_log::test]
fn test_derive_enum() {
    let test_cases = [
        (TestEnum::Foo(Some(42)), vec![0, 2, 1, 42]),
        (TestEnum::Foo(None), vec![0, 1, 0]),
        (
            TestEnum::Bar {
                bazz: vec![1, 2, 3],
            },
            vec![1, 4, 3, 1, 2, 3],
        ),
    ];

    for (reference, bytes) in test_cases {
        test_roundtrip_expected(&reference, &bytes);
    }
}

#[test]
fn test_derive_empty_enum_decode() {
    #[derive(Debug, Encodable, Decodable)]
    enum NotConstructable {}

    let vec = vec![42u8];
    let mut cursor = Cursor::new(vec);

    assert!(
        NotConstructable::consensus_decode_partial(&mut cursor, &ModuleDecoderRegistry::default())
            .is_err()
    );
}

#[test]
fn test_custom_index_enum() {
    #[derive(Debug, PartialEq, Eq, Encodable, Decodable)]
    enum Old {
        Foo,
        Bar,
        Baz,
    }

    #[derive(Debug, PartialEq, Eq, Encodable, Decodable)]
    enum New {
        #[encodable(index = 0)]
        Foo,
        #[encodable(index = 2)]
        Baz,
        #[encodable_default]
        Default { variant: u64, bytes: Vec<u8> },
    }

    let test_vector = vec![
        (Old::Foo, New::Foo),
        (
            Old::Bar,
            New::Default {
                variant: 1,
                bytes: vec![],
            },
        ),
        (Old::Baz, New::Baz),
    ];

    for (old, new) in test_vector {
        let old_bytes = old.consensus_encode_to_vec();
        let decoded_new = New::consensus_decode_whole(&old_bytes, &ModuleRegistry::default())
            .expect("Decoding failed");
        assert_eq!(decoded_new, new);
    }
}

fn encode_value<T: Encodable>(value: &T) -> Vec<u8> {
    let mut writer = Vec::new();
    value.consensus_encode(&mut writer).unwrap();
    writer
}

fn decode_value<T: Decodable>(bytes: &[u8]) -> T {
    T::consensus_decode_whole(bytes, &ModuleDecoderRegistry::default()).unwrap()
}

fn keeps_ordering_after_serialization<T: Ord + Encodable + Decodable + Debug>(mut vec: Vec<T>) {
    vec.sort();
    let mut encoded = vec.iter().map(encode_value).collect::<Vec<_>>();
    encoded.sort();
    let decoded = encoded.iter().map(|v| decode_value(v)).collect::<Vec<_>>();
    for (i, (a, b)) in vec.iter().zip(decoded.iter()).enumerate() {
        assert_eq!(a, b, "difference at index {i}");
    }
}

#[test]
fn test_lexicographical_sorting() {
    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
    struct TestAmount(u64);

    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
    struct TestComplexAmount(u16, u32, u64);

    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Encodable, Decodable)]
    struct Text(String);

    let amounts = (0..20000).map(TestAmount).collect::<Vec<_>>();
    keeps_ordering_after_serialization(amounts);

    let complex_amounts = (10..20000)
        .flat_map(|i| {
            (i - 1..=i + 1).flat_map(move |j| {
                (i - 1..=i + 1).map(move |k| TestComplexAmount(i as u16, j as u32, k as u64))
            })
        })
        .collect::<Vec<_>>();
    keeps_ordering_after_serialization(complex_amounts);

    let texts = (' '..'~')
        .flat_map(|i| {
            (' '..'~')
                .map(|j| Text(format!("{i}{j}")))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    keeps_ordering_after_serialization(texts);

    // bitcoin structures are not lexicographically sortable so we cannot
    // test them here. in future we may crate a wrapper type that is
    // lexicographically sortable to use when needed
}

#[test]
fn whole_decode_rejects_trailing_bytes_with_a_message() {
    let err = u8::consensus_decode_whole(&[1, 2], &ModuleDecoderRegistry::default())
        .expect_err("one byte too many");
    assert!(matches!(err, DecodeError::Custom { .. }), "{err:?}");
    assert!(
        err.to_string()
            .starts_with("Type did not consume all bytes during decoding"),
        "{err}"
    );
}

#[test]
fn decode_error_display_is_the_outer_layer_and_the_chain_is_reachable() {
    let io = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short read");
    let err = Err::<(), _>(io)
        .context("Decoding field a")
        .context("Decoding Foo")
        .expect_err("built from an error");

    assert_eq!(err.to_string(), "Decoding Foo");
    assert_eq!(
        err.fmt_compact().to_string(),
        "Decoding Foo: Decoding field a: short read"
    );

    let DecodeError::Context { source: inner, .. } = &err else {
        panic!("outer layer is the last context added: {err:?}");
    };
    let DecodeError::Context { source: leaf, .. } = &**inner else {
        panic!("inner layer is the first context added: {inner:?}");
    };
    assert!(matches!(**leaf, DecodeError::Io(_)), "{leaf:?}");
}

#[test]
fn from_err_shows_the_typed_error_as_is() {
    let parse_error = "x".parse::<u8>().expect_err("not a number");
    let message = parse_error.to_string();

    let err = DecodeError::from_err(parse_error);

    assert!(matches!(err, DecodeError::Invalid(_)), "{err:?}");
    assert_eq!(err.to_string(), message);
    assert_eq!(err.fmt_compact().to_string(), message);
}

#[test]
fn custom_and_from_str_carry_only_a_message() {
    let err = DecodeError::custom(format!("Unknown network magic: {:x}", 0xd9b4_bef9_u32));
    assert!(matches!(err, DecodeError::Custom { .. }), "{err:?}");
    assert_eq!(err.to_string(), "Unknown network magic: d9b4bef9");
    assert!(std::error::Error::source(&err).is_none());

    let err = DecodeError::from_str("Out of range, expected 0 or 1");
    assert_eq!(err.to_string(), "Out of range, expected 0 or 1");
}

#[test]
fn with_context_only_formats_on_error() {
    let ok: Result<u8, DecodeError> = Ok(1);
    let formatted = ok
        .with_context(|| panic!("must not be called on Ok"))
        .expect("still Ok");
    assert_eq!(formatted, 1);

    let err = Err::<u8, _>(DecodeError::from_str("bad"))
        .with_context(|| format!("Decoding item {}", 3))
        .expect_err("still Err");
    assert_eq!(err.fmt_compact().to_string(), "Decoding item 3: bad");
}

#[test]
fn truncated_input_is_an_io_error() {
    let err = u8::consensus_decode_whole(&[], &ModuleDecoderRegistry::default())
        .expect_err("empty input is not a u8");
    assert!(matches!(err, DecodeError::Io(_)), "{err:?}");
}

#[test]
fn truncated_integer_is_an_io_error() {
    let err = u32::consensus_decode_whole(&[], &ModuleDecoderRegistry::default())
        .expect_err("zero bytes are not a u32");
    assert!(matches!(err, DecodeError::Io(_)), "{err:?}");
}

#[test]
fn truncated_transaction_id_is_an_io_error() {
    let err =
        crate::TransactionId::consensus_decode_whole(&[0u8; 31], &ModuleDecoderRegistry::default())
            .expect_err("31 bytes are not a transaction id");
    assert!(matches!(err, DecodeError::Io(_)), "{err:?}");
}

#[test]
fn derived_decode_names_the_failing_field_and_keeps_the_io_root() {
    // `vec` decodes as one element (7); `num` then has no bytes left.
    let err = TestStruct::consensus_decode_whole(&[1, 7], &ModuleDecoderRegistry::default())
        .expect_err("payload is truncated");

    let DecodeError::Context { context, source } = &err else {
        panic!("the failing field's context is the outer layer: {err:?}");
    };
    assert_eq!(
        context,
        "Decoding named block field: TestStruct{ ... num ... }"
    );
    assert!(matches!(**source, DecodeError::Io(_)), "{source:?}");
}

#[test]
fn derived_decode_reports_unknown_variants_structurally() {
    let unknown_variant = DefaultEnum::Default {
        variant: 42,
        bytes: vec![0, 1, 2, 3],
    };
    let mut encoding = vec![];
    unknown_variant
        .consensus_encode(&mut encoding)
        .expect("encodes");

    let err = NoDefaultEnum::consensus_decode_whole(&encoding, &ModuleRegistry::default())
        .expect_err("variant 42 does not exist");
    assert!(
        matches!(
            err,
            DecodeError::InvalidVariant {
                variant: 42,
                type_name: "NoDefaultEnum"
            }
        ),
        "{err:?}"
    );
}
