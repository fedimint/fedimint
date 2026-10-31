use futures::{StreamExt, stream};

use super::super::PrefixDatabaseTransaction;

#[tokio::test]
async fn prefix_stream_reuses_owned_buffers() {
    for prefix in [vec![], vec![0], vec![0, 255, 0]] {
        for suffix in [vec![], vec![0, 255, 0], vec![42; 64 * 1024]] {
            for value in [vec![], vec![0, 255, 0], vec![43; 64 * 1024]] {
                let mut key = Vec::with_capacity(prefix.len() + suffix.len() + 16);
                key.extend_from_slice(&prefix);
                key.extend_from_slice(&suffix);
                let key_ptr = key.as_ptr();
                let key_capacity = key.capacity();
                let value_ptr = value.as_ptr();
                let expected_value = value.clone();
                let input = Box::pin(stream::iter([(key, value)]));
                let mut output =
                    PrefixDatabaseTransaction::<()>::adapt_prefix_stream(input, prefix.len());
                let (key, value) = output.next().await.unwrap();
                assert_eq!(key, suffix);
                assert_eq!(value, expected_value);
                assert_eq!(key.as_ptr(), key_ptr);
                assert_eq!(key.capacity(), key_capacity);
                assert_eq!(value.as_ptr(), value_ptr);
                assert!(output.next().await.is_none());
            }
        }
    }
}
