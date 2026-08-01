use loginflow::LoginFlowBuilder;
use std::time::Duration;

#[tokio::test]
async fn test_multiple_builders_can_coexist() {
    let mut handles = vec![];
    for _ in 0..10 {
        handles.push(tokio::spawn(async move {
            let builder = LoginFlowBuilder::default()
                .http_timeout(Duration::from_millis(10))
                .build();
            assert!(builder.is_ok());
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}
