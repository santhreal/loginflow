//! Integration test for SPA hydration wait.

#![cfg(feature = "browser")]

use loginflow::drive::{wait_for_spa_hydration, HydrationWait};
use runtime_headless::{BrowserLaunchOptions, BrowserRuntime};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn waits_for_hydration_signal() {
    let server = MockServer::start().await;

    // Serve a simple HTML page that simulates a slow SPA hydration.
    // It creates `#app-root` after 500ms.
    let html = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>SPA</title>
        <script>
            setTimeout(() => {
                const el = document.createElement('div');
                el.id = 'app-root';
                el.textContent = 'Hydrated';
                document.body.appendChild(el);
            }, 500);
        </script>
    </head>
    <body>
        <div id="loading">Loading...</div>
    </body>
    </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/spa"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(html, "text/html"))
        .mount(&server)
        .await;

    let options = BrowserLaunchOptions {
        headed: false,
        ..Default::default()
    };
    let runtime = BrowserRuntime::launch(&options)
        .await
        .expect("Fix: test requires chromium");

    let page = runtime
        .browser()
        .new_page("about:blank")
        .await
        .expect("Fix: page creation failed");

    page.goto(format!("{}/spa", server.uri()))
        .await
        .expect("Fix: goto failed");

    let config = HydrationWait {
        timeout: Duration::from_secs(5),
        selector: Some("#app-root".to_string()),
        wait_for_idle: true,
    };

    // This should wait for #app-root to appear.
    let result = wait_for_spa_hydration(&page, &config).await;
    assert!(result.is_ok(), "Hydration wait failed: {:?}", result.err());

    // Verify the element is actually there.
    let el = page.find_element("#app-root").await;
    let app_root = el.expect("Fix: Element #app-root should exist");
    let text = runtime_headless::extract_element_value(
        &page,
        "#app-root",
        &runtime_headless::ElementTarget::Text,
    )
    .await
    .expect("Fix: extract failed");
    let text = app_root
        .inner_text()
        .await
        .expect("Fix: Should get inner text");
    assert_eq!(text, Some("Hydrated".to_string()));
}
