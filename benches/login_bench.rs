use criterion::{criterion_group, criterion_main, Criterion};
use loginflow::discover_best_login_form;
use url::Url;

fn bench_html_discovery(c: &mut Criterion) {
    let html = r#"<html><body><form><input type="text" name="username"><input type="password" name="password"></form></body></html>"#;
    let url = Url::parse("https://example.com").unwrap();
    c.bench_function("discover_basic_login", |b| {
        b.iter(|| discover_best_login_form(html, &url))
    });
}

criterion_group!(benches, bench_html_discovery);
criterion_main!(benches);
