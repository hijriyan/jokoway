use jokoway_core::config::ConfigBuilder;

use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_strict_validation_api_settings() {
    let yaml = r#"
jokoway:
  http_listen: "127.0.0.1:8080"
  api:
    listen: "127.0.0.1:9090"
    unknown_field: "should fail"
"#;
    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", yaml).unwrap();

    let result = ConfigBuilder::new().from_file(file.path());
    assert!(
        result.is_err(),
        "Should fail due to unknown field in ApiSettings"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("unknown field `unknown_field`"),
        "Error message should mention unknown field: {}",
        err
    );
}

#[test]
fn test_strict_validation_upstream() {
    let yaml = r#"
jokoway:
  http_listen: "127.0.0.1:8080"
  upstreams:
    - name: "test"
      servers:
        - host: "127.0.0.1:8081"
      invalid_upstream_field: "should fail"
"#;
    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", yaml).unwrap();

    let result = ConfigBuilder::new().from_file(file.path());
    assert!(
        result.is_err(),
        "Should fail due to unknown field in Upstream"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("unknown field `invalid_upstream_field`"),
        "Error message should mention unknown field: {}",
        err
    );
}

#[test]
fn test_jokoway_config_allows_extra() {
    let yaml = r#"
jokoway:
  http_listen: "127.0.0.1:8080"
  extra_dynamic_field: "allowed"
"#;
    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", yaml).unwrap();

    let result = ConfigBuilder::new().from_file(file.path());
    assert!(
        result.is_ok(),
        "Should pass as JokowayConfig allows extra fields"
    );
    let (config, _) = result.unwrap().build();
    assert!(config.extra.contains_key("extra_dynamic_field"));
}

#[test]
fn test_root_config_allows_unknown() {
    let yaml = r#"
jokoway:
  http_listen: "127.0.0.1:8080"
unknown_root_field: "allowed"
"#;
    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", yaml).unwrap();

    let result = ConfigBuilder::new().from_file(file.path());
    assert!(
        result.is_ok(),
        "Should pass as RootConfig allows unknown fields"
    );
}
