#![forbid(unsafe_code)]

//! CI and local verification test ensuring that the CSP and security headers in
//! `/render.yaml` and `strongroom_backend::middleware::SECURITY_HEADERS`
//! match the single source of truth in `/security/headers/security-headers.json`.

use std::{collections::BTreeMap, error::Error, fs, path::Path};
use strongroom_backend::middleware::SECURITY_HEADERS;

#[derive(Debug, PartialEq, Eq)]
struct CanonicalHeaderSpec {
    common_headers: BTreeMap<String, String>,
    client_csp: String,
    backend_csp: String,
}

#[derive(Debug, PartialEq, Eq)]
struct RenderHeaderEntry {
    path: String,
    name: String,
    value: String,
}

fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_security_headers_json(raw_json: &str) -> Result<CanonicalHeaderSpec, String> {
    let mut common_headers = BTreeMap::new();
    let mut client_csp: Option<String> = None;
    let mut backend_csp: Option<String> = None;
    let mut in_common_headers = false;

    for line in raw_json.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if trimmed.starts_with("\"commonHeaders\"") && trimmed.ends_with('{') {
            in_common_headers = true;
            continue;
        }
        if in_common_headers {
            if trimmed == "}" {
                in_common_headers = false;
                continue;
            }
            if let Some((key, value)) = trimmed.split_once(':') {
                common_headers.insert(unquote(key), unquote(value));
            }
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let k = unquote(key);
            if k == "clientContentSecurityPolicy" {
                client_csp = Some(unquote(value));
            } else if k == "backendContentSecurityPolicy" {
                backend_csp = Some(unquote(value));
            }
        }
    }

    if common_headers.is_empty() {
        return Err("commonHeaders in security-headers.json is empty or missing".to_string());
    }

    Ok(CanonicalHeaderSpec {
        common_headers,
        client_csp: client_csp.ok_or("Missing clientContentSecurityPolicy")?,
        backend_csp: backend_csp.ok_or("Missing backendContentSecurityPolicy")?,
    })
}

fn parse_render_yaml_headers(raw_yaml: &str) -> Result<Vec<RenderHeaderEntry>, String> {
    let mut entries = Vec::new();
    let mut in_headers_block = false;
    let mut current_path: Option<String> = None;
    let mut current_name: Option<String> = None;
    let mut current_value: Option<String> = None;

    for line in raw_yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "headers:" {
            in_headers_block = true;
            continue;
        }
        if in_headers_block {
            if trimmed.starts_with("- type:") {
                break;
            }
            if let Some(rest) = trimmed.strip_prefix("- path:") {
                if let (Some(p), Some(n), Some(v)) = (
                    current_path.take(),
                    current_name.take(),
                    current_value.take(),
                ) {
                    entries.push(RenderHeaderEntry {
                        path: p,
                        name: n,
                        value: v,
                    });
                }
                current_path = Some(unquote(rest));
            } else if let Some(rest) = trimmed.strip_prefix("name:") {
                current_name = Some(unquote(rest));
            } else if let Some(rest) = trimmed.strip_prefix("value:") {
                current_value = Some(unquote(rest));
            }
        }
    }

    if let (Some(p), Some(n), Some(v)) = (
        current_path.take(),
        current_name.take(),
        current_value.take(),
    ) {
        entries.push(RenderHeaderEntry {
            path: p,
            name: n,
            value: v,
        });
    }

    if entries.is_empty() {
        return Err("No headers entries found in render.yaml".to_string());
    }

    Ok(entries)
}

fn verify_render_yaml_matches_canonical(
    spec: &CanonicalHeaderSpec,
    render_entries: &[RenderHeaderEntry],
) -> Result<(), String> {
    let mut expected = spec.common_headers.clone();
    expected.insert(
        "Content-Security-Policy".to_string(),
        spec.client_csp.clone(),
    );

    if render_entries.len() != expected.len() {
        return Err(format!(
            "Header count mismatch: render.yaml has {} entries, security-headers.json expects {}",
            render_entries.len(),
            expected.len()
        ));
    }

    let mut seen = BTreeMap::new();
    for entry in render_entries {
        if entry.path != "/*" {
            return Err(format!(
                "Header '{}' in render.yaml must apply to path '/*', found '{}'",
                entry.name, entry.path
            ));
        }
        if seen
            .insert(entry.name.clone(), entry.value.clone())
            .is_some()
        {
            return Err(format!("Duplicate header '{}' in render.yaml", entry.name));
        }
    }

    for (expected_name, expected_val) in &expected {
        match seen.get(expected_name) {
            Some(actual_val) if actual_val == expected_val => {}
            Some(actual_val) => {
                return Err(format!(
                    "Header '{}' value mismatch:\n  render.yaml:           {}\n  security-headers.json: {}",
                    expected_name, actual_val, expected_val
                ));
            }
            None => {
                return Err(format!(
                    "Missing required header '{}' in render.yaml",
                    expected_name
                ));
            }
        }
    }

    Ok(())
}

#[test]
fn render_yaml_and_backend_headers_match_security_headers_json() -> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let json_path = manifest_dir.join("../security/headers/security-headers.json");
    let render_path = manifest_dir.join("../render.yaml");

    let raw_json = fs::read_to_string(&json_path)?;
    let raw_yaml = fs::read_to_string(&render_path)?;

    let spec = parse_security_headers_json(&raw_json)?;
    let render_entries = parse_render_yaml_headers(&raw_yaml)?;

    // 1. Verify render.yaml matches security-headers.json
    verify_render_yaml_matches_canonical(&spec, &render_entries)?;

    // 2. Verify backend SECURITY_HEADERS matches security-headers.json
    let mut expected_backend = BTreeMap::new();
    expected_backend.insert(
        "content-security-policy".to_string(),
        spec.backend_csp.clone(),
    );
    for (k, v) in &spec.common_headers {
        expected_backend.insert(k.to_ascii_lowercase(), v.clone());
    }

    assert_eq!(
        SECURITY_HEADERS.len(),
        expected_backend.len(),
        "Backend SECURITY_HEADERS count differs from security-headers.json"
    );

    for &(name, value) in SECURITY_HEADERS {
        let expected_value = expected_backend
            .get(name)
            .ok_or_else(|| format!("Unexpected backend header: {name}"))?;
        assert_eq!(
            value, expected_value,
            "Backend header '{name}' differs from security-headers.json"
        );
    }

    Ok(())
}

#[test]
fn tampered_csp_in_render_yaml_fails_verification() -> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let raw_json =
        fs::read_to_string(manifest_dir.join("../security/headers/security-headers.json"))?;
    let raw_yaml = fs::read_to_string(manifest_dir.join("../render.yaml"))?;

    let spec = parse_security_headers_json(&raw_json)?;
    let mut render_entries = parse_render_yaml_headers(&raw_yaml)?;

    // Tamper with CSP in render.yaml
    for entry in &mut render_entries {
        if entry.name == "Content-Security-Policy" {
            entry.value = "default-src 'self' 'unsafe-inline'".to_string();
        }
    }

    let result = verify_render_yaml_matches_canonical(&spec, &render_entries);
    assert!(
        result.is_err(),
        "Verification must fail when CSP in render.yaml is tampered with"
    );
    Ok(())
}

#[test]
fn missing_or_wrong_path_header_in_render_yaml_fails_verification() -> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let raw_json =
        fs::read_to_string(manifest_dir.join("../security/headers/security-headers.json"))?;
    let raw_yaml = fs::read_to_string(manifest_dir.join("../render.yaml"))?;

    let spec = parse_security_headers_json(&raw_json)?;
    let mut render_entries = parse_render_yaml_headers(&raw_yaml)?;

    // Change path from /* to /app/*
    render_entries[0].path = "/app/*".to_string();
    assert!(
        verify_render_yaml_matches_canonical(&spec, &render_entries).is_err(),
        "Verification must fail when header path is not /*"
    );

    // Drop one header
    let _ = render_entries.pop();
    assert!(
        verify_render_yaml_matches_canonical(&spec, &render_entries).is_err(),
        "Verification must fail when a header is removed from render.yaml"
    );

    Ok(())
}
