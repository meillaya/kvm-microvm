//! Transport contract validation for the kvm-microvm-orchestrator platform.
//!
//! This crate validates that the REST (OpenAPI) and gRPC (proto3) lifecycle
//! API definitions are in parity and conform to the Unix-socket-only
//! transport constraint.
//!
//! # Checks
//!
//! - Schema parity: every OpenAPI operation has a matching proto RPC.
//! - Static scan: no TCP addresses (`0.0.0.0`, `127.0.0.1`, `tcp://`)
//!   appear in either contract file.
//! - OpenAPI validity: the spec parses as valid YAML with required fields.
//! - Proto validity: the proto file has valid proto3 syntax structure.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// OpenAPI parsing
// ---------------------------------------------------------------------------

/// Minimal OpenAPI 3.1 document structure for validation.
#[derive(Debug, Deserialize)]
pub struct OpenApiDoc {
    /// OpenAPI version string (must start with "3.1").
    pub openapi: String,
    /// API metadata.
    pub info: OpenApiInfo,
    /// Server definitions.
    #[serde(default)]
    pub servers: Vec<OpenApiServer>,
    /// Path definitions keyed by path template.
    pub paths: BTreeMap<String, PathItem>,
}

/// API info block.
#[derive(Debug, Deserialize)]
pub struct OpenApiInfo {
    /// API title.
    pub title: String,
    /// API version.
    pub version: String,
}

/// Server entry.
#[derive(Debug, Deserialize)]
pub struct OpenApiServer {
    /// Server URL (must be a unix:// URI).
    pub url: String,
}

/// A path item containing HTTP method operations.
#[derive(Debug, Default, Deserialize)]
pub struct PathItem {
    /// GET operation.
    #[serde(default)]
    pub get: Option<Operation>,
    /// POST operation.
    #[serde(default)]
    pub post: Option<Operation>,
    /// PUT operation.
    #[serde(default)]
    pub put: Option<Operation>,
    /// DELETE operation.
    #[serde(default)]
    pub delete: Option<Operation>,
    /// PATCH operation.
    #[serde(default)]
    pub patch: Option<Operation>,
}

/// An individual API operation.
#[derive(Debug, Deserialize)]
pub struct Operation {
    /// Unique operation identifier.
    #[serde(rename = "operationId")]
    pub operation_id: String,
    /// Human-readable summary.
    #[serde(default)]
    pub summary: Option<String>,
}

impl OpenApiDoc {
    /// Parse an OpenAPI document from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Load and parse an OpenAPI document from a file path.
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::from_yaml(&content)?)
    }

    /// Return all operations as (method, path, operation_id) tuples.
    pub fn operations(&self) -> Vec<(&str, &str, &str)> {
        let mut ops = Vec::new();
        for (path, item) in &self.paths {
            if let Some(op) = &item.get {
                ops.push(("GET", path.as_str(), op.operation_id.as_str()));
            }
            if let Some(op) = &item.post {
                ops.push(("POST", path.as_str(), op.operation_id.as_str()));
            }
            if let Some(op) = &item.put {
                ops.push(("PUT", path.as_str(), op.operation_id.as_str()));
            }
            if let Some(op) = &item.delete {
                ops.push(("DELETE", path.as_str(), op.operation_id.as_str()));
            }
            if let Some(op) = &item.patch {
                ops.push(("PATCH", path.as_str(), op.operation_id.as_str()));
            }
        }
        ops
    }

    /// Validate that the document meets minimum requirements.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if !self.openapi.starts_with("3.1") {
            errors.push(format!(
                "openapi version must start with '3.1', got '{}'",
                self.openapi
            ));
        }

        if self.info.title.is_empty() {
            errors.push("info.title must not be empty".to_string());
        }

        if self.info.version.is_empty() {
            errors.push("info.version must not be empty".to_string());
        }

        if self.paths.is_empty() {
            errors.push("paths must not be empty".to_string());
        }

        // All servers must use unix:// scheme.
        for server in &self.servers {
            if !server.url.starts_with("unix://") {
                errors.push(format!(
                    "server url must use unix:// scheme, got '{}'",
                    server.url
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ---------------------------------------------------------------------------
// Proto parsing (text-based)
// ---------------------------------------------------------------------------

/// Parsed proto3 service definition.
#[derive(Debug, Clone)]
pub struct ProtoService {
    /// Service name.
    pub name: String,
    /// RPC method names.
    pub rpcs: Vec<String>,
}

/// Parsed proto3 document structure.
#[derive(Debug, Clone)]
pub struct ProtoDoc {
    /// Proto syntax version.
    pub syntax: String,
    /// Package name.
    pub package: String,
    /// Services defined in the file.
    pub services: Vec<ProtoService>,
    /// Message names defined in the file.
    pub messages: Vec<String>,
    /// Enum names defined in the file.
    pub enums: Vec<String>,
}

impl ProtoDoc {
    /// Parse a proto3 file from its text content.
    ///
    /// This is a lightweight structural parser sufficient for parity
    /// validation: it extracts syntax, package, service/RPC names,
    /// message names, and enum names.
    pub fn from_text(content: &str) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let mut syntax = String::new();
        let mut package = String::new();
        let mut services = Vec::new();
        let mut messages = Vec::new();
        let mut enums = Vec::new();

        let mut in_service = false;
        let mut current_service: Option<ProtoService> = None;
        let mut brace_depth: i32 = 0;

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines.
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            // Track brace depth.
            let opens = trimmed.matches('{').count() as i32;
            let closes = trimmed.matches('}').count() as i32;

            // Parse syntax.
            if trimmed.starts_with("syntax") {
                if let Some(s) = extract_quoted(trimmed) {
                    syntax = s;
                }
            }

            // Parse package.
            if trimmed.starts_with("package") {
                if let Some(p) = trimmed
                    .strip_prefix("package")
                    .and_then(|s| s.trim().strip_suffix(';'))
                {
                    package = p.trim().to_string();
                }
            }

            // Parse service start.
            if trimmed.starts_with("service ") && trimmed.contains('{') {
                let name = trimmed
                    .strip_prefix("service")
                    .unwrap()
                    .trim()
                    .split('{')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                in_service = true;
                current_service = Some(ProtoService {
                    name,
                    rpcs: Vec::new(),
                });
            }

            // Parse RPC within service.
            if in_service && trimmed.starts_with("rpc ") {
                if let Some(rpc_name) = trimmed
                    .strip_prefix("rpc")
                    .and_then(|s| s.trim().split('(').next())
                {
                    if let Some(svc) = &mut current_service {
                        svc.rpcs.push(rpc_name.trim().to_string());
                    }
                }
            }

            // Parse message.
            if trimmed.starts_with("message ") && trimmed.contains('{') {
                let name = trimmed
                    .strip_prefix("message")
                    .unwrap()
                    .trim()
                    .split('{')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                messages.push(name);
            }

            // Parse enum.
            if trimmed.starts_with("enum ") && trimmed.contains('{') {
                let name = trimmed
                    .strip_prefix("enum")
                    .unwrap()
                    .trim()
                    .split('{')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                enums.push(name);
            }

            brace_depth += opens - closes;

            // Service end.
            if in_service && brace_depth <= 0 {
                if let Some(svc) = current_service.take() {
                    services.push(svc);
                }
                in_service = false;
                brace_depth = 0;
            }
        }

        if syntax.is_empty() {
            errors.push("missing syntax declaration".to_string());
        } else if syntax != "proto3" {
            errors.push(format!("expected proto3 syntax, got '{}'", syntax));
        }

        if package.is_empty() {
            errors.push("missing package declaration".to_string());
        }

        if services.is_empty() {
            errors.push("no service definitions found".to_string());
        }

        if errors.is_empty() {
            Ok(Self {
                syntax,
                package,
                services,
                messages,
                enums,
            })
        } else {
            Err(errors)
        }
    }

    /// Load and parse a proto file from a file path.
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::from_text(&content).map_err(|e| format!("proto parse errors: {:?}", e))?)
    }

    /// Return all RPC names across all services.
    pub fn all_rpcs(&self) -> Vec<&str> {
        self.services
            .iter()
            .flat_map(|s| s.rpcs.iter().map(|r| r.as_str()))
            .collect()
    }
}

/// Extract a quoted string value from a line like `syntax = "proto3";`.
fn extract_quoted(line: &str) -> Option<String> {
    let start = line.find('"')?;
    let rest = &line[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ---------------------------------------------------------------------------
// Parity mapping
// ---------------------------------------------------------------------------

/// Expected mapping between OpenAPI operation IDs and proto RPC names.
///
/// The mapping uses a canonical form: the OpenAPI operationId (camelCase)
/// must correspond to the proto RPC name (PascalCase).
pub fn operation_id_to_rpc_name(operation_id: &str) -> String {
    // OpenAPI uses camelCase (e.g., "createVm"), proto uses PascalCase ("CreateVm").
    let mut chars = operation_id.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Check parity between an OpenAPI document and a proto document.
///
/// Returns a list of mismatches (empty means full parity).
pub fn check_parity(openapi: &OpenApiDoc, proto: &ProtoDoc) -> Vec<String> {
    let mut mismatches = Vec::new();
    let proto_rpcs: Vec<String> = proto.all_rpcs().iter().map(|s| s.to_string()).collect();

    for (_method, _path, operation_id) in openapi.operations() {
        let expected_rpc = operation_id_to_rpc_name(operation_id);
        if !proto_rpcs.contains(&expected_rpc) {
            mismatches.push(format!(
                "OpenAPI operation '{}' has no matching proto RPC (expected '{}')",
                operation_id, expected_rpc
            ));
        }
    }

    // Check for proto RPCs without OpenAPI counterparts.
    let openapi_ops: Vec<String> = openapi
        .operations()
        .iter()
        .map(|(_, _, id)| operation_id_to_rpc_name(id))
        .collect();

    for rpc in &proto_rpcs {
        if !openapi_ops.contains(rpc) {
            mismatches.push(format!(
                "proto RPC '{}' has no matching OpenAPI operation",
                rpc
            ));
        }
    }

    mismatches
}

// ---------------------------------------------------------------------------
// Static transport scan
// ---------------------------------------------------------------------------

/// Forbidden patterns indicating TCP transport configuration.
pub const FORBIDDEN_TCP_PATTERNS: &[&str] = &[
    "0.0.0.0",
    "127.0.0.1",
    "tcp://",
    "[::]",
    "::1",
    "localhost:",
];

/// Scan content for forbidden TCP transport patterns.
///
/// Returns a list of violations found (line number, pattern, line content).
pub fn scan_for_tcp_patterns(content: &str) -> Vec<(usize, String, String)> {
    let mut violations = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        for pattern in FORBIDDEN_TCP_PATTERNS {
            if line.contains(pattern) {
                violations.push((line_num + 1, pattern.to_string(), line.trim().to_string()));
            }
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_id_to_rpc_name_converts_camel_to_pascal() {
        assert_eq!(operation_id_to_rpc_name("createVm"), "CreateVm");
        assert_eq!(operation_id_to_rpc_name("getVmStatus"), "GetVmStatus");
        assert_eq!(operation_id_to_rpc_name("snapshotVm"), "SnapshotVm");
        assert_eq!(operation_id_to_rpc_name("restoreVm"), "RestoreVm");
    }

    #[test]
    fn scan_detects_tcp_patterns() {
        let content = "server: 0.0.0.0:8080\nlisten: 127.0.0.1:9090\n";
        let violations = scan_for_tcp_patterns(content);
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].1, "0.0.0.0");
        assert_eq!(violations[1].1, "127.0.0.1");
    }

    #[test]
    fn scan_passes_clean_content() {
        let content = "server: unix:///run/microvm/api.sock\n";
        let violations = scan_for_tcp_patterns(content);
        assert!(violations.is_empty());
    }

    #[test]
    fn proto_parser_extracts_structure() {
        let proto = r#"
syntax = "proto3";
package test.v1;

service TestService {
  rpc DoThing(DoThingRequest) returns (DoThingResponse);
}

message DoThingRequest {
  string id = 1;
}

message DoThingResponse {}
"#;
        let doc = ProtoDoc::from_text(proto).unwrap();
        assert_eq!(doc.syntax, "proto3");
        assert_eq!(doc.package, "test.v1");
        assert_eq!(doc.services.len(), 1);
        assert_eq!(doc.services[0].name, "TestService");
        assert_eq!(doc.services[0].rpcs, vec!["DoThing"]);
        assert!(doc.messages.contains(&"DoThingRequest".to_string()));
        assert!(doc.messages.contains(&"DoThingResponse".to_string()));
    }

    #[test]
    fn openapi_parser_validates_version() {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
paths: {}
"#;
        let doc = OpenApiDoc::from_yaml(yaml).unwrap();
        let errors = doc.validate().unwrap_err();
        assert!(errors.iter().any(|e| e.contains("3.1")));
    }
}
