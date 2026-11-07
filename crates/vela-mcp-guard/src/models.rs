use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An incoming or outgoing Model Context Protocol (MCP) tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolCall {
    pub call_id: String,
    pub tool_name: String,
    pub arguments: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub caller_identity: Option<String>,
}

/// The result returned by a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolResult {
    pub call_id: String,
    pub tool_name: String,
    pub output: serde_json::Value,
    #[serde(default)]
    pub is_error: bool,
}

/// Severity level of a security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Info,
    Warning,
    High,
    Critical,
}

/// A policy or security violation detected during inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyViolation {
    pub rule_name: String,
    pub description: String,
    pub severity: ViolationSeverity,
    pub target_field: Option<String>,
}

/// Verdict on an MCP tool call or result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GuardVerdict {
    Allowed,
    Blocked {
        reason: String,
        violations: Vec<PolicyViolation>,
    },
    Sanitized {
        sanitized_arguments: HashMap<String, serde_json::Value>,
        violations: Vec<PolicyViolation>,
    },
}

impl GuardVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, GuardVerdict::Allowed | GuardVerdict::Sanitized { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, GuardVerdict::Blocked { .. })
    }
}
