use crate::models::{GuardVerdict, McpToolCall, McpToolResult, PolicyViolation, ViolationSeverity};
use crate::scanner::EgressScanner;
use std::collections::{HashMap, HashSet};

/// Policy configuration for MCP Tool execution.
#[derive(Debug, Clone)]
pub struct McpSecurityPolicy {
    pub name: String,
    pub allowed_tools: HashSet<String>,
    pub forbidden_tools: HashSet<String>,
    pub block_on_injection: bool,
    pub block_on_canary_leak: bool,
    pub max_argument_len: usize,
}

impl Default for McpSecurityPolicy {
    fn default() -> Self {
        let mut forbidden = HashSet::new();
        forbidden.insert("bash".to_string());
        forbidden.insert("sh".to_string());
        forbidden.insert("shell_exec".to_string());
        forbidden.insert("eval".to_string());
        forbidden.insert("raw_sql_query".to_string());

        Self {
            name: "default_guard_policy".to_string(),
            allowed_tools: HashSet::new(), // Empty means allow all unless explicitly forbidden
            forbidden_tools: forbidden,
            block_on_injection: true,
            block_on_canary_leak: true,
            max_argument_len: 16 * 1024,
        }
    }
}

/// The MCP Guard firewall engine.
pub struct McpGuard {
    policy: McpSecurityPolicy,
    scanner: EgressScanner,
}

impl McpGuard {
    pub fn new(policy: McpSecurityPolicy) -> Self {
        Self {
            policy,
            scanner: EgressScanner::new(),
        }
    }

    pub fn with_policy(mut self, policy: McpSecurityPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn scanner_mut(&mut self) -> &mut EgressScanner {
        &mut self.scanner
    }

    pub fn register_canary(&mut self, canary: impl Into<String>) {
        self.scanner.register_canary(canary);
    }

    /// Intercept and evaluate an incoming MCP tool invocation.
    pub fn intercept_call(&self, call: &McpToolCall) -> GuardVerdict {
        let mut violations = Vec::new();

        // 1. Check forbidden tools
        if self.policy.forbidden_tools.contains(&call.tool_name) {
            violations.push(PolicyViolation {
                rule_name: "forbidden_tool".to_string(),
                description: format!("Tool '{}' is blacklisted by policy '{}'", call.tool_name, self.policy.name),
                severity: ViolationSeverity::Critical,
                target_field: None,
            });
            return GuardVerdict::Blocked {
                reason: format!("Execution of forbidden tool '{}' is blocked", call.tool_name),
                violations,
            };
        }

        // 2. Check allowed tools if whitelist is non-empty
        if !self.policy.allowed_tools.is_empty() && !self.policy.allowed_tools.contains(&call.tool_name) {
            violations.push(PolicyViolation {
                rule_name: "tool_not_whitelisted".to_string(),
                description: format!("Tool '{}' is not whitelisted by policy '{}'", call.tool_name, self.policy.name),
                severity: ViolationSeverity::High,
                target_field: None,
            });
            return GuardVerdict::Blocked {
                reason: format!("Tool '{}' is not in allowed tools whitelist", call.tool_name),
                violations,
            };
        }

        // 3. Inspect arguments for injection & canary leakage
        let mut sanitized_args = HashMap::new();
        let mut modified = false;

        for (arg_key, arg_val) in &call.arguments {
            let serialized = arg_val.to_string();

            if serialized.len() > self.policy.max_argument_len {
                violations.push(PolicyViolation {
                    rule_name: "argument_length_exceeded".to_string(),
                    description: format!("Argument '{}' exceeds maximum allowed length of {}", arg_key, self.policy.max_argument_len),
                    severity: ViolationSeverity::Warning,
                    target_field: Some(arg_key.clone()),
                });
            }

            let scan = self.scanner.scan(&serialized);

            if scan.has_prompt_injection && self.policy.block_on_injection {
                violations.push(PolicyViolation {
                    rule_name: "prompt_injection_detected".to_string(),
                    description: format!("Prompt injection pattern detected in argument '{}': {:?}", arg_key, scan.matched_patterns),
                    severity: ViolationSeverity::Critical,
                    target_field: Some(arg_key.clone()),
                });
                return GuardVerdict::Blocked {
                    reason: format!("Prompt injection detected in argument '{}'", arg_key),
                    violations,
                };
            }

            if !scan.canary_tokens_found.is_empty() && self.policy.block_on_canary_leak {
                violations.push(PolicyViolation {
                    rule_name: "canary_token_leakage".to_string(),
                    description: format!("Canary token leaked in argument '{}': {:?}", arg_key, scan.canary_tokens_found),
                    severity: ViolationSeverity::Critical,
                    target_field: Some(arg_key.clone()),
                });
                return GuardVerdict::Blocked {
                    reason: format!("Canary token exfiltration detected in argument '{}'", arg_key),
                    violations,
                };
            }

            if !scan.is_clean() {
                // If there are warnings/patterns that didn't block, note them
                for pat in scan.matched_patterns {
                    violations.push(PolicyViolation {
                        rule_name: "suspicious_pattern".to_string(),
                        description: format!("Suspicious pattern in '{}': {}", arg_key, pat),
                        severity: ViolationSeverity::Warning,
                        target_field: Some(arg_key.clone()),
                    });
                }
            }

            // Redact if needed
            let redacted = self.scanner.redact(&serialized);
            if redacted != serialized {
                modified = true;
                sanitized_args.insert(arg_key.clone(), serde_json::Value::String(redacted));
            } else {
                sanitized_args.insert(arg_key.clone(), arg_val.clone());
            }
        }

        if !violations.is_empty() && modified {
            GuardVerdict::Sanitized {
                sanitized_arguments: sanitized_args,
                violations,
            }
        } else if !violations.is_empty() {
            // Non-fatal violations
            GuardVerdict::Sanitized {
                sanitized_arguments: call.arguments.clone(),
                violations,
            }
        } else {
            GuardVerdict::Allowed
        }
    }

    /// Inspect tool result for egress leakage before returning to the LLM agent.
    pub fn inspect_result(&self, result: &McpToolResult) -> GuardVerdict {
        let serialized = result.output.to_string();
        let scan = self.scanner.scan(&serialized);
        let mut violations = Vec::new();

        if !scan.canary_tokens_found.is_empty() && self.policy.block_on_canary_leak {
            violations.push(PolicyViolation {
                rule_name: "canary_leakage_in_tool_output".to_string(),
                description: format!("Output contains leaked canary tokens: {:?}", scan.canary_tokens_found),
                severity: ViolationSeverity::Critical,
                target_field: None,
            });
            return GuardVerdict::Blocked {
                reason: "Tool output contains sensitive canary token".to_string(),
                violations,
            };
        }

        if scan.has_prompt_injection && self.policy.block_on_injection {
            violations.push(PolicyViolation {
                rule_name: "indirect_prompt_injection_in_output".to_string(),
                description: format!("Indirect prompt injection detected in output: {:?}", scan.matched_patterns),
                severity: ViolationSeverity::High,
                target_field: None,
            });
            return GuardVerdict::Blocked {
                reason: "Indirect prompt injection detected in tool execution output".to_string(),
                violations,
            };
        }

        GuardVerdict::Allowed
    }
}
