use std::collections::HashSet;

/// Egress scan result containing any detected sensitive tokens or patterns.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub matched_patterns: Vec<String>,
    pub canary_tokens_found: Vec<String>,
    pub has_prompt_injection: bool,
}

impl ScanResult {
    pub fn is_clean(&self) -> bool {
        self.matched_patterns.is_empty()
            && self.canary_tokens_found.is_empty()
            && !self.has_prompt_injection
    }
}

/// Scanner for prompt injection, canary token leakage, and unauthorized egress patterns.
pub struct EgressScanner {
    canary_tokens: HashSet<String>,
    injection_patterns: Vec<&'static str>,
    credential_patterns: Vec<&'static str>,
}

impl Default for EgressScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl EgressScanner {
    pub fn new() -> Self {
        Self {
            canary_tokens: HashSet::new(),
            injection_patterns: vec![
                "ignore previous instructions",
                "ignore all previous instructions",
                "system override",
                "bypass security",
                "disregard instructions",
                "you are now in developer mode",
                "jailbreak",
                "exfiltrate",
                "eval(",
                "exec(",
                "drop table",
                "drop database",
                "select * from information_schema",
                "/etc/passwd",
                "/etc/shadow",
            ],
            credential_patterns: vec![
                "eyjhbgcioi", // JWT prefix (lowercase)
                "eyjhbgci",   // JWT prefix (lowercase)
                "akiat",      // AWS key prefix
                "ghp_",       // GitHub personal token
                "glpat-",     // GitLab token
                "xoxb-",      // Slack bot token
                "sk-proj-",   // OpenAI API key
                "private key-----",
            ],
        }
    }

    /// Register a canary token to trace for unauthorized egress or prompt leakage.
    pub fn register_canary(&mut self, token: impl Into<String>) {
        self.canary_tokens.insert(token.into());
    }

    /// Check if a canary token is tracked.
    pub fn has_canary(&self, token: &str) -> bool {
        self.canary_tokens.contains(token)
    }

    /// Scan text content for canaries, injection patterns, and credential leaks.
    pub fn scan(&self, text: &str) -> ScanResult {
        let text_lower = text.to_lowercase();
        let mut matched_patterns = Vec::new();
        let mut canary_tokens_found = Vec::new();
        let mut has_prompt_injection = false;

        // Canary check (exact match on original text and lowercase)
        for canary in &self.canary_tokens {
            if text.contains(canary) || text_lower.contains(&canary.to_lowercase()) {
                canary_tokens_found.push(canary.clone());
            }
        }

        // Injection heuristics
        for pattern in &self.injection_patterns {
            if text_lower.contains(pattern) {
                matched_patterns.push(format!("prompt_injection:{}", pattern));
                has_prompt_injection = true;
            }
        }

        // Credential heuristics
        for pattern in &self.credential_patterns {
            if text_lower.contains(pattern) {
                matched_patterns.push(format!("credential_leak:{}", pattern));
            }
        }

        ScanResult {
            matched_patterns,
            canary_tokens_found,
            has_prompt_injection,
        }
    }

    /// Redact known sensitive patterns or credentials from text.
    pub fn redact(&self, text: &str) -> String {
        let mut sanitized = text.to_string();
        for canary in &self.canary_tokens {
            sanitized = sanitized.replace(canary, "[REDACTED_CANARY]");
        }
        sanitized
    }
}
