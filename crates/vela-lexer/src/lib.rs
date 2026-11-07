//! Zero-copy DFA Lexer for the Vela Programming Language (`.vela`).
//! Built with `logos` to tokenize sovereignty schemas, taint types, and covenants.

use logos::Logos;
use serde::{Deserialize, Serialize};
use std::ops::Range;

pub type Span = Range<usize>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpannedToken {
    pub token: Token,
    pub span: Span,
    pub slice: String,
}

#[derive(Logos, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[logos(skip r"[ \t\r\n\f]+")]
#[logos(skip r"//[^\n]*")]
pub enum Token {
    // Top-level & declaration keywords
    #[token("module")]
    KwModule,
    #[token("version")]
    KwVersion,
    #[token("import")]
    KwImport,
    #[token("schema")]
    KwSchema,
    #[token("covenant")]
    KwCovenant,
    #[token("invariant")]
    KwInvariant,
    #[token("when")]
    KwWhen,
    #[token("where")]
    KwWhere,
    #[token("let")]
    KwLet,
    #[token("emit")]
    KwEmit,

    // Built-in provenance & taint type constructors
    #[token("tainted")]
    KwTainted,
    #[token("ephemeral")]
    KwEphemeral,
    #[token("sanitized")]
    KwSanitized,
    #[token("public")]
    KwPublic,

    // Operators & punctuation
    #[token("|>")]
    Pipe,
    #[token("->")]
    ThinArrow,
    #[token("=>")]
    FatArrow,
    #[token("::")]
    DoubleColon,
    #[token(":")]
    Colon,
    #[token(";")]
    Semicolon,
    #[token(",")]
    Comma,
    #[token(".")]
    Dot,
    #[token("=")]
    Equals,
    #[token("==")]
    EqEq,
    #[token("!=")]
    NotEq,
    #[token("<=")]
    LtEq,
    #[token(">=")]
    GtEq,
    #[token("<")]
    LAngle,
    #[token(">")]
    RAngle,
    #[token("&&")]
    AndAnd,
    #[token("||")]
    OrOr,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,

    // Literals & Identifiers
    #[regex(r"[0-9]+(ms|s|m|h|d)", |lex| lex.slice().to_string())]
    DurationLit(String),

    #[regex(r"[0-9]+\.[0-9]+", |lex| lex.slice().parse::<f64>().ok())]
    FloatLit(f64),

    #[regex(r"[0-9]+", |lex| lex.slice().parse::<i64>().ok())]
    IntLit(i64),

    #[regex(r#""([^"\\]|\\.)*""#, |lex| {
        let s = lex.slice();
        s[1..s.len()-1].to_string()
    })]
    StringLit(String),

    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    Ident(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LexError {
    pub span: Span,
    pub unexpected: String,
}

/// Tokenizes a `.vela` source string into a vector of `SpannedToken`s or returns lexical errors.
pub fn tokenize(source: &str) -> Result<Vec<SpannedToken>, Vec<LexError>> {
    let mut lexer = Token::lexer(source);
    let mut tokens = Vec::new();
    let mut errors = Vec::new();

    while let Some(result) = lexer.next() {
        let span = lexer.span();
        let slice = lexer.slice().to_string();
        match result {
            Ok(token) => tokens.push(SpannedToken { token, span, slice }),
            Err(()) => errors.push(LexError {
                span,
                unexpected: slice,
            }),
        }
    }

    if errors.is_empty() {
        Ok(tokens)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer_recognizes_vela_constructs() {
        let src = r#"
            module azanian_eagle.eduhelp version "1.0.0";
            schema Learner {
                sa_id: tainted<ZA_IDNumber, POPIA::Section26>,
                prompt: ephemeral<MinorTranscript, ttl = 0s>
            }
        "#;
        let tokens = tokenize(src).expect("Lexer should succeed on valid Vela syntax");
        assert!(tokens.iter().any(|t| t.token == Token::KwModule));
        assert!(tokens.iter().any(|t| t.token == Token::KwTainted));
        assert!(tokens.iter().any(|t| t.token == Token::KwEphemeral));
        assert!(tokens.iter().any(|t| t.token == Token::DurationLit("0s".to_string())));
    }
}
