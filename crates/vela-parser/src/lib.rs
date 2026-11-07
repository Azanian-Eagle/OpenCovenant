//! Abstract Syntax Tree (AST) and Parser for `.vela` sovereignty contracts.

use serde::{Deserialize, Serialize};
use vela_lexer::{Span, SpannedToken, Token};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleAst {
    pub name: String,
    pub version: String,
    pub imports: Vec<String>,
    pub schemas: Vec<SchemaDecl>,
    pub covenants: Vec<CovenantDecl>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaDecl {
    pub name: String,
    pub fields: Vec<FieldDecl>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldDecl {
    pub name: String,
    pub ty: ProvenanceType,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProvenanceKind {
    Tainted,
    Ephemeral,
    Sanitized,
    Public,
    Primitive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceType {
    pub kind: ProvenanceKind,
    pub base_type: String,
    pub regulation_tag: Option<String>,
    pub ttl_seconds: Option<u64>,
    pub jurisdiction: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CovenantDecl {
    pub name: String,
    pub input_param: String,
    pub input_schema: String,
    pub sinks: Vec<(String, String)>,
    pub invariants: Vec<InvariantRule>,
    pub bindings: Vec<LetBinding>,
    pub emissions: Vec<EmitStmt>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvariantRule {
    pub name: String,
    pub condition_summary: String,
    pub forbidden_field: String,
    pub forbidden_sink_type: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LetBinding {
    pub var_name: String,
    pub declared_type: ProvenanceType,
    pub source_field: String,
    pub pipe_transforms: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmitStmt {
    pub sink_var: String,
    pub assignments: Vec<(String, String)>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

pub struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<SpannedToken>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&SpannedToken> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<SpannedToken> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn current_span(&self) -> Span {
        self.peek()
            .map(|t| t.span.clone())
            .or_else(|| self.tokens.last().map(|t| t.span.clone()))
            .unwrap_or(0..0)
    }

    fn expect(&mut self, expected: &Token) -> Result<SpannedToken, ParseError> {
        match self.next() {
            Some(t) if &t.token == expected => Ok(t),
            Some(t) => Err(ParseError {
                message: format!("Expected {:?}, found '{}'", expected, t.slice),
                span: t.span,
            }),
            None => Err(ParseError {
                message: format!("Unexpected end of file, expected {:?}", expected),
                span: self.current_span(),
            }),
        }
    }

    fn expect_ident(&mut self) -> Result<(String, Span), ParseError> {
        match self.next() {
            Some(SpannedToken {
                token: Token::Ident(name),
                span,
                ..
            }) => Ok((name, span)),
            Some(t) => Err(ParseError {
                message: format!("Expected identifier, found '{}'", t.slice),
                span: t.span,
            }),
            None => Err(ParseError {
                message: "Unexpected end of file while expecting identifier".to_string(),
                span: self.current_span(),
            }),
        }
    }

    pub fn parse_module(&mut self) -> Result<ModuleAst, ParseError> {
        self.expect(&Token::KwModule)?;
        let mut mod_parts = Vec::new();
        let (first, _) = self.expect_ident()?;
        mod_parts.push(first);
        while let Some(t) = self.peek() {
            if t.token == Token::Dot {
                self.next();
                let (part, _) = self.expect_ident()?;
                mod_parts.push(part);
            } else {
                break;
            }
        }
        self.expect(&Token::KwVersion)?;
        let version = match self.next() {
            Some(SpannedToken {
                token: Token::StringLit(v),
                ..
            }) => v,
            Some(t) => {
                return Err(ParseError {
                    message: format!("Expected version string literal, found '{}'", t.slice),
                    span: t.span,
                })
            }
            None => {
                return Err(ParseError {
                    message: "Missing version string literal".to_string(),
                    span: self.current_span(),
                })
            }
        };
        self.expect(&Token::Semicolon)?;

        let mut imports = Vec::new();
        let mut schemas = Vec::new();
        let mut covenants = Vec::new();

        while let Some(tok) = self.peek() {
            match &tok.token {
                Token::KwImport => {
                    imports.push(self.parse_import()?);
                }
                Token::KwSchema => {
                    schemas.push(self.parse_schema()?);
                }
                Token::KwCovenant => {
                    covenants.push(self.parse_covenant()?);
                }
                _ => {
                    let bad = self.next().unwrap();
                    return Err(ParseError {
                        message: format!("Unexpected top-level token '{}'", bad.slice),
                        span: bad.span,
                    });
                }
            }
        }

        Ok(ModuleAst {
            name: mod_parts.join("."),
            version,
            imports,
            schemas,
            covenants,
        })
    }

    fn parse_import(&mut self) -> Result<String, ParseError> {
        self.expect(&Token::KwImport)?;
        let mut text = String::new();
        while let Some(t) = self.next() {
            if t.token == Token::Semicolon {
                break;
            }
            text.push_str(&t.slice);
        }
        Ok(text)
    }

    fn parse_schema(&mut self) -> Result<SchemaDecl, ParseError> {
        let start = self.expect(&Token::KwSchema)?.span.start;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let mut fields = Vec::new();

        while let Some(t) = self.peek() {
            if t.token == Token::RBrace {
                break;
            }
            let (field_name, fspan) = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let ty = self.parse_provenance_type()?;

            if let Some(w) = self.peek() {
                if w.token == Token::KwWhere {
                    self.next();
                    while let Some(cur) = self.peek() {
                        if cur.token == Token::Comma || cur.token == Token::RBrace {
                            break;
                        }
                        self.next();
                    }
                }
            }
            if let Some(c) = self.peek() {
                if c.token == Token::Comma {
                    self.next();
                }
            }
            fields.push(FieldDecl {
                name: field_name,
                ty,
                span: fspan,
            });
        }
        let end = self.expect(&Token::RBrace)?.span.end;
        Ok(SchemaDecl {
            name,
            fields,
            span: start..end,
        })
    }

    fn parse_provenance_type(&mut self) -> Result<ProvenanceType, ParseError> {
        let first = self.next().ok_or_else(|| ParseError {
            message: "Expected type expression".to_string(),
            span: self.current_span(),
        })?;

        let kind = match &first.token {
            Token::KwTainted => ProvenanceKind::Tainted,
            Token::KwEphemeral => ProvenanceKind::Ephemeral,
            Token::KwSanitized => ProvenanceKind::Sanitized,
            Token::KwPublic => ProvenanceKind::Public,
            Token::Ident(prim) => {
                return Ok(ProvenanceType {
                    kind: ProvenanceKind::Primitive,
                    base_type: prim.clone(),
                    regulation_tag: None,
                    ttl_seconds: None,
                    jurisdiction: None,
                });
            }
            _ => {
                return Err(ParseError {
                    message: format!("Invalid type constructor '{}'", first.slice),
                    span: first.span,
                })
            }
        };

        self.expect(&Token::LAngle)?;
        let (base_type, _) = self.expect_ident()?;

        if let Some(t) = self.peek() {
            if t.token == Token::LAngle {
                self.next();
                while let Some(inner) = self.next() {
                    if inner.token == Token::RAngle {
                        break;
                    }
                }
            }
        }

        let mut regulation_tag = None;
        let mut ttl_seconds = None;
        let mut jurisdiction = None;

        while let Some(t) = self.peek() {
            if t.token == Token::RAngle {
                self.next();
                break;
            }
            if t.token == Token::Comma {
                self.next();
                continue;
            }
            let (ident, _) = self.expect_ident()?;
            if let Some(next_tok) = self.peek() {
                if next_tok.token == Token::DoubleColon {
                    self.next();
                    let (sub, _) = self.expect_ident()?;
                    regulation_tag = Some(format!("{}::{}", ident, sub));
                } else if next_tok.token == Token::Equals {
                    self.next();
                    if ident == "ttl" {
                        if let Some(SpannedToken {
                            token: Token::DurationLit(d),
                            ..
                        }) = self.next()
                        {
                            let digits: String =
                                d.chars().take_while(|c| c.is_ascii_digit()).collect();
                            ttl_seconds = digits.parse::<u64>().ok();
                        }
                    } else if ident == "jurisdiction" {
                        if let Some(SpannedToken {
                            token: Token::StringLit(j),
                            ..
                        }) = self.next()
                        {
                            jurisdiction = Some(j);
                        }
                    }
                } else {
                    regulation_tag = Some(ident);
                }
            }
        }

        Ok(ProvenanceType {
            kind,
            base_type,
            regulation_tag,
            ttl_seconds,
            jurisdiction,
        })
    }

    fn parse_covenant(&mut self) -> Result<CovenantDecl, ParseError> {
        let start = self.expect(&Token::KwCovenant)?.span.start;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::LParen)?;
        let (input_param, _) = self.expect_ident()?;
        self.expect(&Token::Colon)?;
        let (input_schema, _) = self.expect_ident()?;
        self.expect(&Token::RParen)?;
        self.expect(&Token::ThinArrow)?;
        self.expect(&Token::LParen)?;

        let mut sinks = Vec::new();
        while let Some(t) = self.peek() {
            if t.token == Token::RParen {
                self.next();
                break;
            }
            let (sink_var, _) = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let (sink_type, _) = self.expect_ident()?;
            sinks.push((sink_var, sink_type));
            if let Some(comma) = self.peek() {
                if comma.token == Token::Comma {
                    self.next();
                }
            }
        }

        self.expect(&Token::LBrace)?;
        let mut invariants = Vec::new();
        let mut bindings = Vec::new();
        let mut emissions = Vec::new();

        while let Some(t) = self.peek() {
            match &t.token {
                Token::RBrace => break,
                Token::KwInvariant => invariants.push(self.parse_invariant()?),
                Token::KwLet => bindings.push(self.parse_let_binding()?),
                Token::KwEmit => emissions.push(self.parse_emit()?),
                _ => {
                    let bad = self.next().unwrap();
                    return Err(ParseError {
                        message: format!("Unexpected token '{}' inside covenant body", bad.slice),
                        span: bad.span,
                    });
                }
            }
        }

        let end = self.expect(&Token::RBrace)?.span.end;
        Ok(CovenantDecl {
            name,
            input_param,
            input_schema,
            sinks,
            invariants,
            bindings,
            emissions,
            span: start..end,
        })
    }

    fn parse_invariant(&mut self) -> Result<InvariantRule, ParseError> {
        let start = self.expect(&Token::KwInvariant)?.span.start;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        self.expect(&Token::KwWhen)?;

        let mut cond_parts = Vec::new();
        while let Some(t) = self.peek() {
            if t.token == Token::FatArrow {
                self.next();
                break;
            }
            cond_parts.push(self.next().unwrap().slice);
        }

        let (_action_fn, _) = self.expect_ident()?;
        self.expect(&Token::LParen)?;
        let (_obj, _) = self.expect_ident()?;
        self.expect(&Token::Dot)?;
        let (forbidden_field, _) = self.expect_ident()?;
        self.expect(&Token::Comma)?;
        let (forbidden_sink_type, _) = self.expect_ident()?;
        self.expect(&Token::RParen)?;
        self.expect(&Token::Semicolon)?;
        let end = self.expect(&Token::RBrace)?.span.end;

        Ok(InvariantRule {
            name,
            condition_summary: cond_parts.join(" "),
            forbidden_field,
            forbidden_sink_type,
            span: start..end,
        })
    }

    fn parse_let_binding(&mut self) -> Result<LetBinding, ParseError> {
        let start = self.expect(&Token::KwLet)?.span.start;
        let (var_name, _) = self.expect_ident()?;
        self.expect(&Token::Colon)?;
        let declared_type = self.parse_provenance_type()?;
        self.expect(&Token::Equals)?;

        let (_input_obj, _) = self.expect_ident()?;
        self.expect(&Token::Dot)?;
        let (source_field, _) = self.expect_ident()?;

        let mut pipe_transforms = Vec::new();
        while let Some(t) = self.peek() {
            if t.token == Token::Semicolon {
                break;
            }
            if t.token == Token::Pipe {
                self.next();
                let (fn_name, _) = self.expect_ident()?;
                pipe_transforms.push(fn_name);
                if let Some(lp) = self.peek() {
                    if lp.token == Token::LParen {
                        self.next();
                        let mut depth = 1;
                        while depth > 0 {
                            match self.next() {
                                Some(tok) if tok.token == Token::LParen => depth += 1,
                                Some(tok) if tok.token == Token::RParen => depth -= 1,
                                Some(_) => {}
                                None => break,
                            }
                        }
                    }
                }
            } else {
                self.next();
            }
        }
        let end = self.expect(&Token::Semicolon)?.span.end;

        Ok(LetBinding {
            var_name,
            declared_type,
            source_field,
            pipe_transforms,
            span: start..end,
        })
    }

    fn parse_emit(&mut self) -> Result<EmitStmt, ParseError> {
        let start = self.expect(&Token::KwEmit)?.span.start;
        let (sink_var, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let mut assignments = Vec::new();

        while let Some(t) = self.peek() {
            if t.token == Token::RBrace {
                break;
            }
            let (col_name, _) = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let mut expr_tokens = Vec::new();
            while let Some(cur) = self.peek() {
                if cur.token == Token::Comma || cur.token == Token::RBrace {
                    break;
                }
                expr_tokens.push(self.next().unwrap().slice);
            }
            if let Some(c) = self.peek() {
                if c.token == Token::Comma {
                    self.next();
                }
            }
            assignments.push((col_name, expr_tokens.join("")));
        }

        self.expect(&Token::RBrace)?;
        let end = self.expect(&Token::Semicolon)?.span.end;
        Ok(EmitStmt {
            sink_var,
            assignments,
            span: start..end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_module() {
        let src = r#"
module azanian_eagle.test version "1.0.0";

schema User {
  id: tainted<ZA_IDNumber, POPIA::Section26_SpecialPersonal>,
  nonce: public<UUIDv7>
}

covenant TestCovenant(input: User) -> (db: PostgresSink) {
  let clean_id: sanitized<FixedBytes<32>> = input.id |> blake3_salted(secret_env = "PEPPER");

  emit db {
    hashed: clean_id,
    session: input.nonce
  };
}
"#;
        let tokens = vela_lexer::tokenize(src).expect("Lexing failed");
        let mut parser = Parser::new(tokens);
        let ast = parser.parse_module().expect("Parsing failed");
        assert_eq!(ast.name, "azanian_eagle.test");
        assert_eq!(ast.version, "1.0.0");
        assert_eq!(ast.schemas.len(), 1);
        assert_eq!(ast.covenants.len(), 1);
        assert_eq!(ast.covenants[0].bindings.len(), 1);
        assert_eq!(ast.covenants[0].emissions.len(), 1);
    }
}
