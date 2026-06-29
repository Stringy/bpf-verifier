//! Clang JSON AST deserialisation.
//!
//! Clang's `-Xclang -ast-dump=json` emits a tree of nodes.
//! Each node has a `kind` field and optional fields depending on the kind.
//! We only model the subset relevant to BPF C programmes.

use serde::Deserialize;

/// Deserialise a JSON value that may be a string or a number into
/// `Option<String>`. Clang's AST dump emits `value` as a string for
/// some node kinds (e.g. string literals) and as a bare integer for
/// others (e.g. integer literals in newer clang versions).
fn string_or_number<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrNumber;

    impl<'de> de::Visitor<'de> for StringOrNumber {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string, integer, or null")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
    }

    deserializer.deserialize_any(StringOrNumber)
}

/// A node in the Clang AST. Uses a flat structure with optional fields
/// rather than an enum, because Clang's JSON format is ad-hoc and
/// many fields are shared across node kinds.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: Option<String>,
    #[serde(default)]
    pub kind: String,
    pub name: Option<String>,

    #[serde(rename = "type")]
    pub ty: Option<QualType>,

    pub opcode: Option<String>,
    #[serde(default, deserialize_with = "string_or_number")]
    pub value: Option<String>,

    /// For DeclRefExpr: the referenced declaration
    pub referenced_decl: Option<Box<ReferencedDecl>>,

    /// For VarDecl: whether it has an initialiser
    pub has_init: Option<bool>,

    /// For SectionAttr: the section name
    #[serde(alias = "section_name")]
    pub section_name: Option<String>,

    /// Whether this is an implicit (compiler-generated) node
    pub is_implicit: Option<bool>,

    /// For CastExpr subtypes: the cast kind
    pub cast_kind: Option<String>,

    /// Child nodes
    #[serde(default)]
    pub inner: Vec<Node>,

    /// Source location
    pub loc: Option<SourceLocation>,
    pub range: Option<SourceRange>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QualType {
    pub qual_type: String,
    pub desugared_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferencedDecl {
    pub id: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,

    #[serde(rename = "type")]
    pub ty: Option<QualType>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLocation {
    pub file: Option<String>,
    pub line: Option<u32>,
    pub col: Option<u32>,
    pub expansion_loc: Option<Box<SourceLocation>>,
    pub spelling_loc: Option<Box<SourceLocation>>,
}

#[derive(Debug, Deserialize)]
pub struct SourceRange {
    pub begin: Option<SourceLocation>,
    pub end: Option<SourceLocation>,
}

impl Node {
    /// Check if this node is from a specific source file (not a system header).
    ///
    /// Clang's JSON format only emits the `file` field when it changes from
    /// the previous node. So a node from the main source file often has no
    /// `file` field at all — Clang just emits line/col. We treat "no file
    /// field and not implicit" as "from main source".
    pub fn is_from_file(&self, filename: &str) -> bool {
        if let Some(loc) = &self.loc {
            if let Some(file) = &loc.file {
                return file.contains(filename);
            }
            if let Some(exp) = &loc.expansion_loc {
                if let Some(file) = &exp.file {
                    return file.contains(filename);
                }
            }
            // No file field: if we have a line number and aren't implicit,
            // assume we're in the main source file (Clang's convention)
            if loc.line.is_some() && !self.is_implicit.unwrap_or(false) {
                return true;
            }
        }
        false
    }

    /// Get the qualified type string, if any.
    pub fn qual_type(&self) -> Option<&str> {
        self.ty.as_ref().map(|t| t.qual_type.as_str())
    }

    /// Get the desugared type string, preferring it over the qualified type.
    pub fn desugared_type(&self) -> Option<&str> {
        self.ty
            .as_ref()
            .and_then(|t| t.desugared_type.as_deref().or(Some(t.qual_type.as_str())))
    }

    /// Get the name of the referenced declaration (for DeclRefExpr).
    pub fn ref_name(&self) -> Option<&str> {
        self.referenced_decl
            .as_ref()
            .and_then(|r| r.name.as_deref())
    }

    /// Find child nodes by kind.
    pub fn children_of_kind(&self, kind: &str) -> Vec<&Node> {
        self.inner.iter().filter(|n| n.kind == kind).collect()
    }

    /// Find the first child of a given kind.
    pub fn first_child_of_kind(&self, kind: &str) -> Option<&Node> {
        self.inner.iter().find(|n| n.kind == kind)
    }

    /// Get the section attribute value if present.
    pub fn section_attr(&self) -> Option<&str> {
        for child in &self.inner {
            if child.kind == "SectionAttr" {
                // The section name might be in the inner text or a specific field
                // Clang puts it as the first inner node's value or in the node itself
                if let Some(ref name) = child.name {
                    return Some(name);
                }
                // Sometimes it's in inner[0].value
                if let Some(first) = child.inner.first() {
                    if let Some(ref val) = first.value {
                        return Some(val);
                    }
                }
            }
        }
        None
    }
}
