//! Text forms of property values, shared by the dump and the text renderer.
//!
//! The grammar: closed-set names and value kinds (numbers, times, UUIDs,
//! colors, `<sealed:...>`, enum names) are bare; every vault-controlled
//! string printed next to renderer syntax (a plain single-line value, a node
//! path; labels quote their own vault parts, see `Property`'s `Display`) is
//! one `kdbx_core::text::quote` token; a multi-line value is printed as
//! `continuation_lines`, whose content cannot be mistaken for anything else.
//! So no value can forge a structural line, another property, a sealed value,
//! a protection marker or a ` -> `.

#[cfg(test)]
mod grammar_tests;
pub(crate) mod json;
pub(crate) mod text;
mod wire;

use std::fmt::Write as _;

use kdbx_core::model::{AutoTypeObfuscation, Compression, Icon, InnerCipher, OuterCipher, Value};
use kdbx_core::path::VaultPath;
use kdbx_core::text::{continuation_lines, quote};
use uuid::Uuid;

use crate::properties::{KdfKind, Property, Shown};

/// The prefix of every continuation line of a multi-line value, after the
/// line's indentation.
pub(crate) const CONTINUATION: &str = "| ";

/// A value's text form: an inline part, and for multi-line text the raw text
/// to render as continuation lines below it.
pub(crate) struct ValueText<'a> {
    /// The single-line part (for a block value, only its markers).
    pub(crate) inline: String,
    /// Multi-line text, rendered with [`continuation_lines`].
    pub(crate) block: Option<&'a str>,
    /// Presence alone: the line is the label, without a colon.
    pub(crate) bare: bool,
}

impl<'a> ValueText<'a> {
    /// The text form of `value` as the value of `property`.
    pub(crate) fn of(property: &Property, value: &'a Shown) -> Self {
        let multiline = property.is_multiline();
        let bare = matches!(value, Shown::Present);
        let (text, marker) = match value {
            Shown::Text(s) => (Some(s.as_str()), None),
            Shown::Field {
                protected,
                value: Value::Plain(s),
            } => (Some(s.as_str()), protected.then_some("(protected)")),
            _ => (None, None),
        };
        match text {
            Some(s) if multiline => ValueText {
                inline: marker.unwrap_or_default().to_owned(),
                block: Some(s),
                bare,
            },
            Some(s) => ValueText {
                inline: join(&quote(s), marker),
                block: None,
                bare,
            },
            None => ValueText {
                inline: inline(value),
                block: None,
                bare,
            },
        }
    }

    /// Append `label` and this value to `out` as one property line (plus
    /// continuation lines), each line starting with `indent` and the first
    /// with `sign`.
    pub(crate) fn write(&self, out: &mut String, indent: &str, sign: &str, label: &str) {
        let _ = write!(out, "{indent}{sign}{label}");
        if !self.bare {
            out.push(':');
        }
        if !self.inline.is_empty() {
            out.push(' ');
            out.push_str(&self.inline);
        }
        out.push('\n');
        if let Some(text) = self.block {
            let prefix = format!("{indent}{}{CONTINUATION}", " ".repeat(sign.len() + 2));
            for line in continuation_lines(text, &prefix) {
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
}

fn join(text: &str, marker: Option<&str>) -> String {
    match marker {
        Some(m) => format!("{text} {m}"),
        None => text.to_owned(),
    }
}

/// The single-line text form of a value.
pub(crate) fn inline(value: &Shown) -> String {
    match value {
        Shown::Text(s) => quote(s),
        Shown::Sealed(fp) => sealed(fp),
        Shown::Field { protected, value } => match value {
            Value::Plain(s) => join(&quote(s), protected.then_some("(protected)")),
            Value::Sealed(fp) => join(&sealed(fp), (!protected).then_some("(unprotected)")),
            _ => "<unrecognized>".to_owned(),
        },
        Shown::Bool(b) => b.to_string(),
        Shown::Int(n) => n.to_string(),
        Shown::Uint(n) => n.to_string(),
        Shown::Time(t) => t.to_string(),
        Shown::Uuid(u) => u.to_string(),
        Shown::Color(c) => c.to_string(),
        Shown::Icon(icon) => match icon {
            Icon::Standard(n) => format!("standard {n}"),
            Icon::Custom(u) => format!("custom {u}"),
            _ => "unrecognized".to_owned(),
        },
        Shown::Attachment {
            size,
            fingerprint,
            protected,
        } => {
            let flag = if *protected { ", protected" } else { "" };
            format!("{} ({size} bytes{flag})", sealed(fingerprint))
        }
        Shown::Blob { size, fingerprint } => format!("{} ({size} bytes)", sealed(fingerprint)),
        Shown::Present => String::new(),
        Shown::Format(v) => v.to_string(),
        Shown::Kdf(k) => kdf_name(*k).to_owned(),
        Shown::OuterCipher(c) => match c {
            OuterCipher::Aes256 => "AES-256",
            OuterCipher::Twofish => "Twofish",
            OuterCipher::ChaCha20 => "ChaCha20",
            _ => "unrecognized",
        }
        .to_owned(),
        Shown::InnerCipher(c) => match c {
            InnerCipher::Plain => "none",
            InnerCipher::Salsa20 => "Salsa20",
            InnerCipher::ChaCha20 => "ChaCha20",
            _ => "unrecognized",
        }
        .to_owned(),
        Shown::Compression(c) => match c {
            Compression::None => "none",
            Compression::GZip => "gzip",
            _ => "unrecognized",
        }
        .to_owned(),
        Shown::Obfuscation(o) => match o {
            AutoTypeObfuscation::None => "none",
            AutoTypeObfuscation::UseClipboard => "use-clipboard",
            _ => "unrecognized",
        }
        .to_owned(),
    }
}

/// The display name of a KDF kind.
pub(crate) fn kdf_name(kind: KdfKind) -> &'static str {
    match kind {
        KdfKind::AesKdf => "AES-KDF",
        KdfKind::Argon2d => "Argon2d",
        KdfKind::Argon2id => "Argon2id",
        KdfKind::Unrecognized => "unrecognized",
    }
}

/// A sealed value: its fingerprint's 8-character short form.
fn sealed(fp: &kdbx_core::fingerprint::Fingerprint) -> String {
    format!("<sealed:{}>", fp.short())
}

/// A node's path as one quoted token (a path holds vault names, so it is
/// quoted like any vault string; unquote, then `VaultPath::parse`).
pub(crate) fn path_token(path: &VaultPath) -> String {
    quote(&path.format())
}

/// A node's address in the dump: its path token and its UUID, or the UUID
/// alone for a node without a path.
pub(crate) fn address(path: Option<&VaultPath>, uuid: Uuid) -> String {
    match path {
        Some(p) => format!("{} [uuid:{uuid}]", path_token(p)),
        None => format!("(no path) [uuid:{uuid}]"),
    }
}
