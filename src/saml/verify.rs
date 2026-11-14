//! Structural checks on a SAML Response before its signatures are verified.
//!
//! The cryptographic check is done by samael (libxmlsec1, exclusive c14n):
//! every `<ds:Signature>` in the document must verify against the IdP
//! certificate, and everything no signature covers is removed before the
//! assertion is read. These checks run first and narrow the document to the
//! one shape that verification is sound for, so the element that is verified
//! is the element that is consumed:
//!
//! - UTF-8 only (in another encoding the DOCTYPE check cannot see the
//!   DOCTYPE), and no DOCTYPE, comments or processing instructions (entity
//!   tricks, and the comment-truncation attack on `NameID`, where a comment
//!   is invisible to the canonicalised signature but splits the text the SP
//!   reads);
//! - the root is a single `samlp:Response`, carrying exactly one
//!   `saml:Assertion`, as a direct child, and no `EncryptedAssertion`;
//! - no ID value occurs twice (`ID` or `xml:id`), so a `#ref` cannot resolve
//!   to an attacker's copy of the signed element (signature wrapping);
//! - every signature is a direct child of the Response or of the Assertion,
//!   has exactly one `Reference`, and that Reference names the ID of the
//!   element it sits in (an enveloped signature over its own parent);
//! - no `ds:Object` (content a signature carries without covering it);
//! - at least one such signature exists: an unsigned response never reaches
//!   the parser.

use anyhow::{anyhow, bail, Result};
use libxml::parser::Parser;
use libxml::tree::{Node, NodeType};
use std::collections::HashSet;

const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

fn is(node: &Node, ns: &str, name: &str) -> bool {
    node.get_name() == name
        && node
            .get_namespace()
            .map(|n| n.get_href() == ns)
            .unwrap_or(false)
}

fn same(a: &Node, b: &Node) -> bool {
    a.node_ptr() == b.node_ptr()
}

/// Check that `xml` is a SAML Response of the shape described in the module
/// documentation. Does not verify any signature.
pub fn check_response_structure(xml: &str) -> Result<()> {
    // Only UTF-8 is read: libxml2 would otherwise decode the bytes in the
    // declared (UTF-7, ...) or detected (UTF-16, UCS-4) encoding, in which
    // the text checks below cannot see a DOCTYPE.
    check_utf8_only(xml)?;

    // SAML responses never carry a DTD; refuse before any parser sees one.
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        bail!("SAML response contains a DTD");
    }

    let doc = Parser::default()
        .parse_string(xml)
        .map_err(|e| anyhow!("SAML response is not well-formed XML: {e:?}"))?;
    // And whatever got past the text checks: no DTD in the parsed document.
    // SAFETY: `doc` owns a valid xmlDoc for as long as it lives.
    let has_dtd = unsafe {
        let ptr = doc.doc_ptr();
        !(*ptr).intSubset.is_null() || !(*ptr).extSubset.is_null()
    };
    if has_dtd {
        bail!("SAML response contains a DTD");
    }
    let root = doc
        .get_root_element()
        .ok_or_else(|| anyhow!("SAML response has no root element"))?;
    if !is(&root, NS_PROTOCOL, "Response") {
        bail!("SAML response root is not samlp:Response");
    }

    let mut ids: HashSet<String> = HashSet::new();
    let mut assertions = Vec::new();
    let mut signatures = Vec::new();

    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        for child in node.get_child_nodes() {
            match child.get_type() {
                Some(NodeType::ElementNode) => stack.push(child),
                Some(NodeType::CommentNode) => bail!("SAML response contains a comment"),
                Some(NodeType::PiNode) => {
                    bail!("SAML response contains a processing instruction")
                }
                Some(NodeType::EntityRefNode) | Some(NodeType::EntityNode) => {
                    bail!("SAML response contains an entity reference")
                }
                _ => {}
            }
        }

        // `ID` is what SAML uses; `xml:id` is an ID to libxml2 as well.
        for (name, value) in node.get_properties() {
            if (name == "ID" || name == "id") && !ids.insert(value.clone()) {
                bail!("SAML response contains the ID {value:?} more than once");
            }
        }

        if is(&node, NS_ASSERTION, "EncryptedAssertion") {
            bail!("encrypted SAML assertions are not supported");
        }
        if is(&node, NS_ASSERTION, "Assertion") {
            assertions.push(node.clone());
        }
        if is(&node, NS_DSIG, "Object") {
            bail!("SAML response signature carries a ds:Object");
        }
        if is(&node, NS_DSIG, "Signature") {
            signatures.push(node.clone());
        }
    }

    let assertion = match assertions.as_slice() {
        [one] => one.clone(),
        [] => bail!("SAML response contains no assertion"),
        _ => bail!("SAML response contains more than one assertion"),
    };
    if !assertion.get_parent().is_some_and(|p| same(&p, &root)) {
        bail!("SAML assertion is not a direct child of the response");
    }

    if signatures.is_empty() {
        bail!("SAML response is not signed");
    }
    for signature in &signatures {
        let parent = signature
            .get_parent()
            .ok_or_else(|| anyhow!("SAML signature has no parent"))?;
        if !same(&parent, &root) && !same(&parent, &assertion) {
            bail!("SAML signature is neither on the response nor on the assertion");
        }
        let parent_id = parent
            .get_attribute("ID")
            .ok_or_else(|| anyhow!("signed SAML element has no ID"))?;

        let signed_info: Vec<Node> = signature
            .get_child_elements()
            .into_iter()
            .filter(|n| is(n, NS_DSIG, "SignedInfo"))
            .collect();
        let [signed_info] = signed_info.as_slice() else {
            bail!("SAML signature must have exactly one SignedInfo");
        };
        let references: Vec<Node> = signed_info
            .get_child_elements()
            .into_iter()
            .filter(|n| is(n, NS_DSIG, "Reference"))
            .collect();
        let [reference] = references.as_slice() else {
            bail!("SAML signature must have exactly one Reference");
        };
        if reference.get_attribute("URI") != Some(format!("#{parent_id}")) {
            bail!("SAML signature does not reference the element it is in");
        }
    }

    Ok(())
}

/// Refuse input libxml2 would not read as UTF-8: NUL characters (an
/// autodetected UTF-16/UCS-4 document is valid UTF-8 with NULs) and an XML
/// declaration naming any other encoding.
fn check_utf8_only(xml: &str) -> Result<()> {
    if xml.contains('\0') {
        bail!("SAML response contains a NUL character (only the UTF-8 encoding is accepted)");
    }
    let Some(rest) = xml.trim_start_matches('\u{feff}').strip_prefix("<?xml") else {
        return Ok(());
    };
    let declaration = rest.split_once("?>").map_or(rest, |(d, _)| d);
    let Some((_, after)) = declaration.split_once("encoding") else {
        return Ok(());
    };
    let value = after
        .trim_start()
        .strip_prefix('=')
        .map(str::trim_start)
        .and_then(|v| {
            let quote = v.chars().next().filter(|q| *q == '"' || *q == '\'')?;
            v[1..].split_once(quote).map(|(value, _)| value)
        })
        .ok_or_else(|| anyhow!("SAML response has a malformed XML declaration"))?;
    if !value.eq_ignore_ascii_case("UTF-8") {
        bail!("SAML response declares the encoding {value:?}; only UTF-8 is accepted");
    }
    Ok(())
}
