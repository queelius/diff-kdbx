//! A stable, line-oriented text dump of one snapshot, for git's textconv.

use kdbx_core::model::{NodeRef, Snapshot};

use crate::nodes::Nodes;
use crate::options::{DumpOptions, Noise};
use crate::properties::{PropertyMap, database_properties, entry_properties, group_properties};
use crate::render::{ValueText, address};

/// Render `snap` as text: a `DATABASE` block, then one `GROUP` or `ENTRY`
/// block per node in tree order, each listing the node's properties in
/// canonical order.
///
/// The dump prints exactly the properties [`compute`](crate::compute) diffs
/// (both read one property map per node), so a git diff of two dumps and a
/// `compute` of the two snapshots report the same things. Output is a pure
/// function of the snapshot and `opts`, and line-safe: structural lines start
/// at column 0 with `DATABASE`, `GROUP` or `ENTRY`, property lines are
/// indented, and every value is escaped or rendered as continuation lines
/// (`    | `), so no value can forge a structural line.
pub fn dump(snap: &Snapshot, opts: &DumpOptions) -> String {
    let mut out = String::from("DATABASE\n");
    write_properties(&mut out, database_properties(snap), opts.noise);
    for node in Nodes::new(snap, opts.recycle_bin).in_path_order() {
        let (keyword, props) = match node.node {
            NodeRef::Group(g) => ("GROUP", group_properties(g)),
            NodeRef::Entry(e) => ("ENTRY", entry_properties(e)),
        };
        out.push_str(keyword);
        out.push(' ');
        out.push_str(&address(node.path.as_ref(), node.node.uuid()));
        out.push('\n');
        write_properties(&mut out, props, opts.noise);
    }
    out
}

fn write_properties(out: &mut String, props: PropertyMap, noise: Noise) {
    for (property, value) in &props {
        if noise == Noise::Suppress && property.is_noise() {
            continue;
        }
        ValueText::of(property, value).write(out, "  ", "", &property.to_string());
    }
}

#[cfg(test)]
mod tests;
