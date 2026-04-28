//! JSON rendering of a ChangeSet via serde.

use crate::change_set::ChangeSet;

pub fn render(cs: &ChangeSet) -> String {
    serde_json::to_string_pretty(cs).expect("ChangeSet must always serialize")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::change_set::{Change, DatabaseChange};

    #[test]
    fn empty_change_set_serializes() {
        let cs = ChangeSet::default();
        let out = render(&cs);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(parsed.is_object());
        assert_eq!(parsed["changes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn database_rename_serializes_with_kind_field() {
        let mut cs = ChangeSet::default();
        cs.changes.push(Change::Database(DatabaseChange::NameChanged {
            from: "a".into(),
            to: "b".into(),
        }));
        let out = render(&cs);
        assert!(out.contains("\"scope\": \"database\""));
        assert!(out.contains("\"kind\": \"name_changed\""));
    }

    #[test]
    fn json_is_deterministic() {
        let cs = ChangeSet::default();
        let a = render(&cs);
        let b = render(&cs);
        assert_eq!(a, b);
    }
}
