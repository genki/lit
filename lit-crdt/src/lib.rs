use anyhow::{anyhow, Result};
use automerge::{transaction::Transactable, Automerge, Change, ReadDoc, ScalarValue, Value, ROOT};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEnvelope {
    pub actor_id: Vec<u8>,
    pub changes: Vec<Vec<u8>>,
}

pub struct TextCrdt {
    doc: Automerge,
}

impl TextCrdt {
    pub fn new() -> Result<Self> {
        Ok(Self {
            doc: Automerge::new(),
        })
    }

    pub fn load(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            Self::new()
        } else {
            Ok(Self {
                doc: Automerge::load(bytes)?,
            })
        }
    }

    pub fn save(&self) -> Vec<u8> {
        self.doc.save()
    }

    pub fn apply_text(&mut self, new_text: &str) -> Result<()> {
        let mut tx = self.doc.transaction();
        tx.put(ROOT, "content", new_text)?;
        tx.commit();
        Ok(())
    }

    pub fn current_text(&self) -> Result<String> {
        match self.doc.get(ROOT, "content")? {
            Some((Value::Scalar(scalar), _)) => match scalar.as_ref() {
                ScalarValue::Str(s) => Ok(s.to_string()),
                _ => Ok(scalar.to_string()),
            },
            _ => Ok(String::new()),
        }
    }

    pub fn export_changes(&mut self) -> ChangeEnvelope {
        let changes = self.doc.get_changes(&[]);
        ChangeEnvelope {
            actor_id: self.doc.get_actor().to_bytes().to_vec(),
            changes: changes
                .into_iter()
                .map(|c| c.raw_bytes().to_vec())
                .collect(),
        }
    }

    pub fn apply_changes(&mut self, env: &ChangeEnvelope) -> Result<()> {
        let mut parsed = Vec::with_capacity(env.changes.len());
        for raw in &env.changes {
            parsed.push(Change::from_bytes(raw.clone())?);
        }
        self.doc
            .apply_changes(parsed.into_iter())
            .map_err(|e| anyhow!("apply_changes: {e}"))
    }
}

pub fn merge_documents(local: &mut TextCrdt, remote_bytes: &[u8]) -> Result<()> {
    let remote = TextCrdt::load(remote_bytes)?;
    let changes: Vec<_> = remote.doc.get_changes(&[]).into_iter().cloned().collect();
    local
        .doc
        .apply_changes(changes.into_iter())
        .map_err(|e| anyhow!("merge_documents: {e}"))
}
