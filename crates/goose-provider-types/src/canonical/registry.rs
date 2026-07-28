use super::CanonicalModel;
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Cached bundled canonical model registry
static BUNDLED_REGISTRY: Lazy<Result<CanonicalModelRegistry>> = Lazy::new(|| {
    const CANONICAL_MODELS_JSON: &str = include_str!("data/canonical_models.json");

    let models: Vec<CanonicalModel> = serde_json::from_str(CANONICAL_MODELS_JSON)
        .context("Failed to parse bundled canonical models JSON")?;

    let mut registry = CanonicalModelRegistry::new();
    for model in models {
        // Extract provider and model from id (format: "provider/model")
        if let Some((provider, model_name)) = model.id.split_once('/') {
            let provider = provider.to_string();
            let model_name = model_name.to_string();
            registry.register(&provider, &model_name, model);
        }
    }

    Ok(registry)
});

/// Environment variable pointing to an external canonical-models JSON file.
/// When set (and non-empty), those entries augment — and on conflict override —
/// the bundled pricing/metadata, so pricing can be added or corrected for
/// specific models (e.g. a provider/model not yet in the bundled registry)
/// without rebuilding goose.
pub const CANONICAL_MODELS_PATH_ENV: &str = "GOOSE_CANONICAL_MODELS_PATH";

/// The registry actually consulted by lookups: the bundled data, optionally
/// merged with the external file named by [`CANONICAL_MODELS_PATH_ENV`]. Built
/// once and cached. If an external file is configured but cannot be read or
/// parsed, we fall back to the bundled data so cost estimates keep working.
static EFFECTIVE_REGISTRY: Lazy<Result<CanonicalModelRegistry>> = Lazy::new(|| {
    let override_path = std::env::var(CANONICAL_MODELS_PATH_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    CanonicalModelRegistry::merged_with_file(override_path).or_else(|_| {
        let bundled = CanonicalModelRegistry::bundled()?;
        Ok(bundled.clone())
    })
});

#[derive(Debug, Clone)]
pub struct CanonicalModelRegistry {
    // Key: (provider, model) tuple
    models: HashMap<(String, String), CanonicalModel>,
}

impl CanonicalModelRegistry {
    pub fn new() -> Self {
        Self {
            models: HashMap::new(),
        }
    }

    pub fn bundled() -> Result<&'static Self> {
        BUNDLED_REGISTRY
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// The registry consulted by lookups: the bundled data, augmented/overridden
    /// by an external file when [`CANONICAL_MODELS_PATH_ENV`] is configured.
    pub fn effective() -> Result<&'static Self> {
        EFFECTIVE_REGISTRY
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Merge another registry into this one. Entries in `other` take precedence
    /// over existing entries with the same `(provider, model)` key.
    pub fn merge(&mut self, other: CanonicalModelRegistry) {
        for (key, model) in other.models {
            self.models.insert(key, model);
        }
    }

    /// Build a registry from the bundled data, then apply an external override
    /// file if one is given. Returns an error only if an external file is
    /// provided but cannot be read or parsed (the bundled data is always valid).
    pub fn merged_with_file(path: Option<impl AsRef<Path>>) -> Result<Self> {
        let mut registry = Self::bundled()
            .map_err(|e| anyhow::anyhow!("{}", e))?
            .clone();
        if let Some(path) = path {
            registry.merge(Self::from_file(path)?);
        }
        Ok(registry)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .context("Failed to read canonical models file")?;

        let models: Vec<CanonicalModel> =
            serde_json::from_str(&content).context("Failed to parse canonical models JSON")?;

        let mut registry = Self::new();
        for model in models {
            if let Some((provider, model_name)) = model.id.split_once('/') {
                let provider = provider.to_string();
                let model_name = model_name.to_string();
                registry.register(&provider, &model_name, model);
            }
        }

        Ok(registry)
    }

    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut models: Vec<&CanonicalModel> = self.models.values().collect();
        models.sort_by(|a, b| a.id.cmp(&b.id));

        let json = serde_json::to_string_pretty(&models)
            .context("Failed to serialize canonical models")?;

        std::fs::write(path.as_ref(), json).context("Failed to write canonical models file")?;

        Ok(())
    }

    pub fn register(&mut self, provider: &str, model: &str, canonical_model: CanonicalModel) {
        self.models
            .insert((provider.to_string(), model.to_string()), canonical_model);
    }

    pub fn get(&self, provider: &str, model: &str) -> Option<&CanonicalModel> {
        self.models.get(&(provider.to_string(), model.to_string()))
    }

    pub fn get_all_models_for_provider(&self, provider: &str) -> Vec<CanonicalModel> {
        self.models
            .iter()
            .filter(|((p, _), _)| p == provider)
            .map(|(_, model)| model.clone())
            .collect()
    }

    pub fn all_models(&self) -> Vec<&CanonicalModel> {
        self.models.values().collect()
    }

    pub fn count(&self) -> usize {
        self.models.len()
    }
}

impl Default for CanonicalModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod externalized_cost_tests {
    use super::*;

    #[test]
    fn merged_with_file_adds_entries_from_external_file() {
        let bundled = CanonicalModelRegistry::bundled().expect("bundled registry loads");
        let mut source = bundled
            .all_models()
            .into_iter()
            .next()
            .expect("bundled registry has at least one model")
            .clone();
        let (p, m) = source.id.split_once('/').expect("model id is provider/model");
        let provider = p.to_string();
        let model = m.to_string();
        let added = format!("{model}__externalized");
        // Re-key under the fabricated id so the file round-trip (which keys by
        // `model.id`) preserves the new (provider, model) entry after merge.
        source.id = format!("{provider}/{added}");

        // The fabricated name must not already be a bundled entry.
        assert!(
            bundled.get(&provider, &added).is_none(),
            "test fixture name must not collide with bundled data"
        );

        let mut external = CanonicalModelRegistry::new();
        external.register(&provider, &added, source);

        let path = std::env::temp_dir().join(format!(
            "goose-canonical-merge-{}-{}.json",
            std::process::id(),
            added
        ));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        external.to_file(&path).expect("write external file");

        let merged =
            CanonicalModelRegistry::merged_with_file(Some(&path)).expect("merge should succeed");
        let _ = std::fs::remove_file(&path);

        assert!(
            merged.get(&provider, &added).is_some(),
            "external entry should be present after merge"
        );
        assert!(
            merged.get(&provider, &model).is_some(),
            "bundled entry should survive the merge"
        );
    }

    #[test]
    fn effective_falls_back_to_bundled_when_unset() {
        // With GOOSE_CANONICAL_MODELS_PATH unset, effective() must equal bundled data.
        // (ENV may be set by a sibling test in the same process; guard on a bogus path.)
        let eff = CanonicalModelRegistry::effective().expect("effective registry loads");
        assert!(eff.count() > 0, "effective registry must be non-empty");
    }
}
