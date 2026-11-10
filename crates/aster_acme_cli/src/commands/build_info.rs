//! Build identity presentation; reading version metadata has no configuration side effects.

use crate::common::{error::CliResult, terminal::safe};

#[derive(serde::Serialize)]
struct BuildInfo {
    product: &'static str,
    version: &'static str,
    revision: &'static str,
    dirty: Option<bool>,
    target: &'static str,
    profile: &'static str,
    features: Vec<&'static str>,
    build_time: &'static str,
}

pub(crate) fn render(json: bool) -> CliResult<String> {
    let info = BuildInfo {
        product: "AsterACME",
        version: env!("CARGO_PKG_VERSION"),
        revision: env!("ASTER_BUILD_REVISION"),
        dirty: match env!("ASTER_BUILD_DIRTY") {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        target: env!("ASTER_BUILD_TARGET"),
        profile: env!("ASTER_BUILD_PROFILE"),
        features: env!("ASTER_BUILD_FEATURES")
            .split(',')
            .filter(|feature| !feature.is_empty())
            .collect(),
        build_time: env!("ASTER_BUILD_TIME"),
    };
    if json {
        return Ok(serde_json::to_string_pretty(&info)?);
    }
    let revision = match info.dirty {
        Some(true) => format!("{} (dirty)", info.revision),
        Some(false) => info.revision.to_owned(),
        None => format!("{} (working tree unknown)", info.revision),
    };
    Ok([
        format!("{} {}", info.product, info.version),
        format!("Revision:  {revision}"),
        format!("Target:    {}", info.target),
        format!("Profile:   {}", info.profile),
        format!(
            "Features:  {}",
            if info.features.is_empty() {
                "none".into()
            } else {
                info.features.join(", ")
            }
        ),
        format!("Built:     {}", info.build_time),
    ]
    .map(|line| safe(&line))
    .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_and_human_versions_expose_the_same_build_identity() {
        let json: serde_json::Value = serde_json::from_str(&render(true).unwrap()).unwrap();
        assert_eq!(json["product"], "AsterACME");
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        for field in ["revision", "target", "profile", "build_time"] {
            assert!(
                render(false)
                    .unwrap()
                    .contains(json[field].as_str().unwrap())
            );
        }
        assert!(json["features"].is_array());
        assert!(json["dirty"].is_boolean() || json["dirty"].is_null());
    }
}
