//! Build identity presentation; reading version metadata has no configuration side effects.

use crate::common::{error::CliResult, table};

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
    let rows = [
        [info.product.into(), info.version.into()],
        ["Revision:".into(), revision],
        ["Target:".into(), info.target.into()],
        ["Profile:".into(), info.profile.into()],
        [
            "Features:".into(),
            if info.features.is_empty() {
                "none".into()
            } else {
                info.features.join(", ")
            },
        ],
        [
            "Built:".into(),
            time::OffsetDateTime::parse(
                info.build_time,
                &time::format_description::well_known::Rfc3339,
            )
            .map_or_else(
                |_| info.build_time.to_owned(),
                |at| crate::common::time::timestamp(Some(at)),
            ),
        ],
    ];
    Ok(table::align(&rows).join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_and_human_versions_expose_the_same_build_identity() {
        let json: serde_json::Value = serde_json::from_str(&render(true).unwrap()).unwrap();
        assert_eq!(json["product"], "AsterACME");
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        for field in ["revision", "target", "profile"] {
            assert!(
                render(false)
                    .unwrap()
                    .contains(json[field].as_str().unwrap())
            );
        }
        assert!(json["features"].is_array());
        assert!(json["dirty"].is_boolean() || json["dirty"].is_null());
    }
    #[test]
    fn version_and_revision_share_the_same_value_column() {
        let text = render(false).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(
            lines[0].find(env!("CARGO_PKG_VERSION")),
            lines[1].find(env!("ASTER_BUILD_REVISION"))
        );
        let parsed: serde_json::Value = serde_json::from_str(&render(true).unwrap()).unwrap();
        assert_eq!(parsed["build_time"], env!("ASTER_BUILD_TIME"));
    }
}
