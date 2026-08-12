//! Staple notarization tickets. Unlike notarization itself this does not
//! require the `notarize` feature: ticket lookup uses upstream's always-on
//! HTTP client.

use std::path::Path;

use apple_codesign::stapling::Stapler;

use crate::error::FfiError;

pub(crate) fn staple(path: &Path) -> Result<(), FfiError> {
    let stapler = Stapler::new()?;
    stapler.staple_path(path)?;
    Ok(())
}
