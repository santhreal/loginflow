//! Fill and submit HTML login forms via runtime-headless.

use crate::discover::DiscoveredForm;
use crate::error::DriveError;
use crate::mfa::{MfaPrompt, MfaSource};
use runtime_headless::{
    click, evaluate_script_value, navigate, wait_for_ready_state, HeadlessError, Page,
};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;

const NAV_TIMEOUT: Duration = Duration::from_secs(30);
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Navigate to `page_url`, fill `form`, optionally submit MFA, and submit.
///
/// # Errors
///
/// Returns [`DriveError`] when navigation, fill, or submit fails.
pub async fn drive_html_form(
    page: &Page,
    page_url: &str,
    form: &DiscoveredForm,
    username: &str,
    password: &SecretString,
    mfa: Option<&Arc<dyn MfaSource>>,
) -> Result<(), DriveError> {
    navigate(page, page_url, NAV_TIMEOUT)
        .await
        .map_err(|e| DriveError::Headless(headless_msg(e)))?;
    wait_for_ready_state(page, READY_TIMEOUT)
        .await
        .map_err(|e| DriveError::Headless(headless_msg(e)))?;

    fill_field(page, form, &form.username_field, username).await?;
    fill_field(page, form, &form.password_field, password.expose_secret()).await?;

    for (name, value) in &form.csrf_fields {
        fill_field(page, form, name, value).await?;
    }
    for (name, value) in &form.extra_hidden {
        fill_field(page, form, name, value).await?;
    }

    if form.has_totp_field {
        let source = mfa.ok_or_else(|| DriveError::FieldFill {
            field: "mfa".into(),
            details: "totp field present but no mfa_source".into(),
        })?;
        let response = source
            .fetch(&MfaPrompt::Totp { field_name: None })
            .await
            .map_err(|e| DriveError::FieldFill {
                field: "mfa".into(),
                details: e.to_string(),
            })?;
        let totp_name = totp_field_name(page, form).await?;
        fill_field(page, form, &totp_name, &response.code).await?;
    }

    submit_form(page, form).await?;
    wait_for_ready_state(page, READY_TIMEOUT)
        .await
        .map_err(|e| DriveError::Headless(headless_msg(e)))?;
    Ok(())
}

async fn fill_field(
    page: &Page,
    form: &DiscoveredForm,
    field_name: &str,
    value: &str,
) -> Result<(), DriveError> {
    let form_sel =
        serde_json::to_string(&form.form_selector).map_err(|e| DriveError::FieldFill {
            field: field_name.into(),
            details: e.to_string(),
        })?;
    let name = serde_json::to_string(field_name).map_err(|e| DriveError::FieldFill {
        field: field_name.into(),
        details: e.to_string(),
    })?;
    let val = serde_json::to_string(value).map_err(|e| DriveError::FieldFill {
        field: field_name.into(),
        details: e.to_string(),
    })?;
    let script = format!(
        "() => {{
            const form = document.querySelector({form_sel});
            if (!form) return false;
            const el = form.querySelector('[name=' + {name} + ']') || form.querySelector('#' + {name});
            if (!el) return false;
            el.focus();
            el.value = {val};
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
            return true;
        }}"
    );
    let ok = evaluate_script_value(page, &script)
        .await
        .map_err(|e| DriveError::Headless(headless_msg(e)))?;
    if ok != "true" {
        return Err(DriveError::FieldFill {
            field: field_name.into(),
            details: "element not found or fill returned false".into(),
        });
    }
    Ok(())
}

async fn submit_form(page: &Page, form: &DiscoveredForm) -> Result<(), DriveError> {
    if let Some(selector) = &form.submit_selector {
        click(page, selector)
            .await
            .map_err(|e| DriveError::Headless(headless_msg(e)))?;
        return Ok(());
    }
    let form_sel = serde_json::to_string(&form.form_selector)
        .map_err(|e| DriveError::Headless(e.to_string()))?;
    let script = format!(
        "() => {{ const f = document.querySelector({form_sel}); if (f) f.submit(); return !!f; }}"
    );
    let ok = evaluate_script_value(page, &script)
        .await
        .map_err(|e| DriveError::Headless(headless_msg(e)))?;
    if ok != "true" {
        return Err(DriveError::Headless("form submit failed".into()));
    }
    Ok(())
}

async fn totp_field_name(page: &Page, form: &DiscoveredForm) -> Result<String, DriveError> {
    let form_sel =
        serde_json::to_string(&form.form_selector).map_err(|e| DriveError::FieldFill {
            field: "totp".into(),
            details: e.to_string(),
        })?;
    let script = format!(
        "() => {{
            const form = document.querySelector({form_sel});
            if (!form) return null;
            for (const el of form.querySelectorAll('input')) {{
                const n = (el.name || el.id || '').toLowerCase();
                const t = (el.type || '').toLowerCase();
                if (n.includes('otp') || n.includes('totp') || n.includes('mfa') || n.includes('2fa') || n.includes('code')) {{
                    return el.name || el.id;
                }}
                if (t === 'tel' && n.includes('token')) return el.name || el.id;
            }}
            return null;
        }}"
    );
    let name = evaluate_script_value(page, &script)
        .await
        .map_err(|e| DriveError::Headless(headless_msg(e)))?;
    if name.is_empty() || name == "null" {
        return Err(DriveError::FieldFill {
            field: "totp".into(),
            details: "totp field not found in live DOM".into(),
        });
    }
    Ok(name.trim_matches('"').to_string())
}

fn headless_msg(err: HeadlessError) -> String {
    err.to_string()
}
