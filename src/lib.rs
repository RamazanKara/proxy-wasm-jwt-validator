mod config;
mod token;

use config::{parse_config, ValidatorConfig};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::rc::Rc;
use std::time::{Duration, SystemTime};
use token::{extract_bearer, validate_api_token, validate_jwt, AuthContext};

const MODULE_VERSION: &str = "0.1.0";
const UNAUTHORIZED_BODY: &[u8] = b"Unauthorized";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(TokenRoot {
            state: Rc::new(ConfigState::default()),
            metrics: None,
        })
    });
}}

#[derive(Clone, Default)]
struct ConfigState {
    config: ValidatorConfig,
    error: Option<String>,
}

#[derive(Clone, Default)]
struct MetricIds {
    requests_total: Option<u32>,
    accepted_total: Option<u32>,
    rejected_total: Option<u32>,
    config_errors_total: Option<u32>,
}

struct TokenRoot {
    state: Rc<ConfigState>,
    metrics: Option<MetricIds>,
}

impl Context for TokenRoot {}

impl RootContext for TokenRoot {
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!("proxy-wasm-jwt-validator v{MODULE_VERSION} starting"),
        )
        .ok();

        self.metrics = Some(MetricIds {
            requests_total: define_counter("jwt_validator_requests_total"),
            accepted_total: define_counter("jwt_validator_accepted_total"),
            rejected_total: define_counter("jwt_validator_rejected_total"),
            config_errors_total: define_counter("jwt_validator_config_errors_total"),
        });

        true
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        let bytes = self.get_plugin_configuration().unwrap_or_default();
        let state = match parse_config(&bytes) {
            Ok(config) => ConfigState {
                config,
                error: None,
            },
            Err(error) => {
                proxy_wasm::hostcalls::log(LogLevel::Error, &format!("jwt-validator: {error}"))
                    .ok();
                ConfigState {
                    config: ValidatorConfig::default(),
                    error: Some(error),
                }
            }
        };

        self.state = Rc::new(state);
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(TokenFilter {
            state: Rc::clone(&self.state),
            metrics: self.metrics.clone().unwrap_or_default(),
        }))
    }
}

struct TokenFilter {
    state: Rc<ConfigState>,
    metrics: MetricIds,
}

impl Context for TokenFilter {}

impl HttpContext for TokenFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        increment(self.metrics.requests_total);

        if let Some(error) = self.state.error.clone() {
            increment(self.metrics.config_errors_total);
            return self.reject("config-error", Some(error));
        }

        let now_secs = self
            .get_current_time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        match self.validate_request(now_secs) {
            Ok(context) => {
                increment(self.metrics.accepted_total);
                self.mark_request("verified", Some(&context));
                self.strip_token_headers();
                Action::Continue
            }
            Err(reason) => self.reject(&reason, None),
        }
    }
}

impl TokenFilter {
    fn validate_request(&self, now_secs: u64) -> Result<AuthContext, String> {
        let config = &self.state.config;

        if let Some(auth_header) = self.get_http_request_header(&config.authorization_header) {
            if let Some(token) = extract_bearer(&auth_header) {
                return validate_jwt(&token, config, now_secs);
            }
        }

        if let Some(api_token) = self.get_http_request_header(&config.api_key_header) {
            if !api_token.trim().is_empty() {
                return validate_api_token(&api_token, config);
            }
        }

        Err("missing-token".to_string())
    }

    fn reject(&mut self, reason: &str, details: Option<String>) -> Action {
        increment(self.metrics.rejected_total);
        self.mark_request(reason, None);
        self.strip_token_headers();

        if self.state.config.is_report_mode() {
            return Action::Continue;
        }

        if let Some(details) = details {
            proxy_wasm::hostcalls::log(
                LogLevel::Warn,
                &format!("jwt-validator: rejecting request: {reason}: {details}"),
            )
            .ok();
        } else {
            proxy_wasm::hostcalls::log(
                LogLevel::Warn,
                &format!("jwt-validator: rejecting request: {reason}"),
            )
            .ok();
        }

        self.send_http_response(
            401,
            vec![(self.state.config.status_header.as_str(), reason)],
            Some(UNAUTHORIZED_BODY),
        );
        Action::Pause
    }

    fn mark_request(&self, status: &str, context: Option<&AuthContext>) {
        let config = &self.state.config;
        if !config.emit_headers {
            return;
        }

        self.set_http_request_header(&config.status_header, Some(status));
        if let Some(context) = context {
            self.set_http_request_header(&config.token_type_header, Some(&context.token_type));
            self.set_http_request_header(&config.key_id_header, Some(&context.key_id));
            if !context.subject.is_empty() {
                self.set_http_request_header(&config.subject_header, Some(&context.subject));
            }
            if !context.issuer.is_empty() {
                self.set_http_request_header(&config.issuer_header, Some(&context.issuer));
            }
            if !context.scopes.is_empty() {
                self.set_http_request_header(
                    &config.scopes_header,
                    Some(&context.scopes.join(" ")),
                );
            }
        }
    }

    fn strip_token_headers(&self) {
        let config = &self.state.config;
        if !config.strip_token_headers {
            return;
        }
        self.remove_http_request_header(&config.authorization_header);
        self.remove_http_request_header(&config.api_key_header);
    }
}

fn define_counter(name: &str) -> Option<u32> {
    proxy_wasm::hostcalls::define_metric(MetricType::Counter, name).ok()
}

fn increment(metric_id: Option<u32>) {
    if let Some(metric_id) = metric_id {
        proxy_wasm::hostcalls::increment_metric(metric_id, 1).ok();
    }
}
