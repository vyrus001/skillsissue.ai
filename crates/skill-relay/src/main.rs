use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, AUTHORIZATION, CONNECTION,
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION,
};
use axum::http::{Method, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::redirect::Policy;
use serde_json::{Map, Number, Value};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
const DEFAULT_REQUEST_BYTES: usize = 1024 * 1024;
const DEFAULT_TOTAL_REQUEST_BYTES: u64 = 768 * 1024;
const DEFAULT_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_MAX_REQUESTS: u64 = 32;
const DEFAULT_MAX_CONCURRENCY: usize = 2;
const DEFAULT_TIMEOUT_SECONDS: u64 = 120;
const HEALTH_BODY_LIMIT: usize = 4 * 1024;
const MAX_CONFIGURED_OUTPUT_TOKENS: u64 = 65_536;
const MAX_CONFIGURED_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_CONFIGURED_TOTAL_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "skill-relay", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the credential-isolating provider relay.
    Serve(ServeArgs),
    /// Check a running relay's health endpoint without loading credentials.
    Check(CheckArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Fresh Unix-domain socket on which the relay accepts sandbox requests.
    #[arg(long, env = "SKILL_RELAY_UNIX_SOCKET")]
    unix_socket: PathBuf,

    /// Provider whose fixed API origin and endpoint allowlist are enabled.
    #[arg(long, env = "SKILL_RELAY_PROVIDER")]
    provider: Provider,

    /// Read-only file containing exactly one raw provider API credential.
    #[arg(long, env = "SKILL_RELAY_CREDENTIAL_FILE")]
    credential_file: PathBuf,

    /// Exact provider model identifier accepted in every forwarded JSON body.
    #[arg(long, env = "SKILL_RELAY_EXPECTED_MODEL")]
    expected_model: String,

    /// Hard upper bound injected into, or clamped onto, generation requests.
    #[arg(long, env = "SKILL_RELAY_MAX_OUTPUT_TOKENS")]
    max_output_tokens: u64,

    #[arg(
        long,
        env = "SKILL_RELAY_MAX_REQUEST_BYTES",
        default_value_t = DEFAULT_REQUEST_BYTES
    )]
    max_request_bytes: usize,

    /// Hard cumulative request-body allowance for this relay process.
    #[arg(
        long,
        env = "SKILL_RELAY_MAX_TOTAL_REQUEST_BYTES",
        default_value_t = DEFAULT_TOTAL_REQUEST_BYTES
    )]
    max_total_request_bytes: u64,

    #[arg(
        long,
        env = "SKILL_RELAY_MAX_RESPONSE_BYTES",
        default_value_t = DEFAULT_RESPONSE_BYTES
    )]
    max_response_bytes: usize,

    /// Maximum number of requests that may be forwarded during this process lifetime.
    #[arg(
        long,
        env = "SKILL_RELAY_MAX_REQUESTS",
        default_value_t = DEFAULT_MAX_REQUESTS
    )]
    max_requests: u64,

    /// Maximum number of requests in flight. Excess requests are rejected, not queued.
    #[arg(
        long,
        env = "SKILL_RELAY_MAX_CONCURRENCY",
        default_value_t = DEFAULT_MAX_CONCURRENCY
    )]
    max_concurrency: usize,

    /// End-to-end timeout for each upstream request, including its response body.
    #[arg(
        long,
        env = "SKILL_RELAY_TIMEOUT_SECONDS",
        default_value_t = DEFAULT_TIMEOUT_SECONDS
    )]
    timeout_seconds: u64,
}

#[derive(Debug, Args)]
struct CheckArgs {
    #[arg(long, env = "SKILL_RELAY_UNIX_SOCKET")]
    unix_socket: PathBuf,

    #[arg(long, default_value_t = 2)]
    timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Provider {
    Openai,
    Anthropic,
}

impl Provider {
    fn upstream_origin(self) -> &'static str {
        match self {
            Self::Openai => "https://api.openai.com",
            Self::Anthropic => "https://api.anthropic.com",
        }
    }

    fn allows(self, method: &Method, uri: &Uri) -> bool {
        if method != Method::POST || uri.scheme().is_some() || uri.authority().is_some() {
            return false;
        }

        match self {
            Self::Openai => uri.path() == "/v1/responses" && uri.query().is_none(),
            Self::Anthropic => {
                matches!(uri.path(), "/v1/messages" | "/v1/messages/count_tokens")
                    && matches!(uri.query(), None | Some("beta=true"))
            }
        }
    }

    fn inject_auth(self, credential: &Credential, headers: &mut HeaderMap) {
        match self {
            Self::Openai => {
                headers.insert(AUTHORIZATION, credential.openai_bearer.clone());
            }
            Self::Anthropic => {
                headers.insert(HeaderName::from_static("x-api-key"), credential.raw.clone());
                headers.insert(
                    HeaderName::from_static("anthropic-version"),
                    HeaderValue::from_static("2023-06-01"),
                );
            }
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
        })
    }
}

#[derive(Clone)]
struct Credential {
    raw: HeaderValue,
    openai_bearer: HeaderValue,
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential([REDACTED])")
    }
}

impl Credential {
    fn read(path: &Path) -> Result<Self, Box<dyn Error>> {
        let file = File::open(path)
            .map_err(|error| format!("cannot open credential file {}: {error}", path.display()))?;
        let metadata = file.metadata().map_err(|error| {
            format!("cannot inspect credential file {}: {error}", path.display())
        })?;
        if !metadata.is_file() {
            return Err("credential path must resolve to a regular file".into());
        }
        ensure_read_only(&metadata)?;

        let mut bytes = Vec::new();
        file.take(MAX_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read credential file {}: {error}", path.display()))?;
        if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
            bytes.fill(0);
            return Err("credential file exceeds the size limit".into());
        }

        let start = bytes
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(bytes.len());
        let end = bytes
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .map_or(start, |index| index + 1);
        let token = &bytes[start..end];
        if token.is_empty() || token.iter().any(u8::is_ascii_whitespace) {
            bytes.fill(0);
            return Err("credential file must contain one non-empty raw token".into());
        }

        let mut raw = match HeaderValue::from_bytes(token) {
            Ok(value) => value,
            Err(_) => {
                bytes.fill(0);
                return Err("credential is not valid as an HTTP header value".into());
            }
        };
        raw.set_sensitive(true);

        let mut bearer_bytes = Vec::with_capacity(7 + token.len());
        bearer_bytes.extend_from_slice(b"Bearer ");
        bearer_bytes.extend_from_slice(token);
        let mut openai_bearer = match HeaderValue::from_bytes(&bearer_bytes) {
            Ok(value) => value,
            Err(_) => {
                bytes.fill(0);
                bearer_bytes.fill(0);
                return Err("credential is not valid as an HTTP header value".into());
            }
        };
        openai_bearer.set_sensitive(true);
        bytes.fill(0);
        bearer_bytes.fill(0);

        Ok(Self { raw, openai_bearer })
    }
}

#[cfg(unix)]
fn ensure_read_only(metadata: &std::fs::Metadata) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o222 != 0 {
        return Err("credential file must not have any write permission bits set".into());
    }
    Ok(())
}

fn fs_path_exists(path: &Path) -> Result<bool, Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn set_socket_mode(path: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn verify_socket_metadata(path: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err("relay transport path must be a Unix socket".into());
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err("relay Unix socket must have mode 0600".into());
    }
    if cfg!(target_os = "linux") && (metadata.uid() != 65_532 || metadata.gid() != 65_532) {
        return Err("relay Unix socket must be owned by uid/gid 65532".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_socket_metadata(_path: &Path) -> Result<(), Box<dyn Error>> {
    Err("Unix sockets require a Unix host".into())
}

#[cfg(not(unix))]
fn set_socket_mode(_path: &Path) -> Result<(), Box<dyn Error>> {
    Err("Unix sockets require a Unix host".into())
}

struct SocketPathGuard(PathBuf);

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(not(unix))]
fn ensure_read_only(metadata: &std::fs::Metadata) -> Result<(), Box<dyn Error>> {
    if !metadata.permissions().readonly() {
        return Err("credential file must be read-only".into());
    }
    Ok(())
}

#[derive(Debug)]
struct StateData {
    provider: Provider,
    credential: Credential,
    expected_model: String,
    max_output_tokens: u64,
    client: reqwest::Client,
    request_body_limit: usize,
    request_body_budget: ByteBudget,
    response_body_limit: usize,
    request_budget: RequestBudget,
    concurrency: Arc<Semaphore>,
    timeout: Duration,
}

type AppState = Arc<StateData>;

#[derive(Debug)]
struct RequestBudget {
    used: AtomicU64,
    maximum: u64,
}

#[derive(Debug)]
struct ByteBudget {
    used: AtomicU64,
    maximum: u64,
}

impl ByteBudget {
    fn new(maximum: u64) -> Self {
        Self {
            used: AtomicU64::new(0),
            maximum,
        }
    }

    fn reserve(&self, amount: u64) -> bool {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(amount)
                    .filter(|next| *next <= self.maximum)
            })
            .is_ok()
    }
}

impl RequestBudget {
    fn new(maximum: u64) -> Self {
        Self {
            used: AtomicU64::new(0),
            maximum,
        }
    }

    fn reserve(&self) -> bool {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < self.maximum).then_some(used + 1)
            })
            .is_ok()
    }
}

#[derive(Clone, Copy, Debug)]
enum RelayFailure {
    NotAllowed,
    InvalidProviderRequest,
    TooManyRequests,
    RequestTooLarge,
    TotalRequestBudgetExceeded,
    UpstreamTimeout,
    UpstreamFailure,
    ResponseTooLarge,
}

impl RelayFailure {
    fn status(self) -> StatusCode {
        match self {
            Self::NotAllowed => StatusCode::NOT_FOUND,
            Self::InvalidProviderRequest => StatusCode::BAD_REQUEST,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::RequestTooLarge | Self::TotalRequestBudgetExceeded => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UpstreamFailure | Self::ResponseTooLarge => StatusCode::BAD_GATEWAY,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::NotAllowed => "request_not_allowed",
            Self::InvalidProviderRequest => "invalid_provider_request",
            Self::TooManyRequests => "relay_capacity_exhausted",
            Self::RequestTooLarge => "request_too_large",
            Self::TotalRequestBudgetExceeded => "total_request_budget_exhausted",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamFailure => "upstream_failure",
            Self::ResponseTooLarge => "upstream_response_too_large",
        }
    }

    fn into_response(self) -> Response<Body> {
        let body = format!("{{\"error\":\"{}\"}}", self.code());
        Response::builder()
            .status(self.status())
            .header("content-type", "application/json")
            .header("cache-control", "no-store")
            .body(Body::from(body))
            .expect("static error response is valid")
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("skill-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Check(args) => check(args).await,
    }
}

async fn serve(args: ServeArgs) -> Result<(), Box<dyn Error>> {
    validate_serve_args(&args)?;
    let timeout = Duration::from_secs(args.timeout_seconds);
    let credential = Credential::read(&args.credential_file)?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .https_only(true)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .build()?;
    let state = Arc::new(StateData {
        provider: args.provider,
        credential,
        expected_model: args.expected_model,
        max_output_tokens: args.max_output_tokens,
        client,
        request_body_limit: args.max_request_bytes,
        request_body_budget: ByteBudget::new(args.max_total_request_bytes),
        response_body_limit: args.max_response_bytes,
        request_budget: RequestBudget::new(args.max_requests),
        concurrency: Arc::new(Semaphore::new(args.max_concurrency)),
        timeout,
    });
    let app = Router::new()
        .route("/healthz", get(health))
        .fallback(any(relay))
        .with_state(state);
    if fs_path_exists(&args.unix_socket)? {
        return Err("relay Unix socket path must not already exist".into());
    }
    let listener = UnixListener::bind(&args.unix_socket)?;
    set_socket_mode(&args.unix_socket)?;
    verify_socket_metadata(&args.unix_socket)?;
    let _socket_guard = SocketPathGuard(args.unix_socket.clone());

    eprintln!(
        "skill-relay unix_socket={} provider={} request_limit={} total_request_bytes={} concurrency={}",
        args.unix_socket.display(),
        args.provider,
        args.max_requests,
        args.max_total_request_bytes,
        args.max_concurrency
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn validate_serve_args(args: &ServeArgs) -> Result<(), Box<dyn Error>> {
    if args.max_request_bytes == 0
        || args.max_total_request_bytes == 0
        || args.max_response_bytes == 0
        || args.max_requests == 0
        || args.max_concurrency == 0
        || args.timeout_seconds == 0
        || args.max_output_tokens == 0
    {
        return Err("all relay bounds must be greater than zero".into());
    }
    if !args.unix_socket.is_absolute()
        || args.unix_socket.as_os_str().as_encoded_bytes().len() > 100
        || args
            .unix_socket
            .parent()
            .is_none_or(|parent| !parent.is_dir())
    {
        return Err("Unix socket must use a short absolute path in an existing directory".into());
    }
    if args.max_output_tokens > MAX_CONFIGURED_OUTPUT_TOKENS {
        return Err("max output tokens exceeds the relay safety ceiling".into());
    }
    if args.max_request_bytes > MAX_CONFIGURED_REQUEST_BYTES
        || args.max_total_request_bytes > MAX_CONFIGURED_TOTAL_REQUEST_BYTES
    {
        return Err("request bytes exceed the relay safety ceiling".into());
    }
    if args.expected_model.is_empty()
        || args.expected_model.len() > 128
        || args.expected_model.chars().any(char::is_whitespace)
        || args.expected_model.chars().any(char::is_control)
    {
        return Err("expected model must be a short non-whitespace identifier".into());
    }
    Ok(())
}

async fn health(State(state): State<AppState>) -> Response<Body> {
    let body = format!("{{\"status\":\"ok\",\"provider\":\"{}\"}}", state.provider);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .expect("static health response is valid")
}

async fn relay(State(state): State<AppState>, request: Request) -> Response<Body> {
    match handle_relay(state, request).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn handle_relay(state: AppState, request: Request) -> Result<Response<Body>, RelayFailure> {
    if !state.provider.allows(request.method(), request.uri()) {
        return Err(RelayFailure::NotAllowed);
    }
    if request
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| value.as_bytes() != b"identity")
    {
        return Err(RelayFailure::NotAllowed);
    }
    if request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|size| size > state.request_body_limit)
    {
        return Err(RelayFailure::RequestTooLarge);
    }
    if !state.request_budget.reserve() {
        return Err(RelayFailure::TooManyRequests);
    }

    let permit = Arc::clone(&state.concurrency)
        .try_acquire_owned()
        .map_err(|_| RelayFailure::TooManyRequests)?;

    let result = tokio::time::timeout(state.timeout, handle_permitted(&state, request))
        .await
        .map_err(|_| RelayFailure::UpstreamTimeout)?;
    drop(permit);
    result
}

async fn handle_permitted(
    state: &StateData,
    request: Request,
) -> Result<Response<Body>, RelayFailure> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, state.request_body_limit)
        .await
        .map_err(|_| RelayFailure::RequestTooLarge)?;
    if !state.request_body_budget.reserve(body.len() as u64) {
        return Err(RelayFailure::TotalRequestBudgetExceeded);
    }
    let body = constrain_provider_body(
        state.provider,
        parts.uri.path(),
        &body,
        &state.expected_model,
        state.max_output_tokens,
    )?;
    if body.len() > state.request_body_limit {
        return Err(RelayFailure::RequestTooLarge);
    }
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |value| value.as_str());
    forward(state, path_and_query, &parts.headers, body).await
}

async fn forward(
    state: &StateData,
    path_and_query: &str,
    incoming_headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<Response<Body>, RelayFailure> {
    let url = format!("{}{}", state.provider.upstream_origin(), path_and_query);
    let mut headers = sanitize_request_headers(incoming_headers);
    state.provider.inject_auth(&state.credential, &mut headers);
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let mut response = state
        .client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                RelayFailure::UpstreamTimeout
            } else {
                RelayFailure::UpstreamFailure
            }
        })?;

    if response.status().is_redirection() || response.status().is_informational() {
        return Err(RelayFailure::UpstreamFailure);
    }
    if response
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| value.as_bytes() != b"identity")
    {
        return Err(RelayFailure::UpstreamFailure);
    }
    if response
        .content_length()
        .is_some_and(|size| size > state.response_body_limit as u64)
    {
        return Err(RelayFailure::ResponseTooLarge);
    }

    let status = response.status();
    let headers = sanitize_response_headers(response.headers());
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RelayFailure::UpstreamFailure)?
    {
        append_bounded(&mut bytes, &chunk, state.response_body_limit)?;
    }

    let mut builder = Response::builder().status(status);
    *builder
        .headers_mut()
        .expect("response builder accepts headers") = headers;
    builder
        .body(Body::from(bytes))
        .map_err(|_| RelayFailure::UpstreamFailure)
}

fn constrain_provider_body(
    provider: Provider,
    path: &str,
    body: &[u8],
    expected_model: &str,
    max_output_tokens: u64,
) -> Result<Vec<u8>, RelayFailure> {
    let mut value =
        serde_json::from_slice::<Value>(body).map_err(|_| RelayFailure::InvalidProviderRequest)?;
    let object = value
        .as_object_mut()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    if object.get("model").and_then(Value::as_str) != Some(expected_model) {
        log_schema_rejection(provider, path, object, "model");
        return Err(RelayFailure::InvalidProviderRequest);
    }

    let validation = match (provider, path) {
        (Provider::Openai, "/v1/responses") => validate_openai_response(object),
        (Provider::Anthropic, "/v1/messages") => validate_anthropic_messages(object),
        (Provider::Anthropic, "/v1/messages/count_tokens") => {
            validate_anthropic_count_tokens(object)
        }
        _ => return Err(RelayFailure::NotAllowed),
    };
    if validation.is_err() {
        let reason = schema_rejection_category(provider, path, object);
        log_schema_rejection(provider, path, object, &reason);
        return Err(RelayFailure::InvalidProviderRequest);
    }

    match (provider, path) {
        (Provider::Openai, "/v1/responses") => {
            clamp_output_tokens(object, "max_output_tokens", max_output_tokens)?;
        }
        (Provider::Anthropic, "/v1/messages") => {
            clamp_output_tokens(object, "max_tokens", max_output_tokens)?;
        }
        (Provider::Anthropic, "/v1/messages/count_tokens") => {}
        _ => return Err(RelayFailure::NotAllowed),
    }

    serde_json::to_vec(&value).map_err(|_| RelayFailure::InvalidProviderRequest)
}

fn validate_openai_response(object: &Map<String, Value>) -> Result<(), RelayFailure> {
    require_and_allow_keys(
        object,
        &[
            "model",
            "input",
            "tools",
            "tool_choice",
            "parallel_tool_calls",
            "store",
            "stream",
        ],
        &[
            "model",
            "instructions",
            "input",
            "tools",
            "tool_choice",
            "parallel_tool_calls",
            "reasoning",
            "store",
            "stream",
            "include",
            "prompt_cache_key",
            "prompt_cache_retention",
            "max_output_tokens",
            "text",
            "client_metadata",
        ],
    )?;
    if object.get("store") != Some(&Value::Bool(false))
        || object.get("stream") != Some(&Value::Bool(true))
        || !object
            .get("parallel_tool_calls")
            .is_some_and(Value::is_boolean)
        || object.get("tool_choice").and_then(Value::as_str) != Some("auto")
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    let input = object
        .get("input")
        .and_then(Value::as_array)
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    input.iter().try_for_each(validate_openai_input_item)?;
    let tools = object
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    tools.iter().try_for_each(validate_openai_tool)?;
    if let Some(include) = object.get("include") {
        let values = include
            .as_array()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        if values
            .iter()
            .any(|value| value.as_str() != Some("reasoning.encrypted_content"))
        {
            return Err(RelayFailure::InvalidProviderRequest);
        }
    }
    if let Some(reasoning) = object.get("reasoning").filter(|value| !value.is_null()) {
        let reasoning = reasoning
            .as_object()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        allow_keys(reasoning, &["effort", "summary"])?;
        for value in reasoning.values() {
            if !value.is_null() && !value.is_string() {
                return Err(RelayFailure::InvalidProviderRequest);
            }
        }
    }
    if let Some(text) = object.get("text").filter(|value| !value.is_null()) {
        let text = text
            .as_object()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        allow_keys(text, &["format", "verbosity"])?;
    }
    for key in ["instructions", "prompt_cache_key", "prompt_cache_retention"] {
        if object
            .get(key)
            .is_some_and(|value| !value.is_string() && !value.is_null())
        {
            return Err(RelayFailure::InvalidProviderRequest);
        }
    }
    if object
        .get("client_metadata")
        .is_some_and(|value| !value.is_object())
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    Ok(())
}

fn validate_openai_tool(value: &Value) -> Result<(), RelayFailure> {
    let tool = value
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    match tool.get("type").and_then(Value::as_str) {
        Some("function") => {
            require_and_allow_keys(
                tool,
                &["type", "name", "description", "parameters", "strict"],
                &["type", "name", "description", "parameters", "strict"],
            )?;
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .ok_or(RelayFailure::InvalidProviderRequest)?;
            if !matches!(
                name,
                "exec_command"
                    | "write_stdin"
                    | "update_plan"
                    | "request_user_input"
                    | "view_image"
                    | "close_agent"
                    | "resume_agent"
                    | "send_input"
                    | "spawn_agent"
                    | "wait_agent"
            ) || !tool.get("description").is_some_and(Value::is_string)
                || !tool.get("parameters").is_some_and(Value::is_object)
                || !tool.get("strict").is_some_and(Value::is_boolean)
                || contains_remote_schema_ref(&tool["parameters"])
            {
                return Err(RelayFailure::InvalidProviderRequest);
            }
        }
        Some("namespace") => {
            require_and_allow_keys(
                tool,
                &["type", "name", "description", "tools"],
                &["type", "name", "description", "tools"],
            )?;
            if tool.get("name").and_then(Value::as_str) != Some("multi_agent_v1")
                || !tool.get("description").is_some_and(Value::is_string)
            {
                return Err(RelayFailure::InvalidProviderRequest);
            }
            tool.get("tools")
                .and_then(Value::as_array)
                .ok_or(RelayFailure::InvalidProviderRequest)?
                .iter()
                .try_for_each(validate_openai_tool)?;
        }
        Some("custom") => validate_openai_apply_patch_tool(tool)?,
        Some("tool_search") => validate_openai_client_tool_search(tool)?,
        _ => return Err(RelayFailure::InvalidProviderRequest),
    }
    Ok(())
}

fn validate_openai_apply_patch_tool(tool: &Map<String, Value>) -> Result<(), RelayFailure> {
    require_and_allow_keys(
        tool,
        &["type", "name", "description", "format"],
        &["type", "name", "description", "format"],
    )?;
    if tool.get("name").and_then(Value::as_str) != Some("apply_patch")
        || !tool.get("description").is_some_and(Value::is_string)
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    let format = tool
        .get("format")
        .and_then(Value::as_object)
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(
        format,
        &["type", "syntax", "definition"],
        &["type", "syntax", "definition"],
    )?;
    if format.get("type").and_then(Value::as_str) != Some("grammar")
        || format.get("syntax").and_then(Value::as_str) != Some("lark")
        || !format.get("definition").is_some_and(Value::is_string)
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    Ok(())
}

fn validate_openai_client_tool_search(tool: &Map<String, Value>) -> Result<(), RelayFailure> {
    require_and_allow_keys(
        tool,
        &["type", "execution", "description", "parameters"],
        &["type", "execution", "description", "parameters"],
    )?;
    if tool.get("execution").and_then(Value::as_str) != Some("client")
        || !tool.get("description").is_some_and(Value::is_string)
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    let parameters = tool
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(
        parameters,
        &["type", "properties", "required", "additionalProperties"],
        &["type", "properties", "required", "additionalProperties"],
    )?;
    if parameters.get("type").and_then(Value::as_str) != Some("object")
        || parameters.get("additionalProperties") != Some(&Value::Bool(false))
        || parameters.get("required") != Some(&serde_json::json!(["query"]))
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    let properties = parameters
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(properties, &["query", "limit"], &["query", "limit"])?;
    validate_simple_schema(&properties["query"], "string")?;
    validate_simple_schema(&properties["limit"], "number")
}

fn validate_simple_schema(value: &Value, expected_type: &str) -> Result<(), RelayFailure> {
    let schema = value
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(schema, &["type", "description"], &["type", "description"])?;
    if schema.get("type").and_then(Value::as_str) != Some(expected_type)
        || !schema.get("description").is_some_and(Value::is_string)
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    Ok(())
}

fn validate_openai_input_item(value: &Value) -> Result<(), RelayFailure> {
    let item = value
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    match item.get("type").and_then(Value::as_str) {
        Some("message") => {
            allow_keys(item, &["type", "role", "content", "status", "phase"])?;
            if !matches!(
                item.get("role").and_then(Value::as_str),
                Some("developer" | "system" | "user" | "assistant")
            ) {
                return Err(RelayFailure::InvalidProviderRequest);
            }
            if let Some(phase) = item.get("phase").filter(|value| !value.is_null()) {
                if !matches!(phase.as_str(), Some("commentary" | "final_answer"))
                    || item.get("role").and_then(Value::as_str) != Some("assistant")
                {
                    return Err(RelayFailure::InvalidProviderRequest);
                }
            }
            item.get("content")
                .and_then(Value::as_array)
                .ok_or(RelayFailure::InvalidProviderRequest)?
                .iter()
                .try_for_each(|block| {
                    let block = block
                        .as_object()
                        .ok_or(RelayFailure::InvalidProviderRequest)?;
                    allow_keys(block, &["type", "text", "annotations", "logprobs"])?;
                    if !matches!(
                        block.get("type").and_then(Value::as_str),
                        Some("input_text" | "output_text" | "refusal")
                    ) || !block.get("text").is_some_and(Value::is_string)
                    {
                        return Err(RelayFailure::InvalidProviderRequest);
                    }
                    Ok(())
                })?;
        }
        Some("function_call") => {
            allow_keys(
                item,
                &["type", "id", "call_id", "name", "arguments", "status"],
            )?;
            if !item.get("call_id").is_some_and(Value::is_string)
                || !item.get("arguments").is_some_and(Value::is_string)
                || !item
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(is_openai_local_call_name)
            {
                return Err(RelayFailure::InvalidProviderRequest);
            }
        }
        Some("function_call_output") => {
            allow_keys(item, &["type", "id", "call_id", "output", "status"])?;
            if !item.get("call_id").is_some_and(Value::is_string)
                || !matches!(item.get("output"), Some(Value::String(_) | Value::Array(_)))
            {
                return Err(RelayFailure::InvalidProviderRequest);
            }
        }
        Some("reasoning") => {
            allow_keys(
                item,
                &[
                    "type",
                    "id",
                    "summary",
                    "content",
                    "encrypted_content",
                    "status",
                ],
            )?;
        }
        _ => return Err(RelayFailure::InvalidProviderRequest),
    }
    Ok(())
}

fn is_openai_local_call_name(name: &str) -> bool {
    matches!(
        name,
        "exec_command"
            | "write_stdin"
            | "update_plan"
            | "request_user_input"
            | "view_image"
            | "multi_agent_v1.close_agent"
            | "multi_agent_v1.resume_agent"
            | "multi_agent_v1.send_input"
            | "multi_agent_v1.spawn_agent"
            | "multi_agent_v1.wait_agent"
    )
}

fn validate_anthropic_messages(object: &Map<String, Value>) -> Result<(), RelayFailure> {
    require_and_allow_keys(
        object,
        &["model", "messages", "tools", "max_tokens", "stream"],
        &[
            "model",
            "messages",
            "system",
            "tools",
            "max_tokens",
            "stream",
            "temperature",
            "top_p",
            "top_k",
            "stop_sequences",
            "tool_choice",
            "thinking",
            "metadata",
            "output_config",
            "context_management",
        ],
    )?;
    if object.get("stream") != Some(&Value::Bool(true)) {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    validate_anthropic_common(object)
}

fn validate_anthropic_count_tokens(object: &Map<String, Value>) -> Result<(), RelayFailure> {
    require_and_allow_keys(
        object,
        &["model", "messages"],
        &[
            "model",
            "messages",
            "system",
            "tools",
            "tool_choice",
            "thinking",
            "context_management",
        ],
    )?;
    validate_anthropic_common(object)
}

fn validate_anthropic_common(object: &Map<String, Value>) -> Result<(), RelayFailure> {
    object
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(RelayFailure::InvalidProviderRequest)?
        .iter()
        .try_for_each(validate_anthropic_message)?;
    if let Some(system) = object.get("system") {
        validate_anthropic_content(system, false)?;
    }
    if let Some(tools) = object.get("tools") {
        tools
            .as_array()
            .ok_or(RelayFailure::InvalidProviderRequest)?
            .iter()
            .try_for_each(validate_anthropic_tool)?;
    }
    if let Some(tool_choice) = object.get("tool_choice") {
        let choice = tool_choice
            .as_object()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        allow_keys(choice, &["type", "name", "disable_parallel_tool_use"])?;
        if !matches!(
            choice.get("type").and_then(Value::as_str),
            Some("auto" | "any" | "tool" | "none")
        ) || choice
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| !is_anthropic_local_tool_name(name))
        {
            return Err(RelayFailure::InvalidProviderRequest);
        }
    }
    if let Some(thinking) = object.get("thinking") {
        let thinking = thinking
            .as_object()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        allow_keys(thinking, &["type", "budget_tokens"])?;
        if !matches!(
            thinking.get("type").and_then(Value::as_str),
            Some("enabled" | "disabled" | "adaptive")
        ) {
            return Err(RelayFailure::InvalidProviderRequest);
        }
    }
    if let Some(metadata) = object.get("metadata") {
        let metadata = metadata
            .as_object()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        allow_keys(metadata, &["user_id"])?;
        if metadata.get("user_id").is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|value| value.len() <= 512 && !value.chars().any(char::is_control))
        }) {
            return Err(RelayFailure::InvalidProviderRequest);
        }
    }
    if let Some(output) = object.get("output_config") {
        validate_anthropic_output_config(output)?;
    }
    if let Some(context) = object.get("context_management") {
        validate_anthropic_context_management(context)?;
    }
    Ok(())
}

fn validate_anthropic_output_config(value: &Value) -> Result<(), RelayFailure> {
    let output = value
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    allow_keys(output, &["effort", "format"])?;
    if output.get("effort").is_some_and(|value| {
        !value.is_null()
            && !matches!(
                value.as_str(),
                Some("low" | "medium" | "high" | "xhigh" | "max")
            )
    }) {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    if let Some(format) = output.get("format").filter(|value| !value.is_null()) {
        let format = format
            .as_object()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        require_and_allow_keys(format, &["type", "schema"], &["type", "schema"])?;
        if format.get("type").and_then(Value::as_str) != Some("json_schema")
            || !format.get("schema").is_some_and(Value::is_object)
            || contains_remote_schema_ref(&format["schema"])
        {
            return Err(RelayFailure::InvalidProviderRequest);
        }
    }
    Ok(())
}

fn validate_anthropic_context_management(value: &Value) -> Result<(), RelayFailure> {
    let context = value
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(context, &["edits"], &["edits"])?;
    let edits = context
        .get("edits")
        .and_then(Value::as_array)
        .filter(|edits| edits.len() == 1)
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    let edit = edits[0]
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(edit, &["type", "keep"], &["type", "keep"])?;
    if edit.get("type").and_then(Value::as_str) != Some("clear_thinking_20251015") {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    match edit.get("keep") {
        Some(Value::String(value)) if value == "all" => Ok(()),
        Some(Value::Object(keep)) => {
            require_and_allow_keys(keep, &["type", "value"], &["type", "value"])?;
            if keep.get("type").and_then(Value::as_str) != Some("thinking_turns")
                || !keep
                    .get("value")
                    .and_then(Value::as_u64)
                    .is_some_and(|value| (1..=64).contains(&value))
            {
                return Err(RelayFailure::InvalidProviderRequest);
            }
            Ok(())
        }
        _ => Err(RelayFailure::InvalidProviderRequest),
    }
}

fn validate_anthropic_tool(value: &Value) -> Result<(), RelayFailure> {
    let tool = value
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(
        tool,
        &["name", "description", "input_schema"],
        &["name", "description", "input_schema"],
    )?;
    if !tool
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(is_anthropic_local_tool_name)
        || !tool.get("description").is_some_and(Value::is_string)
        || !tool.get("input_schema").is_some_and(Value::is_object)
        || contains_remote_schema_ref(&tool["input_schema"])
    {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    Ok(())
}

fn is_anthropic_local_tool_name(name: &str) -> bool {
    matches!(name, "Bash" | "Read" | "Edit" | "Write" | "Glob" | "Grep")
}

fn validate_anthropic_message(value: &Value) -> Result<(), RelayFailure> {
    let message = value
        .as_object()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    require_and_allow_keys(message, &["role", "content"], &["role", "content"])?;
    if !matches!(
        message.get("role").and_then(Value::as_str),
        Some("user" | "assistant")
    ) {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    validate_anthropic_content(&message["content"], true)
}

fn validate_anthropic_content(value: &Value, allow_tool_blocks: bool) -> Result<(), RelayFailure> {
    if value.is_string() {
        return Ok(());
    }
    let blocks = value
        .as_array()
        .ok_or(RelayFailure::InvalidProviderRequest)?;
    for value in blocks {
        let block = value
            .as_object()
            .ok_or(RelayFailure::InvalidProviderRequest)?;
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                allow_keys(block, &["type", "text", "citations", "cache_control"])?;
                if !block.get("text").is_some_and(Value::is_string) {
                    return Err(RelayFailure::InvalidProviderRequest);
                }
            }
            Some("thinking") if allow_tool_blocks => {
                allow_keys(block, &["type", "thinking", "signature"])?;
            }
            Some("redacted_thinking") if allow_tool_blocks => {
                allow_keys(block, &["type", "data"])?;
            }
            Some("tool_use") if allow_tool_blocks => {
                allow_keys(block, &["type", "id", "name", "input", "caller"])?;
                if !block
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(is_anthropic_local_tool_name)
                {
                    return Err(RelayFailure::InvalidProviderRequest);
                }
            }
            Some("tool_result") if allow_tool_blocks => {
                allow_keys(
                    block,
                    &[
                        "type",
                        "tool_use_id",
                        "content",
                        "is_error",
                        "cache_control",
                    ],
                )?;
                let content = block
                    .get("content")
                    .ok_or(RelayFailure::InvalidProviderRequest)?;
                if !content.is_string() {
                    validate_anthropic_content(content, false)?;
                }
            }
            _ => return Err(RelayFailure::InvalidProviderRequest),
        }
    }
    Ok(())
}

fn require_and_allow_keys(
    object: &Map<String, Value>,
    required: &[&str],
    allowed: &[&str],
) -> Result<(), RelayFailure> {
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    allow_keys(object, allowed)
}

fn allow_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), RelayFailure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(RelayFailure::InvalidProviderRequest);
    }
    Ok(())
}

fn contains_remote_schema_ref(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key("$ref") || object.values().any(contains_remote_schema_ref)
        }
        Value::Array(values) => values.iter().any(contains_remote_schema_ref),
        _ => false,
    }
}

fn log_schema_rejection(provider: Provider, path: &str, object: &Map<String, Value>, reason: &str) {
    let mut keys = object
        .keys()
        .take(32)
        .map(|key| diagnostic_identifier(Some(key)))
        .collect::<Vec<_>>();
    keys.sort_unstable();
    let tools = object
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(16)
        .map(|tool| {
            let tool_type = diagnostic_identifier(tool.get("type").and_then(Value::as_str));
            let name = diagnostic_identifier(tool.get("name").and_then(Value::as_str));
            format!("{tool_type}:{name}")
        })
        .collect::<Vec<_>>()
        .join(",");
    let input = sanitized_input_shape(object);
    let nested = [
        "thinking",
        "metadata",
        "output_config",
        "tool_choice",
        "context_management",
    ]
    .into_iter()
    .map(|key| diagnostic_object_field(object, key))
    .collect::<Vec<_>>()
    .join(";");
    let system = object
        .get("system")
        .map_or_else(|| "<absent>".to_string(), sanitized_content_shape);
    eprintln!(
        "skill-relay schema_rejected provider={provider} path={path} reason={reason} top_keys={} tools={tools} input={input} system={system} nested={nested}",
        keys.join(",")
    );
}

fn schema_rejection_category(
    provider: Provider,
    path: &str,
    object: &Map<String, Value>,
) -> String {
    match (provider, path) {
        (Provider::Openai, "/v1/responses") => {
            let Some(input) = object.get("input").and_then(Value::as_array) else {
                return "openai.input".into();
            };
            if let Some((index, _)) = input
                .iter()
                .enumerate()
                .find(|(_, item)| validate_openai_input_item(item).is_err())
            {
                return format!("openai.input[{index}]");
            }
            let Some(tools) = object.get("tools").and_then(Value::as_array) else {
                return "openai.tools".into();
            };
            if let Some((index, _)) = tools
                .iter()
                .enumerate()
                .find(|(_, tool)| validate_openai_tool(tool).is_err())
            {
                return format!("openai.tools[{index}]");
            }
            "openai.envelope".into()
        }
        (Provider::Anthropic, "/v1/messages" | "/v1/messages/count_tokens") => {
            let Some(messages) = object.get("messages").and_then(Value::as_array) else {
                return "anthropic.messages".into();
            };
            if let Some((index, _)) = messages
                .iter()
                .enumerate()
                .find(|(_, message)| validate_anthropic_message(message).is_err())
            {
                return format!("anthropic.messages[{index}]");
            }
            if let Some(tools) = object.get("tools").and_then(Value::as_array) {
                if let Some((index, _)) = tools
                    .iter()
                    .enumerate()
                    .find(|(_, tool)| validate_anthropic_tool(tool).is_err())
                {
                    return format!("anthropic.tools[{index}]");
                }
            }
            "anthropic.envelope".into()
        }
        _ => "endpoint".into(),
    }
}

fn sanitized_input_shape(object: &Map<String, Value>) -> String {
    let Some(items) = object.get("input").and_then(Value::as_array) else {
        return "<absent-or-non-array>".into();
    };
    let mut summary = items
        .iter()
        .take(8)
        .enumerate()
        .map(|(index, item)| {
            let Some(item) = item.as_object() else {
                return format!("{index}:<non-object>");
            };
            let item_type = diagnostic_identifier(item.get("type").and_then(Value::as_str));
            let keys = diagnostic_map_keys(item, 12);
            let name = diagnostic_identifier(item.get("name").and_then(Value::as_str));
            let blocks = item
                .get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(8)
                .enumerate()
                .map(|(block_index, block)| {
                    let Some(block) = block.as_object() else {
                        return format!("{block_index}:<non-object>");
                    };
                    let block_type =
                        diagnostic_identifier(block.get("type").and_then(Value::as_str));
                    format!(
                        "{block_index}:{block_type}/{}",
                        diagnostic_map_keys(block, 8)
                    )
                })
                .collect::<Vec<_>>()
                .join("|");
            format!("{index}:{item_type}/keys={keys}/name={name}/blocks={blocks}")
        })
        .collect::<Vec<_>>()
        .join(";");
    if items.len() > 8 {
        summary.push_str(";<truncated-items>");
    }
    summary.truncate(summary.len().min(4_096));
    summary
}

fn diagnostic_map_keys(object: &Map<String, Value>, limit: usize) -> String {
    let mut keys = object
        .keys()
        .take(limit)
        .map(|key| diagnostic_identifier(Some(key)))
        .collect::<Vec<_>>();
    keys.sort_unstable();
    let mut summary = keys.join(",");
    if object.len() > limit {
        summary.push_str(",<truncated-keys>");
    }
    summary
}

fn diagnostic_object_field(object: &Map<String, Value>, key: &str) -> String {
    let Some(value) = object.get(key) else {
        return format!("{key}=<absent>");
    };
    let Some(value) = value.as_object() else {
        return format!("{key}=<non-object>");
    };
    let kind = diagnostic_identifier(value.get("type").and_then(Value::as_str));
    let edits = value
        .get("edits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(4)
        .map(|edit| {
            let Some(edit) = edit.as_object() else {
                return "<non-object>".to_string();
            };
            format!(
                "{}/{}",
                diagnostic_identifier(edit.get("type").and_then(Value::as_str)),
                diagnostic_map_keys(edit, 10)
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    format!(
        "{key}=keys:{}/type:{kind}/edits:{edits}",
        diagnostic_map_keys(value, 12)
    )
}

fn sanitized_content_shape(value: &Value) -> String {
    if value.is_string() {
        return "<string>".into();
    }
    let Some(blocks) = value.as_array() else {
        return "<non-string-non-array>".into();
    };
    blocks
        .iter()
        .take(8)
        .enumerate()
        .map(|(index, block)| {
            let Some(block) = block.as_object() else {
                return format!("{index}:<non-object>");
            };
            format!(
                "{index}:{}/{}",
                diagnostic_identifier(block.get("type").and_then(Value::as_str)),
                diagnostic_map_keys(block, 10)
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn diagnostic_identifier(value: Option<&str>) -> String {
    const SAFE: &[&str] = &[
        "model",
        "instructions",
        "input",
        "messages",
        "system",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "stream",
        "include",
        "prompt_cache_key",
        "prompt_cache_retention",
        "max_output_tokens",
        "max_tokens",
        "text",
        "client_metadata",
        "temperature",
        "top_p",
        "top_k",
        "stop_sequences",
        "thinking",
        "metadata",
        "output_config",
        "type",
        "role",
        "content",
        "status",
        "id",
        "call_id",
        "name",
        "arguments",
        "output",
        "summary",
        "encrypted_content",
        "phase",
        "execution",
        "annotations",
        "logprobs",
        "message",
        "input_text",
        "output_text",
        "refusal",
        "function_call",
        "function_call_output",
        "custom_tool_call",
        "custom_tool_call_output",
        "tool_search_call",
        "tool_search_output",
        "function",
        "custom",
        "apply_patch",
        "tool_search",
        "namespace",
        "multi_agent_v1",
        "exec_command",
        "write_stdin",
        "update_plan",
        "request_user_input",
        "view_image",
        "close_agent",
        "resume_agent",
        "send_input",
        "spawn_agent",
        "wait_agent",
        "Bash",
        "Read",
        "Edit",
        "Write",
        "Glob",
        "Grep",
        "web_search",
        "mcp",
        "computer_use_preview",
        "code_interpreter",
        "file_search",
        "image_generation",
        "web_search_20250305",
        "web_fetch_20250910",
        "code_execution_20250825",
        "computer_20250124",
    ];
    let Some(value) = value else {
        return "<absent>".into();
    };
    if SAFE.contains(&value) {
        return value.to_string();
    }
    // Never echo attacker-controlled JSON keys or tool names into durable logs.
    // This deterministic non-cryptographic tag is diagnostic only.
    let hash = value.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    });
    format!("<unknown:{hash:016x}:{}>", value.len().min(999))
}

fn clamp_output_tokens(
    object: &mut Map<String, Value>,
    field: &str,
    limit: u64,
) -> Result<(), RelayFailure> {
    let bounded = match object.get(field) {
        None | Some(Value::Null) => limit,
        Some(Value::Number(value)) => value
            .as_u64()
            .filter(|value| *value > 0)
            .map(|value| value.min(limit))
            .ok_or(RelayFailure::InvalidProviderRequest)?,
        Some(_) => return Err(RelayFailure::InvalidProviderRequest),
    };
    object.insert(field.to_string(), Value::Number(Number::from(bounded)));
    Ok(())
}

fn append_bounded(
    destination: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), RelayFailure> {
    let new_length = destination
        .len()
        .checked_add(chunk.len())
        .ok_or(RelayFailure::ResponseTooLarge)?;
    if new_length > limit {
        return Err(RelayFailure::ResponseTooLarge);
    }
    destination.extend_from_slice(chunk);
    Ok(())
}

fn sanitize_request_headers(headers: &HeaderMap) -> HeaderMap {
    sanitize_headers(headers, true)
}

fn sanitize_response_headers(headers: &HeaderMap) -> HeaderMap {
    sanitize_headers(headers, false)
}

fn sanitize_headers(headers: &HeaderMap, request: bool) -> HeaderMap {
    let connection_headers = connection_named_headers(headers);
    let mut sanitized = HeaderMap::new();
    for (name, value) in headers {
        if is_hop_by_hop(name)
            || connection_headers.contains(name)
            || name == CONTENT_LENGTH
            || (request && is_request_secret_or_routing_header(name))
            || (!request && (name == LOCATION || matches!(name.as_str(), "alt-svc" | "set-cookie")))
        {
            continue;
        }
        sanitized.append(name.clone(), value.clone());
    }
    sanitized
}

fn connection_named_headers(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_str(name.trim()).ok())
        .collect()
}

fn is_request_secret_or_routing_header(name: &HeaderName) -> bool {
    name == AUTHORIZATION
        || name == HOST
        || name.as_str() == "x-api-key"
        || name.as_str() == "proxy-authorization"
        || name.as_str() == "cookie"
        || name.as_str() == "anthropic-version"
        || name == ACCEPT_ENCODING
        || name.as_str() == "forwarded"
        || name.as_str() == "via"
        || name.as_str().starts_with("x-forwarded-")
        || matches!(name.as_str(), "x-original-url" | "x-rewrite-url")
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "expect"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn check(args: CheckArgs) -> Result<(), Box<dyn Error>> {
    if args.timeout_seconds == 0 {
        return Err("health timeout must be greater than zero".into());
    }
    if !args.unix_socket.is_absolute()
        || args.unix_socket.as_os_str().as_encoded_bytes().len() > 100
    {
        return Err("health Unix socket must use a short absolute path".into());
    }
    verify_socket_metadata(&args.unix_socket)?;

    let timeout = Duration::from_secs(args.timeout_seconds);
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .unix_socket(args.unix_socket.clone())
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()?;
    let mut response = client.get("http://localhost/healthz").send().await?;
    if response.status() != StatusCode::OK {
        return Err("relay health check failed".into());
    }
    if response
        .content_length()
        .is_some_and(|size| size > HEALTH_BODY_LIMIT as u64)
    {
        return Err("relay health response exceeds the size limit".into());
    }
    let mut size = 0usize;
    while let Some(chunk) = response.chunk().await? {
        size = size
            .checked_add(chunk.len())
            .ok_or("relay health response exceeds the size limit")?;
        if size > HEALTH_BODY_LIMIT {
            return Err("relay health response exceeds the size limit".into());
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_endpoint_allowlist_is_exact() {
        let post = Method::POST;
        assert!(Provider::Openai.allows(&post, &Uri::from_static("/v1/responses")));
        assert!(!Provider::Openai.allows(&post, &Uri::from_static("/v1/messages")));
        assert!(!Provider::Openai.allows(
            &post,
            &Uri::from_static("/v1/responses?redirect=https://example.invalid")
        ));
        assert!(Provider::Anthropic.allows(&post, &Uri::from_static("/v1/messages")));
        assert!(Provider::Anthropic.allows(&post, &Uri::from_static("/v1/messages?beta=true")));
        assert!(Provider::Anthropic.allows(&post, &Uri::from_static("/v1/messages/count_tokens")));
        assert!(Provider::Anthropic.allows(
            &post,
            &Uri::from_static("/v1/messages/count_tokens?beta=true")
        ));
        assert!(!Provider::Anthropic.allows(&post, &Uri::from_static("/v1/messages?beta=false")));
        assert!(!Provider::Anthropic.allows(
            &post,
            &Uri::from_static("/v1/messages?beta=true&redirect=https://example.invalid")
        ));
        assert!(!Provider::Anthropic.allows(&Method::GET, &Uri::from_static("/v1/messages")));
    }

    fn constrained_json(provider: Provider, path: &str, body: Value) -> Value {
        let encoded = serde_json::to_vec(&body).unwrap();
        let constrained =
            constrain_provider_body(provider, path, &encoded, "expected-model", 4_096).unwrap();
        serde_json::from_slice(&constrained).unwrap()
    }

    fn openai_body() -> Value {
        serde_json::json!({
            "model":"expected-model",
            "instructions":"local harness",
            "input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}],
            "tools":[],
            "tool_choice":"auto",
            "parallel_tool_calls":true,
            "store":false,
            "stream":true
        })
    }

    fn anthropic_body() -> Value {
        serde_json::json!({
            "model":"expected-model",
            "max_tokens":100_000,
            "messages":[{"role":"user","content":"hello"}],
            "tools":[],
            "stream":true
        })
    }

    #[test]
    fn generation_requests_require_model_and_inject_or_clamp_output_tokens() {
        let openai = constrained_json(Provider::Openai, "/v1/responses", openai_body());
        assert_eq!(openai["max_output_tokens"], 4_096);

        let anthropic = constrained_json(Provider::Anthropic, "/v1/messages", anthropic_body());
        assert_eq!(anthropic["max_tokens"], 4_096);

        let mut below_body = openai_body();
        below_body["max_output_tokens"] = Value::from(128);
        let below_cap = constrained_json(Provider::Openai, "/v1/responses", below_body);
        assert_eq!(below_cap["max_output_tokens"], 128);
    }

    #[test]
    fn count_tokens_validates_model_without_injecting_output_tokens() {
        let constrained = constrained_json(
            Provider::Anthropic,
            "/v1/messages/count_tokens",
            serde_json::json!({"model":"expected-model","messages":[]}),
        );
        assert_eq!(constrained["model"], "expected-model");
        assert!(constrained.get("max_tokens").is_none());
    }

    #[test]
    fn malformed_non_object_mismatched_and_invalid_token_bodies_are_rejected() {
        for body in [
            b"not-json".as_slice(),
            br#"[1,2,3]"#,
            br#"{"input":"missing model"}"#,
            br#"{"model":"different-model"}"#,
            br#"{"model":"expected-model","max_output_tokens":0}"#,
            br#"{"model":"expected-model","max_output_tokens":"4096"}"#,
        ] {
            assert!(matches!(
                constrain_provider_body(
                    Provider::Openai,
                    "/v1/responses",
                    body,
                    "expected-model",
                    4_096
                ),
                Err(RelayFailure::InvalidProviderRequest)
            ));
        }
    }

    #[test]
    fn provider_hosted_tools_and_spend_or_storage_controls_are_rejected() {
        for (field, value) in [
            ("background", Value::Bool(true)),
            ("service_tier", Value::String("priority".into())),
            ("priority", Value::Bool(true)),
        ] {
            let mut body = openai_body();
            body[field] = value;
            assert!(constrain_provider_body(
                Provider::Openai,
                "/v1/responses",
                &serde_json::to_vec(&body).unwrap(),
                "expected-model",
                4096
            )
            .is_err());
        }
        let mut stored = openai_body();
        stored["store"] = Value::Bool(true);
        assert!(constrain_provider_body(
            Provider::Openai,
            "/v1/responses",
            &serde_json::to_vec(&stored).unwrap(),
            "expected-model",
            4096
        )
        .is_err());

        for tool_type in [
            "web_search",
            "mcp",
            "computer_use_preview",
            "code_interpreter",
            "file_search",
            "image_generation",
        ] {
            let mut body = openai_body();
            body["tools"] = serde_json::json!([{"type":tool_type}]);
            assert!(constrain_provider_body(
                Provider::Openai,
                "/v1/responses",
                &serde_json::to_vec(&body).unwrap(),
                "expected-model",
                4096
            )
            .is_err());
        }

        for tool_type in [
            "web_search_20250305",
            "web_fetch_20250910",
            "code_execution_20250825",
            "computer_20250124",
        ] {
            let mut body = anthropic_body();
            body["tools"] = serde_json::json!([{"type":tool_type,"name":"Bash"}]);
            assert!(constrain_provider_body(
                Provider::Anthropic,
                "/v1/messages",
                &serde_json::to_vec(&body).unwrap(),
                "expected-model",
                4096
            )
            .is_err());
        }
    }

    #[test]
    fn pinned_local_tool_shapes_are_accepted() {
        let mut openai = openai_body();
        openai["tools"] = serde_json::json!([
            {"type":"function","name":"exec_command","description":"local","parameters":{"type":"object"},"strict":false},
            {"type":"namespace","name":"multi_agent_v1","description":"local","tools":[
                {"type":"function","name":"spawn_agent","description":"local","parameters":{"type":"object"},"strict":false}
            ]},
            {"type":"custom","name":"apply_patch","description":"local patch application","format":{
                "type":"grammar","syntax":"lark","definition":"start: PATCH"
            }},
            {"type":"tool_search","execution":"client","description":"local deferred-tool search","parameters":{
                "type":"object",
                "properties":{
                    "limit":{"type":"number","description":"Maximum results"},
                    "query":{"type":"string","description":"Search query"}
                },
                "required":["query"],
                "additionalProperties":false
            }}
        ]);
        constrained_json(Provider::Openai, "/v1/responses", openai);

        let mut follow_up = openai_body();
        follow_up["input"] = serde_json::json!([{
            "type":"message","role":"assistant","phase":"commentary",
            "content":[{"type":"output_text","text":"local progress"}]
        }]);
        constrained_json(Provider::Openai, "/v1/responses", follow_up);

        let mut anthropic = anthropic_body();
        anthropic["tools"] = serde_json::json!([
            {"name":"Bash","description":"local","input_schema":{"type":"object"}},
            {"name":"Read","description":"local","input_schema":{"type":"object"}}
        ]);
        anthropic["output_config"] = serde_json::json!({
            "effort":"low",
            "format":{"type":"json_schema","schema":{
                "type":"object","properties":{"ok":{"type":"boolean"}},
                "required":["ok"],"additionalProperties":false
            }}
        });
        anthropic["context_management"] = serde_json::json!({
            "edits":[{"type":"clear_thinking_20251015","keep":{
                "type":"thinking_turns","value":2
            }}]
        });
        constrained_json(Provider::Anthropic, "/v1/messages", anthropic);
    }

    #[test]
    fn anthropic_output_and_context_controls_remain_fail_closed() {
        for (field, value) in [
            (
                "output_config",
                serde_json::json!({"format":{"type":"json_schema","schema":{
                    "$ref":"https://attacker.invalid/schema"
                }}}),
            ),
            (
                "context_management",
                serde_json::json!({"edits":[{
                    "type":"clear_tool_uses_20250919","keep":"all"
                }]}),
            ),
            (
                "context_management",
                serde_json::json!({"edits":[{
                    "type":"clear_thinking_20251015",
                    "keep":{"type":"thinking_turns","value":0}
                }]}),
            ),
        ] {
            let mut body = anthropic_body();
            body[field] = value;
            assert!(constrain_provider_body(
                Provider::Anthropic,
                "/v1/messages",
                &serde_json::to_vec(&body).unwrap(),
                "expected-model",
                4096
            )
            .is_err());
        }
    }

    #[test]
    fn openai_local_tool_variants_remain_fail_closed() {
        for tool in [
            serde_json::json!({"type":"local_shell"}),
            serde_json::json!({
                "type":"custom","name":"other","description":"x",
                "format":{"type":"grammar","syntax":"lark","definition":"start: X"}
            }),
            serde_json::json!({
                "type":"custom","name":"apply_patch","description":"x",
                "format":{"type":"grammar","syntax":"regex","definition":".*"}
            }),
            serde_json::json!({
                "type":"tool_search","execution":"server","description":"x",
                "parameters":{
                    "type":"object","properties":{
                        "limit":{"type":"number","description":"Maximum results"},
                        "query":{"type":"string","description":"Search query"}
                    },"required":["query"],"additionalProperties":false
                }
            }),
        ] {
            let mut body = openai_body();
            body["tools"] = Value::Array(vec![tool]);
            assert!(constrain_provider_body(
                Provider::Openai,
                "/v1/responses",
                &serde_json::to_vec(&body).unwrap(),
                "expected-model",
                4096
            )
            .is_err());
        }
    }

    #[test]
    fn openai_message_phase_is_pinned_to_assistant_output_phases() {
        for message in [
            serde_json::json!({
                "type":"message","role":"assistant","phase":"attacker",
                "content":[{"type":"output_text","text":"x"}]
            }),
            serde_json::json!({
                "type":"message","role":"user","phase":"commentary",
                "content":[{"type":"input_text","text":"x"}]
            }),
        ] {
            let mut body = openai_body();
            body["input"] = Value::Array(vec![message]);
            assert!(constrain_provider_body(
                Provider::Openai,
                "/v1/responses",
                &serde_json::to_vec(&body).unwrap(),
                "expected-model",
                4096
            )
            .is_err());
        }
    }

    #[test]
    fn request_headers_strip_auth_routing_hop_and_connection_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("attacker-token"));
        headers.insert(HOST, HeaderValue::from_static("example.invalid"));
        headers.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("attacker-token"),
        );
        headers.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("session=attacker-token"),
        );
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-remove-me"),
        );
        headers.insert(
            HeaderName::from_static("x-remove-me"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("9000"));

        let sanitized = sanitize_request_headers(&headers);
        assert!(!sanitized.contains_key(AUTHORIZATION));
        assert!(!sanitized.contains_key(HOST));
        assert!(!sanitized.contains_key("x-api-key"));
        assert!(!sanitized.contains_key("cookie"));
        assert!(!sanitized.contains_key(CONNECTION));
        assert!(!sanitized.contains_key("x-remove-me"));
        assert!(!sanitized.contains_key(CONTENT_LENGTH));
        assert_eq!(sanitized["content-type"], "application/json");
    }

    #[test]
    fn provider_auth_replaces_untrusted_auth() {
        let mut raw = HeaderValue::from_static("real-secret");
        raw.set_sensitive(true);
        let mut bearer = HeaderValue::from_static("Bearer real-secret");
        bearer.set_sensitive(true);
        let credential = Credential {
            raw,
            openai_bearer: bearer,
        };
        assert_eq!(format!("{credential:?}"), "Credential([REDACTED])");

        let mut openai = HeaderMap::new();
        Provider::Openai.inject_auth(&credential, &mut openai);
        assert_eq!(openai[AUTHORIZATION], "Bearer real-secret");
        assert!(openai[AUTHORIZATION].is_sensitive());

        let mut anthropic = HeaderMap::new();
        Provider::Anthropic.inject_auth(&credential, &mut anthropic);
        assert_eq!(anthropic["x-api-key"], "real-secret");
        assert!(anthropic["x-api-key"].is_sensitive());
        assert_eq!(anthropic["anthropic-version"], "2023-06-01");
    }

    #[test]
    fn request_budget_never_exceeds_bound() {
        let budget = RequestBudget::new(2);
        assert!(budget.reserve());
        assert!(budget.reserve());
        assert!(!budget.reserve());
        assert_eq!(budget.used.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cumulative_request_body_budget_never_exceeds_bound() {
        let budget = ByteBudget::new(10);
        assert!(budget.reserve(4));
        assert!(budget.reserve(6));
        assert!(!budget.reserve(1));
        assert_eq!(budget.used.load(Ordering::Relaxed), 10);
    }

    #[tokio::test]
    async fn invalid_endpoint_allowed_requests_consume_request_count_budget() {
        let mut raw = HeaderValue::from_static("secret");
        raw.set_sensitive(true);
        let mut bearer = HeaderValue::from_static("Bearer secret");
        bearer.set_sensitive(true);
        let state = Arc::new(StateData {
            provider: Provider::Openai,
            credential: Credential {
                raw,
                openai_bearer: bearer,
            },
            expected_model: "expected-model".into(),
            max_output_tokens: 4_096,
            client: reqwest::Client::new(),
            request_body_limit: 4_096,
            request_body_budget: ByteBudget::new(8_192),
            response_body_limit: 4_096,
            request_budget: RequestBudget::new(1),
            concurrency: Arc::new(Semaphore::new(1)),
            timeout: Duration::from_secs(1),
        });
        let invalid = || {
            Request::builder()
                .method(Method::POST)
                .uri("/v1/responses")
                .body(Body::from(r#"{"model":"wrong"}"#))
                .unwrap()
        };
        assert!(matches!(
            handle_relay(Arc::clone(&state), invalid()).await,
            Err(RelayFailure::InvalidProviderRequest)
        ));
        assert!(matches!(
            handle_relay(state, invalid()).await,
            Err(RelayFailure::TooManyRequests)
        ));
    }

    #[test]
    fn schema_diagnostics_never_echo_unknown_identifiers() {
        let secret_like = "attacker-controlled-json-key-material";
        let diagnostic = diagnostic_identifier(Some(secret_like));
        assert!(diagnostic.starts_with("<unknown:"));
        assert!(!diagnostic.contains(secret_like));

        let object = serde_json::json!({
            "context_management": {
                "edits": [{"type": secret_like, secret_like: true}]
            }
        });
        let shape = diagnostic_object_field(object.as_object().unwrap(), "context_management");
        assert!(!shape.contains(secret_like));
        let content = serde_json::json!([{"type": secret_like, secret_like: "hidden"}]);
        assert!(!sanitized_content_shape(&content).contains(secret_like));
    }

    #[tokio::test]
    async fn request_body_limit_rejects_oversize_input() {
        assert!(to_bytes(Body::from("12345"), 4).await.is_err());
        assert_eq!(to_bytes(Body::from("1234"), 4).await.unwrap().len(), 4);
    }

    #[test]
    fn response_headers_strip_redirect_and_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://example.invalid"),
        );
        headers.insert(CONNECTION, HeaderValue::from_static("x-remove-me"));
        headers.insert(
            HeaderName::from_static("x-remove-me"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("alt-svc"),
            HeaderValue::from_static("h3=\"example.invalid:443\""),
        );
        headers.insert(
            HeaderName::from_static("set-cookie"),
            HeaderValue::from_static("session=provider-token"),
        );

        let sanitized = sanitize_response_headers(&headers);
        assert!(!sanitized.contains_key(LOCATION));
        assert!(!sanitized.contains_key(CONNECTION));
        assert!(!sanitized.contains_key("x-remove-me"));
        assert!(!sanitized.contains_key("alt-svc"));
        assert!(!sanitized.contains_key("set-cookie"));
        assert_eq!(sanitized["content-type"], "application/json");
    }

    #[test]
    fn response_body_limit_is_enforced_without_partial_append() {
        let mut body = b"123".to_vec();
        assert!(append_bounded(&mut body, b"4", 4).is_ok());
        assert!(matches!(
            append_bounded(&mut body, b"5", 4),
            Err(RelayFailure::ResponseTooLarge)
        ));
        assert_eq!(body, b"1234");
    }
}
