use std::collections::{BTreeSet, VecDeque};
use std::io::Read;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use url::{Host, Url};

const USER_AGENT: &str = "skillsissue.ai-ingest/0.1 (+https://skillsissue.ai/#methodology)";
const MAX_CATALOG_BYTES: usize = 96 * 1024 * 1024;
const MAX_DETAIL_BYTES: usize = 4 * 1024 * 1024;
const MAX_MARKDOWN_BYTES: usize = 16 * 1024 * 1024;
const MAX_CATALOG_DOCUMENTS: usize = 32;
const MAX_DETAIL_URLS: usize = 500_000;
const MAX_REDIRECTS: usize = 3;

static LOC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<loc>\s*([^<]+?)\s*</loc>").expect("valid loc regex"));
static HREF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)href\s*=\s*["']([^"']+)["']"#).expect("valid href regex"));
static MARKDOWN_LINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)\]\((https://[^\s)>]+)").expect("valid Markdown link regex"));

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogCandidate {
    pub detail_url: String,
    pub provenance_path: String,
    pub source: CatalogSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogSource {
    GitHub(GitHubSource),
    Markdown { markdown_url: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubSource {
    pub repository_url: String,
    pub requested_revision: Option<String>,
    pub source_path: Option<PathBuf>,
    pub repository_provenance_prefix: String,
    pub provenance_prefix: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CatalogScan {
    pub candidates: Vec<CatalogCandidate>,
    pub errors: Vec<String>,
}

pub fn discover(
    locator: &str,
    platform_id: &str,
    poll_sequence: u64,
    rate_limit_per_minute: Option<u32>,
    probe_limit: usize,
) -> Result<CatalogScan> {
    if probe_limit == 0 {
        bail!("catalog probe limit must be greater than zero");
    }
    let root = parse_public_https(locator).context("validate catalog locator")?;
    let mut http = CatalogHttp::new(rate_limit_per_minute)?;
    let detail_urls = collect_detail_urls(&mut http, &root, platform_id)?;
    if detail_urls.is_empty() {
        bail!("catalog did not expose any supported skill detail URLs");
    }

    let start = (poll_sequence as usize)
        .wrapping_mul(probe_limit)
        .wrapping_rem(detail_urls.len());
    let mut scan = CatalogScan::default();
    for offset in 0..probe_limit.min(detail_urls.len()) {
        let detail = &detail_urls[(start + offset) % detail_urls.len()];
        match http
            .get(detail, MAX_DETAIL_BYTES)
            .and_then(|body| extract_candidate(platform_id, detail, &body))
        {
            Ok(Some(candidate)) => scan.candidates.push(candidate),
            Ok(None) => {}
            Err(error) => scan
                .errors
                .push(format!("catalog detail {}: {error:#}", detail)),
        }
    }
    Ok(scan)
}

pub fn fetch_markdown(
    markdown_url: &str,
    detail_url: &str,
    rate_limit_per_minute: Option<u32>,
    configured_limit: u64,
) -> Result<Vec<u8>> {
    let detail = parse_public_https(detail_url).context("validate catalog detail URL")?;
    let markdown = parse_public_https(markdown_url).context("validate catalog Markdown URL")?;
    if !same_origin(&detail, &markdown) {
        bail!("catalog Markdown download changed origin");
    }
    let configured_limit = usize::try_from(configured_limit).unwrap_or(usize::MAX);
    let limit = configured_limit.min(MAX_MARKDOWN_BYTES);
    if limit == 0 {
        bail!("catalog Markdown byte limit must be greater than zero");
    }
    let mut http = CatalogHttp::new(rate_limit_per_minute)?;
    let bytes = http.get(&markdown, limit)?;
    if bytes.is_empty() {
        bail!("catalog Markdown download was empty");
    }
    Ok(bytes)
}

fn collect_detail_urls(http: &mut CatalogHttp, root: &Url, platform_id: &str) -> Result<Vec<Url>> {
    let mut queue = VecDeque::from([root.clone()]);
    let mut visited = BTreeSet::new();
    let mut details = Vec::new();
    let mut detail_keys = BTreeSet::new();

    while let Some(document_url) = queue.pop_front() {
        if visited.len() >= MAX_CATALOG_DOCUMENTS {
            bail!("catalog exceeded the document traversal limit");
        }
        if !same_origin(root, &document_url) {
            bail!("catalog document changed origin");
        }
        if !visited.insert(document_url.as_str().to_owned()) {
            continue;
        }
        let body = http.get(&document_url, MAX_CATALOG_BYTES)?;
        let text = std::str::from_utf8(&body).context("catalog document is not UTF-8")?;
        if text.contains("<sitemapindex") {
            for child in extract_locs(&document_url, text) {
                if same_origin(root, &child)
                    && should_follow_sitemap(platform_id, &child)
                    && !visited.contains(child.as_str())
                {
                    queue.push_back(child);
                }
            }
            continue;
        }

        let urls = if text.contains("<urlset") {
            extract_locs(&document_url, text)
        } else if document_url.path().ends_with(".txt") || text.trim_start().starts_with('#') {
            extract_markdown_urls(&document_url, text)
        } else {
            extract_href_urls(&document_url, text)
        };
        for mut url in urls {
            url.set_fragment(None);
            if same_origin(root, &url)
                && is_detail_url(platform_id, &document_url, &url)
                && detail_keys.insert(url.as_str().to_owned())
            {
                details.push(url);
                if details.len() >= MAX_DETAIL_URLS {
                    return Ok(details);
                }
            }
        }
    }
    Ok(details)
}

fn extract_locs(base: &Url, text: &str) -> Vec<Url> {
    LOC_RE
        .captures_iter(text)
        .filter_map(|capture| resolve_reference(base, &decode_html(capture.get(1)?.as_str())))
        .collect()
}

fn extract_href_urls(base: &Url, text: &str) -> Vec<Url> {
    HREF_RE
        .captures_iter(text)
        .filter_map(|capture| resolve_reference(base, &decode_html(capture.get(1)?.as_str())))
        .collect()
}

fn extract_markdown_urls(base: &Url, text: &str) -> Vec<Url> {
    MARKDOWN_LINK_RE
        .captures_iter(text)
        .filter_map(|capture| resolve_reference(base, capture.get(1)?.as_str()))
        .collect()
}

fn extract_candidate(
    platform_id: &str,
    detail: &Url,
    body: &[u8],
) -> Result<Option<CatalogCandidate>> {
    let text = std::str::from_utf8(body).context("catalog detail is not UTF-8")?;
    let links = extract_href_urls(detail, text);
    let provenance_path = detail
        .path()
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_owned();
    let provenance_path = if provenance_path.is_empty() {
        "catalog".to_owned()
    } else {
        provenance_path
    };

    if let Some(markdown) = links.iter().find(|url| {
        same_origin(detail, url)
            && (url.path().to_ascii_lowercase().ends_with("/skill.md")
                || platform_id == "skillregistry"
                    && url.path().to_ascii_lowercase().ends_with(".md"))
    }) {
        return Ok(Some(CatalogCandidate {
            detail_url: detail.as_str().to_owned(),
            provenance_path,
            source: CatalogSource::Markdown {
                markdown_url: markdown.as_str().to_owned(),
            },
        }));
    }

    let mut repositories = links
        .iter()
        .filter_map(parse_github_source)
        .filter(|source| !is_catalog_repository(platform_id, &source.repository_url))
        .collect::<Vec<_>>();
    repositories.sort_by_key(|source| source.source_path.is_none());
    let Some(source) = repositories.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(CatalogCandidate {
        detail_url: detail.as_str().to_owned(),
        provenance_path,
        source: CatalogSource::GitHub(source),
    }))
}

fn parse_github_source(url: &Url) -> Option<GitHubSource> {
    if url.scheme() != "https" || !url.host_str()?.eq_ignore_ascii_case("github.com") {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() < 2 || segments[0].is_empty() || segments[1].is_empty() {
        return None;
    }
    let owner = segments[0];
    let repository = segments[1].trim_end_matches(".git");
    if repository.is_empty() || matches!(repository, "features" | "topics" | "marketplace") {
        return None;
    }
    let mut requested_revision = None;
    let mut source_path = None;
    if segments.len() >= 4 && matches!(segments[2], "tree" | "blob") {
        if !segments[3].is_empty() {
            requested_revision = Some(segments[3].to_owned());
        }
        if segments.len() > 4 {
            let mut path = PathBuf::new();
            for segment in &segments[4..] {
                if segment.is_empty() || *segment == "." || *segment == ".." {
                    return None;
                }
                path.push(segment);
            }
            if segments[2] == "blob" {
                path.pop();
            }
            if !path.as_os_str().is_empty() {
                source_path = Some(path);
            }
        }
    }
    let repository_provenance_prefix = format!("github/{owner}/{repository}");
    let mut provenance_prefix = repository_provenance_prefix.clone();
    if let Some(path) = &source_path {
        provenance_prefix.push('/');
        provenance_prefix.push_str(&path.to_string_lossy().replace('\\', "/"));
    }
    Some(GitHubSource {
        repository_url: format!("https://github.com/{owner}/{repository}"),
        requested_revision,
        source_path,
        repository_provenance_prefix,
        provenance_prefix,
    })
}

fn should_follow_sitemap(platform_id: &str, url: &Url) -> bool {
    match platform_id {
        "skills-sh" => url.path().contains("sitemap-skills-"),
        "smithery-skills" => url.path().contains("/skills/sitemap/"),
        _ => url.path().contains("sitemap") || url.path().ends_with(".xml"),
    }
}

fn is_detail_url(platform_id: &str, document: &Url, url: &Url) -> bool {
    let path = url.path().trim_end_matches('/');
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    match platform_id {
        "skillsllm" => segments.len() == 2 && segments[0] == "skill",
        "skills-sh" => document.path().contains("sitemap-skills-") && segments.len() >= 3,
        "skillregistry" => segments.len() == 2 && segments[0] == "skill",
        "mcpservers-agent-skills" => {
            segments.len() >= 3
                && segments[0] == "agent-skills"
                && !matches!(segments[1], "author" | "category" | "official")
        }
        "smithery-skills" => segments.len() >= 3 && segments[0] == "skills",
        "lobehub-skills" => {
            segments.len() == 2
                && segments[0] == "skills"
                && !matches!(segments[1], "collection" | "skill.md")
        }
        "ai-agents-directory" => segments.len() == 2 && segments[0] == "skills",
        "mcpmarket-skills" => {
            segments.len() == 3
                && segments[0] == "tools"
                && segments[1] == "skills"
                && !matches!(
                    segments[2],
                    "all" | "categories" | "leaderboard" | "official"
                )
        }
        _ => false,
    }
}

fn is_catalog_repository(platform_id: &str, repository_url: &str) -> bool {
    match platform_id {
        "lobehub-skills" => {
            repository_url.eq_ignore_ascii_case("https://github.com/lobehub/lobehub")
        }
        "smithery-skills" => repository_url
            .strip_prefix("https://github.com/")
            .is_some_and(|path| path.starts_with("smithery-ai/")),
        _ => false,
    }
}

fn resolve_reference(base: &Url, value: &str) -> Option<Url> {
    let value = value.trim();
    if value.is_empty() || value.starts_with("javascript:") || value.starts_with("data:") {
        return None;
    }
    let mut url = base.join(value).ok()?;
    if validate_public_https_url(&url).is_err() {
        return None;
    }
    url.set_fragment(None);
    Some(url)
}

fn decode_html(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn parse_public_https(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("parse URL")?;
    validate_public_https_url(&url)?;
    Ok(url)
}

fn validate_public_https_url(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        bail!("catalog URLs must use HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("catalog URLs must not contain credentials");
    }
    if url.port().is_some() {
        bail!("catalog URLs must use the default HTTPS port");
    }
    match url.host() {
        Some(Host::Domain(host))
            if !host.eq_ignore_ascii_case("localhost") && host.contains('.') => {}
        _ => bail!("catalog URLs must use a public DNS hostname"),
    }
    Ok(())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

struct CatalogHttp {
    client: Client,
    request_interval: Duration,
    last_request: Option<Instant>,
}

impl CatalogHttp {
    fn new(rate_limit_per_minute: Option<u32>) -> Result<Self> {
        let requests = rate_limit_per_minute.unwrap_or(60).max(1);
        let request_interval = Duration::from_secs_f64(60.0 / f64::from(requests));
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .redirect(Policy::none())
            .user_agent(USER_AGENT)
            .build()
            .context("build catalog HTTP client")?;
        Ok(Self {
            client,
            request_interval,
            last_request: None,
        })
    }

    fn get(&mut self, url: &Url, max_bytes: usize) -> Result<Vec<u8>> {
        validate_public_https_url(url)?;
        let mut current = url.clone();
        for redirect_count in 0..=MAX_REDIRECTS {
            self.wait_for_rate_limit();
            let response = self
                .client
                .get(current.clone())
                .send()
                .with_context(|| format!("GET {current}"))?;
            self.last_request = Some(Instant::now());
            if response.status().is_redirection() {
                if redirect_count == MAX_REDIRECTS {
                    bail!("catalog redirect limit exceeded");
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .context("catalog redirect omitted Location")?
                    .to_str()
                    .context("catalog redirect Location is not ASCII")?;
                let next = current.join(location).context("resolve catalog redirect")?;
                validate_public_https_url(&next)?;
                if !same_origin(url, &next) {
                    bail!("catalog redirect changed origin");
                }
                current = next;
                continue;
            }
            if !response.status().is_success() {
                bail!("catalog request returned HTTP {}", response.status());
            }
            if response
                .content_length()
                .is_some_and(|length| length > max_bytes as u64)
            {
                bail!("catalog response exceeded the byte limit");
            }
            let mut bytes = Vec::new();
            response
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .context("read catalog response")?;
            if bytes.len() > max_bytes {
                bail!("catalog response exceeded the byte limit");
            }
            return Ok(bytes);
        }
        unreachable!("redirect loop returns or fails")
    }

    fn wait_for_rate_limit(&self) {
        if let Some(last_request) = self.last_request
            && let Some(remaining) = self.request_interval.checked_sub(last_request.elapsed())
        {
            thread::sleep(remaining);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_skill_urls_from_declared_sitemap_shapes() {
        let document = Url::parse("https://www.skills.sh/sitemap-skills-1.xml").unwrap();
        let detail = Url::parse("https://www.skills.sh/vercel-labs/skills/find-skills").unwrap();
        assert!(is_detail_url("skills-sh", &document, &detail));
        assert!(!is_detail_url(
            "skills-sh",
            &Url::parse("https://www.skills.sh/sitemap-misc.xml").unwrap(),
            &detail
        ));
        assert!(is_detail_url(
            "mcpservers-agent-skills",
            &Url::parse("https://mcpservers.org/sitemaps/skills.xml").unwrap(),
            &Url::parse("https://mcpservers.org/agent-skills/anthropic/frontend-design").unwrap()
        ));
    }

    #[test]
    fn prefers_a_skill_tree_over_catalog_repository_chrome() {
        let detail = Url::parse("https://lobehub.com/skills/anthropics-skills-pptx").unwrap();
        let body = br#"
            <a href="https://github.com/lobehub/lobehub">GitHub</a>
            <a href="https://github.com/anthropics/skills">Owner</a>
            <a href="https://github.com/anthropics/skills/tree/main/skills/pptx">Source</a>
        "#;
        let candidate = extract_candidate("lobehub-skills", &detail, body)
            .unwrap()
            .unwrap();
        assert_eq!(
            candidate.source,
            CatalogSource::GitHub(GitHubSource {
                repository_url: "https://github.com/anthropics/skills".to_owned(),
                requested_revision: Some("main".to_owned()),
                source_path: Some(PathBuf::from("skills/pptx")),
                repository_provenance_prefix: "github/anthropics/skills".to_owned(),
                provenance_prefix: "github/anthropics/skills/skills/pptx".to_owned(),
            })
        );
    }

    #[test]
    fn accepts_same_origin_skill_markdown() {
        let detail = Url::parse("https://skillregistry.io/skill/skill-finder").unwrap();
        let body = br#"<a href="/skills/skill-finder.md">Download Skill</a>"#;
        let candidate = extract_candidate("skillregistry", &detail, body)
            .unwrap()
            .unwrap();
        assert_eq!(
            candidate.source,
            CatalogSource::Markdown {
                markdown_url: "https://skillregistry.io/skills/skill-finder.md".to_owned()
            }
        );
    }

    #[test]
    fn rejects_cross_origin_markdown_handoffs() {
        let detail = Url::parse("https://skillregistry.io/skill/example").unwrap();
        let body = br#"<a href="https://attacker.example/SKILL.md">Download Skill</a>"#;
        assert!(
            extract_candidate("skillregistry", &detail, body)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn github_blob_handoff_scans_the_containing_directory() {
        let url = Url::parse(
            "https://github.com/openai/skills/blob/main/skills/.curated/openai-docs/SKILL.md",
        )
        .unwrap();
        let source = parse_github_source(&url).unwrap();
        assert_eq!(source.requested_revision.as_deref(), Some("main"));
        assert_eq!(
            source.source_path.as_deref(),
            Some(std::path::Path::new("skills/.curated/openai-docs"))
        );
    }
}
