use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub provider: String,
    pub query: String,
    pub url: String,
    pub title: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Default)]
pub struct WebSearchConfig {
    pub google_api_key: Option<String>,
    pub google_cx: Option<String>,
    pub brave_api_key: Option<String>,
    pub bing_api_key: Option<String>,
    pub exa_api_key: Option<String>,
    pub gitlab_token: Option<String>,
    pub max_pages: usize,
}

impl WebSearchConfig {
    pub fn from_env() -> Self {
        Self {
            google_api_key: non_empty_env("GOOGLE_API_KEY"),
            google_cx: non_empty_env("GOOGLE_CSE_ID"),
            brave_api_key: non_empty_env("BRAVE_API_KEY"),
            bing_api_key: non_empty_env("BING_SEARCH_API_KEY"),
            exa_api_key: non_empty_env("EXA_API_KEY"),
            gitlab_token: non_empty_env("GITLAB_TOKEN"),
            max_pages: std::env::var("WEB_SEARCH_PAGES")
                .ok()
                .and_then(|value| value.parse().ok())
                .filter(|pages| *pages > 0)
                .map(|pages: usize| pages.min(10))
                .unwrap_or(1),
        }
    }

    pub fn backend_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.google_api_key.is_some() && self.google_cx.is_some() {
            names.push("google");
        }
        if self.brave_api_key.is_some() {
            names.push("brave");
        }
        if self.bing_api_key.is_some() {
            names.push("bing");
        }
        if self.exa_api_key.is_some() {
            names.push("exa");
        }
        if self.gitlab_token.is_some() {
            names.push("gitlab");
        }
        names
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub async fn search_dorks(
    client: &Client,
    queries: &[String],
    config: &WebSearchConfig,
) -> Result<Vec<SearchHit>> {
    if config.backend_names().is_empty() {
        bail!(
            "no web-search backend configured; set BRAVE_API_KEY, GOOGLE_API_KEY + GOOGLE_CSE_ID, BING_SEARCH_API_KEY, EXA_API_KEY, or GITLAB_TOKEN"
        );
    }

    let batches: Vec<Result<Vec<SearchHit>>> = stream::iter(queries.iter().cloned())
        .map(|query| {
            let client = client.clone();
            let config = config.clone();
            async move { search_one_dork(&client, &query, &config).await }
        })
        .buffer_unordered(2)
        .collect()
        .await;

    let mut hits = Vec::new();
    for batch in batches {
        hits.extend(batch?);
    }
    Ok(dedupe_hits(hits))
}

async fn search_one_dork(
    client: &Client,
    query: &str,
    config: &WebSearchConfig,
) -> Result<Vec<SearchHit>> {
    let mut hits = Vec::new();
    if config.google_api_key.is_some() && config.google_cx.is_some() {
        for page in 0..config.max_pages {
            hits.extend(search_google(client, query, config, page).await?);
        }
    }
    if config.brave_api_key.is_some() {
        for page in 0..config.max_pages.min(10) {
            hits.extend(search_brave(client, query, config, page).await?);
        }
    }
    if config.bing_api_key.is_some() {
        for page in 0..config.max_pages {
            hits.extend(search_bing(client, query, config, page).await?);
        }
    }
    if config.exa_api_key.is_some() {
        hits.extend(search_exa(client, query, config).await?);
    }
    if config.gitlab_token.is_some() {
        for page in 0..config.max_pages {
            hits.extend(search_gitlab(client, query, config, page).await?);
        }
    }
    Ok(hits)
}

async fn search_google(
    client: &Client,
    query: &str,
    config: &WebSearchConfig,
    page: usize,
) -> Result<Vec<SearchHit>> {
    let response = client
        .get("https://www.googleapis.com/customsearch/v1")
        .query(&[
            ("key", config.google_api_key.as_deref().unwrap_or_default()),
            ("cx", config.google_cx.as_deref().unwrap_or_default()),
            ("q", query),
            ("num", "10"),
            ("start", &(page * 10 + 1).to_string()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(parse_google_hits(query, &response))
}

async fn search_brave(
    client: &Client,
    query: &str,
    config: &WebSearchConfig,
    page: usize,
) -> Result<Vec<SearchHit>> {
    let response = client
        .get("https://api.search.brave.com/res/v1/web/search")
        .header(
            "X-Subscription-Token",
            config.brave_api_key.as_deref().unwrap_or_default(),
        )
        .query(&[
            ("q", query),
            ("count", "20"),
            ("offset", &(page * 20).to_string()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(parse_brave_hits(query, &response))
}

async fn search_bing(
    client: &Client,
    query: &str,
    config: &WebSearchConfig,
    page: usize,
) -> Result<Vec<SearchHit>> {
    let response = client
        .get("https://api.bing.microsoft.com/v7.0/search")
        .header(
            "Ocp-Apim-Subscription-Key",
            config.bing_api_key.as_deref().unwrap_or_default(),
        )
        .query(&[
            ("q", query),
            ("count", "50"),
            ("offset", &(page * 50).to_string()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(parse_bing_hits(query, &response))
}

async fn search_exa(
    client: &Client,
    query: &str,
    config: &WebSearchConfig,
) -> Result<Vec<SearchHit>> {
    let response = client
        .post("https://api.exa.ai/search")
        .header(
            "x-api-key",
            config.exa_api_key.as_deref().unwrap_or_default(),
        )
        .json(&serde_json::json!({
            "query": query,
            "numResults": 20,
            "contents": {"highlights": true},
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(parse_exa_hits(query, &response))
}

async fn search_gitlab(
    client: &Client,
    query: &str,
    config: &WebSearchConfig,
    page: usize,
) -> Result<Vec<SearchHit>> {
    let gitlab_query = query
        .replace("site:gitlab.com", "")
        .replace("filetype:", "extension:");
    let response = client
        .get("https://gitlab.com/api/v4/search")
        .header(
            "PRIVATE-TOKEN",
            config.gitlab_token.as_deref().unwrap_or_default(),
        )
        .query(&[
            ("scope", "blobs"),
            ("search", gitlab_query.as_str()),
            ("page", &(page + 1).to_string()),
            ("per_page", "100"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(parse_gitlab_hits(query, &response))
}

fn parse_google_hits(query: &str, body: &Value) -> Vec<SearchHit> {
    body.get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some(SearchHit {
                provider: "google".into(),
                query: query.into(),
                url: item.get("link")?.as_str()?.into(),
                title: item
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                snippet: item
                    .get("snippet")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
            })
        })
        .collect()
}

fn parse_brave_hits(query: &str, body: &Value) -> Vec<SearchHit> {
    body.pointer("/web/results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some(SearchHit {
                provider: "brave".into(),
                query: query.into(),
                url: item.get("url")?.as_str()?.into(),
                title: item
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                snippet: item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
            })
        })
        .collect()
}

fn parse_bing_hits(query: &str, body: &Value) -> Vec<SearchHit> {
    body.pointer("/webPages/value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some(SearchHit {
                provider: "bing".into(),
                query: query.into(),
                url: item.get("url")?.as_str()?.into(),
                title: item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                snippet: item
                    .get("snippet")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
            })
        })
        .collect()
}

fn parse_exa_hits(query: &str, body: &Value) -> Vec<SearchHit> {
    body.get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let snippet = item
                .get("highlights")
                .and_then(Value::as_array)
                .map(|highlights| {
                    highlights
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .filter(|snippet| !snippet.is_empty())
                .or_else(|| item.get("text").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_default();
            Some(SearchHit {
                provider: "exa".into(),
                query: query.into(),
                url: item.get("url")?.as_str()?.into(),
                title: item
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                snippet,
            })
        })
        .collect()
}

fn parse_gitlab_hits(query: &str, body: &Value) -> Vec<SearchHit> {
    body.as_array()
        .into_iter()
        .flatten()
        .map(|item| {
            let path = item
                .get("path")
                .or_else(|| item.get("filename"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let project_id = item
                .get("project_id")
                .and_then(Value::as_i64)
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".into());
            SearchHit {
                provider: "gitlab".into(),
                query: query.into(),
                url: item
                    .get("web_url")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("https://gitlab.com/search?search={path}")),
                title: format!("GitLab project {project_id} / {path}"),
                snippet: item
                    .get("data")
                    .or_else(|| item.get("content"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
            }
        })
        .collect()
}

fn dedupe_hits(hits: Vec<SearchHit>) -> Vec<SearchHit> {
    let mut seen = HashSet::new();
    hits.into_iter()
        .filter(|hit| seen.insert(format!("{}\n{}\n{}", hit.provider, hit.url, hit.snippet)))
        .collect()
}

pub async fn discover_subdomains(client: &Client, domain: &str) -> Result<Vec<String>> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || !domain.contains('.') || domain.contains('/') {
        bail!("domain must be a hostname such as example.com");
    }

    let body = client
        .get("https://crt.sh/")
        .query(&[("q", format!("%.{domain}")), ("output", "json".into())])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await
        .context("crt.sh returned invalid JSON")?;

    let names = parse_crtsh_names(&body, &domain);

    Ok(names)
}

fn parse_crtsh_names(body: &Value, domain: &str) -> Vec<String> {
    let mut names = HashSet::new();
    for name in body
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("name_value").and_then(Value::as_str))
        .flat_map(str::lines)
    {
        let name = name.trim().trim_start_matches("*.").to_ascii_lowercase();
        if name == domain || name.ends_with(&format!(".{domain}")) {
            names.insert(name);
        }
    }

    let mut names: Vec<_> = names.into_iter().collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_web_provider_shapes() {
        let google = parse_google_hits(
            "q",
            &json!({"items": [{"link": "https://gist.github.com/x", "title": "t", "snippet": "s"}]}),
        );
        assert_eq!(google[0].provider, "google");

        let brave = parse_brave_hits(
            "q",
            &json!({"web": {"results": [{"url": "https://gitlab.com/x", "title": "t", "description": "s"}]}}),
        );
        assert_eq!(brave[0].url, "https://gitlab.com/x");

        let bing = parse_bing_hits(
            "q",
            &json!({"webPages": {"value": [{"url": "https://sourcegraph.com/x", "name": "t", "snippet": "s"}]}}),
        );
        assert_eq!(bing[0].provider, "bing");
    }

    #[test]
    fn parses_exa_highlights_and_text() {
        let hits = parse_exa_hits(
            "q",
            &json!({
                "results": [
                    {
                        "url": "https://example.com/highlighted",
                        "title": "t",
                        "highlights": ["h1", "h2"],
                        "text": "fallback"
                    },
                    {
                        "url": "https://example.com/text",
                        "text": "body"
                    },
                    {"url": 42},
                    {"title": "missing url"}
                ]
            }),
        );
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].provider, "exa");
        assert_eq!(hits[0].snippet, "h1\nh2");
        assert_eq!(hits[1].snippet, "body");
        assert!(parse_exa_hits("q", &json!({"results": {}})).is_empty());
    }

    #[test]
    fn detects_exa_backend_from_config() {
        let config = WebSearchConfig {
            exa_api_key: Some("exa-key".into()),
            ..Default::default()
        };
        assert_eq!(config.backend_names(), vec!["exa"]);
    }

    #[test]
    fn parses_and_deduplicates_subdomains() {
        let body = json!([
            {"name_value": "*.Example.com\napi.example.com"},
            {"name_value": "API.EXAMPLE.COM\nadmin.example.com"}
        ]);
        let names = parse_crtsh_names(&body, "example.com");
        assert_eq!(
            names,
            ["admin.example.com", "api.example.com", "example.com"]
        );
    }
}
