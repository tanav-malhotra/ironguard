use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug)]
pub enum ProviderKind {
    OpenAI,
    Anthropic,
    OpenRouter,
    Ollama,
    GoogleGemini,
}

impl ProviderKind {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "openai" => Self::OpenAI,
            "anthropic" => Self::Anthropic,
            "openrouter" => Self::OpenRouter,
            "ollama" => Self::Ollama,
            "google" | "gemini" => Self::GoogleGemini,
            _ => Self::OpenAI,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AiConfig {
    pub provider: ProviderKind,
    pub model: String,
    pub api_key: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AiResponse {
    pub text: String,
}

#[async_trait::async_trait]
pub trait AiProvider: Send + Sync {
    async fn complete(&self, system: &str, user: &str) -> Result<AiResponse>;
}

pub struct GeminiProvider {
    client: reqwest::Client,
    model: String,
    api_key: String,
}

impl GeminiProvider {
    pub fn new(model: String, api_key: Option<String>) -> Result<Self> {
        let key = api_key
            .or_else(|| std::env::var("GEMINI_API_KEY").ok())
            .ok_or_else(|| anyhow!("Missing Gemini API key (set --api-key or GEMINI_API_KEY)"))?;
        Ok(Self { client: reqwest::Client::new(), model, api_key: key })
    }
}

#[derive(Serialize)]
struct GeminiRequest<'a> {
    contents: Vec<GeminiContent<'a>>,
}

#[derive(Serialize)]
struct GeminiContent<'a> {
    role: &'a str,
    parts: Vec<GeminiPart<'a>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum GeminiPart<'a> { Text { text: &'a str } }

#[derive(Deserialize)]
struct GeminiResponseRoot {
    candidates: Option<Vec<GeminiCandidate>>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    content: Option<GeminiCandidateContent>,
}

#[derive(Deserialize)]
struct GeminiCandidateContent {
    parts: Option<Vec<GeminiCandidatePart>>, 
}

#[derive(Deserialize)]
struct GeminiCandidatePart { text: Option<String> }

impl fmt::Debug for GeminiResponseRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeminiResponseRoot").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AiProvider for GeminiProvider {
    async fn complete(&self, system: &str, user: &str) -> Result<AiResponse> {
        let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.api_key);
        let body = GeminiRequest {
            contents: vec![
                GeminiContent { role: "user", parts: vec![GeminiPart::Text{ text: system }]},
                GeminiContent { role: "user", parts: vec![GeminiPart::Text{ text: user }]},
            ]
        };
        let res = self.client.post(&url).json(&body).send().await.context("gemini request")?;
        let status = res.status();
        let json: GeminiResponseRoot = res.json().await.context("gemini response json")?;
        if !status.is_success() { return Err(anyhow!("gemini error status={} body={:?}", status, json)); }
        let text = json.candidates
            .and_then(|mut c| c.pop())
            .and_then(|c| c.content)
            .and_then(|c| c.parts)
            .and_then(|mut p| p.pop())
            .and_then(|p| p.text)
            .unwrap_or_default();
        Ok(AiResponse { text })
    }
}


