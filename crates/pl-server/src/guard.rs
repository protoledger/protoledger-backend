//! Защита локального API (`plan/security.md` T16–T21, T24, ADR 0010): Host → Origin → токен сессии.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use pl_core::ProblemKind;

use crate::{ApiError, AppState};

pub const TOKEN_HEADER: &str = "x-protoledger-token";
const ALLOWED_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];
const CSP: &str = "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'";

/// Токен сессии и дополнительные разрешённые origin (dev-режим).
#[derive(Clone)]
pub struct Guard {
    token: Arc<str>,
    extra_origins: Arc<[String]>,
}

impl Guard {
    /// Новый токен: 256 бит из системного CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        // Без случайности безопасный токен невозможен, поэтому запуск прерываем.
        getrandom::fill(&mut bytes).expect("системный генератор случайных чисел недоступен");
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self::with_token(token, Vec::new())
    }

    /// Заданный токен — только для dev-режима и тестов.
    pub fn with_token(token: String, extra_origins: Vec<String>) -> Self {
        Self {
            token: token.into(),
            extra_origins: extra_origins.into(),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    fn token_matches(&self, given: &[u8]) -> bool {
        // Сравнение за постоянное время: токен не должен подбираться по задержке.
        let expected = self.token.as_bytes();
        let mut diff = expected.len() ^ given.len();
        for (i, byte) in expected.iter().enumerate() {
            diff |= usize::from(byte ^ given.get(i).copied().unwrap_or(0));
        }
        diff == 0
    }
}

fn forbidden(detail: &'static str) -> ApiError {
    ApiError::new(ProblemKind::Forbidden, detail)
}

/// `Host` без порта должен быть loopback; порт не сверяем (Docker публикует другой порт).
fn host_allowed(headers: &HeaderMap) -> Option<&str> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let name = if host.starts_with('[') {
        let end = host.find(']')?;
        let rest = host.get(end + 1..)?;
        if !(rest.is_empty() || rest.strip_prefix(':').is_some_and(valid_port)) {
            return None;
        }
        host.get(..=end)?
    } else {
        match host.rsplit_once(':') {
            Some((name, port)) if valid_port(port) => name,
            Some(_) => return None,
            None => host,
        }
    };
    let name = name.to_ascii_lowercase();
    ALLOWED_HOSTS.contains(&name.as_str()).then_some(host)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())
}

fn origin_allowed(guard: &Guard, headers: &HeaderMap, host: &str) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    if guard.extra_origins.iter().any(|o| o == origin) {
        return true;
    }
    // Свой origin — тот же адрес, по которому открыт движок.
    origin
        .strip_prefix("http://")
        .is_some_and(|authority| authority.eq_ignore_ascii_case(host))
}

fn needs_token(path: &str) -> bool {
    let is_api = path == "/api" || path.starts_with("/api/");
    let exempt = path == "/api/health" || path == "/api/docs" || path.starts_with("/api/docs/");
    is_api && !exempt
}

/// Проверки запроса и защитные заголовки ответа (в том числе у отказов).
pub async fn enforce(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = match check(&state.guard, &request) {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    harden(&mut response, &path);
    response
}

fn check(guard: &Guard, request: &Request) -> Result<(), ApiError> {
    let headers = request.headers();
    let Some(host) = host_allowed(headers) else {
        return Err(forbidden("Заголовок Host не совпадает с адресом движка."));
    };
    if !origin_allowed(guard, headers, host) {
        return Err(forbidden("Запросы с чужих сайтов запрещены."));
    }
    if needs_token(request.uri().path()) {
        let given = headers
            .get(TOKEN_HEADER)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        if !guard.token_matches(given) {
            return Err(ApiError::new(
                ProblemKind::Unauthorized,
                "Не передан или неверен заголовок X-Protoledger-Token.",
            ));
        }
    }
    Ok(())
}

fn harden(response: &mut Response, path: &str) {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // Swagger UI (только dev-сборка) использует встроенные скрипты и стили.
    let docs = path == "/api/docs" || path.starts_with("/api/docs/");
    if !docs {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        h
    }

    #[test]
    fn host_whitelist() {
        for ok in [
            "127.0.0.1:8080",
            "localhost:8080",
            "LOCALHOST:1",
            "[::1]:8080",
            "localhost",
            "[::1]",
        ] {
            assert!(host_allowed(&headers(ok)).is_some(), "{ok}");
        }
        for bad in [
            "evil.com",
            "evil.com:8080",
            "localhost.evil.com:8080",
            "127.0.0.1.evil.com",
            "localhost:abc",
            "localhost:",
            "[::1",
            "[::2]:8080",
            "0.0.0.0:8080",
            "",
        ] {
            assert!(host_allowed(&headers(bad)).is_none(), "{bad}");
        }
        assert!(host_allowed(&HeaderMap::new()).is_none());
    }

    #[test]
    fn token_comparison() {
        let guard = Guard::with_token("secret-token".to_owned(), vec![]);
        assert!(guard.token_matches(b"secret-token"));
        assert!(!guard.token_matches(b"secret-tokeN"));
        assert!(!guard.token_matches(b"secret-token-and-more"));
        assert!(!guard.token_matches(b""));
    }

    #[test]
    fn random_tokens_are_long_and_distinct() {
        let (a, b) = (Guard::random(), Guard::random());
        assert_eq!(a.token().len(), 64);
        assert_ne!(a.token(), b.token());
    }

    #[test]
    fn token_scope() {
        assert!(needs_token("/api/sources"));
        assert!(needs_token("/api/nope"));
        assert!(!needs_token("/api/health"));
        assert!(!needs_token("/api/docs/"));
        assert!(!needs_token("/"));
        assert!(!needs_token("/explore"));
    }
}
