use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};

use crate::ClientError;

pub struct TransportRequest {
    pub method: Method,
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub struct TransportResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait ApiTransport: Send + Sync {
    async fn execute(&self, request: TransportRequest) -> Result<TransportResponse, ClientError>;
}
