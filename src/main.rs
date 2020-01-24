use hyper::{body::to_bytes, client::HttpConnector, Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
use openssl::base64;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::collections::BTreeMap;
use std::fs;
use std::time;
use url::Url;

const OAUTH_HEADER_PREFIX: &str = "OAuth ";
const OAUTH_CONSUMER_KEY: &str = "oauth_consumer_key";
const OAUTH_NONCE: &str = "oauth_nonce";
const OAUTH_SIGNATURE_METHOD: &str = "oauth_signature_method";
const OAUTH_TIMESTAMP: &str = "oauth_timestamp";
const OAUTH_SIGNATURE: &str = "oauth_signature";
const OAUTH_TOKEN: &str = "oauth_token";
const OAUTH_VERSION: &str = "oauth_version";
const OAUTH_CALLBACK: &str = "oauth_callback";
const OAUTH_VERIFIER: &str = "oauth_verifier";
const OAUTH_1: &str = "1.0";

const EQUALS: char = '=';
const COMMA: char = ',';
const QUOTE: char = '"';
const AMPERSAND: char = '&';

const SIG_METHOD: &str = "RSA-SHA1";
const CONSUMER_KEY: &str = "SomeKey";

const FRAGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'.').remove(b'-').remove(b'_');
type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T> = std::result::Result<T, Error>;

#[tokio::main]
async fn main() -> Result<()> {
    let private_key = fs::read("./private_key.pem").unwrap();
    get_request_token(&private_key).await?;
    get_access_token(&private_key, "oauth_token", "oauth_verifier").await?;

    make_oauth_request(&private_key, "oauth_token").await?;
    make_oauth_request_post(&private_key, "oauth_token").await?;
    Ok(())
}

fn init_client() -> Client<HttpsConnector<HttpConnector>> {
    let https = HttpsConnector::new();
    Client::builder().build::<_, Body>(https)
}

fn get_timestamp() -> u64 {
    time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get_nonce() -> String {
    let nonce: String = thread_rng().sample_iter(Alphanumeric).take(8).collect();
    nonce
}

fn encode(input: &str) -> String {
    percent_encode(input.as_bytes(), FRAGMENT).to_string()
}

fn sign(private_key: &[u8], input: &str) -> String {
    let key = PKey::private_key_from_pem(&private_key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha1(), &key).unwrap();
    signer.update(input.as_bytes()).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    base64::encode_block(&signature)
}

async fn make_request_header(
    method: Method,
    url: &str,
    req_body: Body,
    oauth_header: &str,
) -> String {
    let client = init_client();
    let req = Request::builder()
        .method(method)
        .uri(url)
        .header("content-type", "application/json")
        .header("Authorization", oauth_header)
        .body(req_body)
        .unwrap();
    let res = client.request(req).await.unwrap();
    let body = to_bytes(res.into_body()).await.unwrap();
    std::str::from_utf8(&body).unwrap().to_owned()
}

fn create_header_params(params: &BTreeMap<String, String>) -> String {
    let mut header = String::from(OAUTH_HEADER_PREFIX);
    for (key, value) in params.iter() {
        if *key != OAUTH_SIGNATURE {
            header.push_str(key);
            header.push(EQUALS);
            header.push(QUOTE);
            header.push_str(&encode(value));
            header.push(QUOTE);
            header.push(COMMA);
        }
    }
    header.push_str(OAUTH_SIGNATURE);
    header.push(EQUALS);
    header.push(QUOTE);
    header.push_str(&encode(
        params
            .get(OAUTH_SIGNATURE)
            .expect("signature needs to be there"),
    ));
    header.push(QUOTE);
    header
}

fn create_params(params: &BTreeMap<String, String>) -> String {
    let mut res = String::new();
    for (i, (key, value)) in params.iter().enumerate() {
        res.push_str(key);
        res.push(EQUALS);
        res.push_str(&encode(value));
        if i < params.len() - 1 {
            res.push(AMPERSAND);
        }
    }
    res
}

fn url_without_query(mut url: Url) -> String {
    url.set_query(None);
    url.as_str().to_owned()
}

async fn make_oauth_request(private_key: &[u8], oauth_token: &str) -> Result<()> {
    let url = "https://some-jira.atlassian.net/rest/api/latest/search?jql=project+in+(10000)+order+by+key+asc&startAt=0&maxResults=100&fields=id,key,summary";

    let parsed_url = Url::parse(url).expect("url is valid");
    let query = parsed_url.query_pairs();
    let url_without = url_without_query(parsed_url.clone());

    let nonce = get_nonce();
    let timestamp = get_timestamp();

    let mut params = BTreeMap::new();
    params.insert(OAUTH_CONSUMER_KEY.to_owned(), CONSUMER_KEY.to_owned());
    params.insert(OAUTH_NONCE.to_owned(), nonce.clone());
    params.insert(OAUTH_VERSION.to_owned(), OAUTH_1.to_owned());
    params.insert(OAUTH_TIMESTAMP.to_owned(), timestamp.to_string());
    params.insert(OAUTH_SIGNATURE_METHOD.to_owned(), SIG_METHOD.to_owned());
    params.insert(OAUTH_TOKEN.to_owned(), oauth_token.to_owned());

    for (key, value) in query {
        params.insert(key.into_owned(), value.into_owned());
    }

    let parameters = create_params(&params);

    let encoded_url = encode(&url_without);
    let encoded_parameters = encode(&parameters);
    let combined = format!("GET&{}&{}", encoded_url, encoded_parameters);

    let b64 = sign(&private_key, &combined);

    for (key, _) in query {
        params.remove(key.as_ref());
    }

    params.insert(OAUTH_SIGNATURE.to_owned(), b64);

    let header = create_header_params(&params);

    let res = make_request_header(Method::GET, url, Body::empty(), &header).await;
    println!("{}", res);

    Ok(())
}

async fn make_oauth_request_post(private_key: &[u8], oauth_token: &str) -> Result<()> {
    let url = "https://some-jira.atlassian.net/rest/api/latest/project";
    let nonce = get_nonce();
    let timestamp = get_timestamp();

    let mut params = BTreeMap::new();
    params.insert(OAUTH_CONSUMER_KEY.to_owned(), CONSUMER_KEY.to_owned());
    params.insert(OAUTH_NONCE.to_owned(), nonce.clone());
    params.insert(OAUTH_VERSION.to_owned(), OAUTH_1.to_owned());
    params.insert(OAUTH_TIMESTAMP.to_owned(), timestamp.to_string());
    params.insert(OAUTH_SIGNATURE_METHOD.to_owned(), SIG_METHOD.to_owned());
    params.insert(OAUTH_TOKEN.to_owned(), oauth_token.to_owned());

    let parameters = create_params(&params);

    let encoded_url = encode(url);
    let encoded_parameters = encode(&parameters);
    let combined = format!("POST&{}&{}", encoded_url, encoded_parameters);

    let b64 = sign(&private_key, &combined);

    params.insert(OAUTH_SIGNATURE.to_owned(), b64);

    let header = create_header_params(&params);

    let body = r#"{"key": "TUTA", "name":"tutest22", "lead":"admin", "projectTypeKey":"software","description":"some cool stuff"}"#;

    let res = make_request_header(Method::POST, url, body.into(), &header).await;
    println!("{}", res);

    Ok(())
}

async fn get_request_token(private_key: &[u8]) -> Result<()> {
    let nonce = get_nonce();
    let timestamp = get_timestamp();

    let callback_url = "http://localhost:3000/cb";
    let url = "https://some-jira.atlassian.net/plugins/servlet/oauth/request-token";

    let mut params = BTreeMap::new();
    params.insert(OAUTH_CONSUMER_KEY.to_owned(), CONSUMER_KEY.to_owned());
    params.insert(OAUTH_NONCE.to_owned(), nonce.clone());
    params.insert(OAUTH_VERSION.to_owned(), OAUTH_1.to_owned());
    params.insert(OAUTH_TIMESTAMP.to_owned(), timestamp.to_string());
    params.insert(OAUTH_SIGNATURE_METHOD.to_owned(), SIG_METHOD.to_owned());
    params.insert(OAUTH_CALLBACK.to_owned(), callback_url.to_owned());

    let encoded_url = encode(url);
    let parameters = create_params(&params);
    let encoded_parameters = encode(&parameters);

    let combined = format!("POST&{}&{}", encoded_url, encoded_parameters);

    let b64 = sign(&private_key, &combined);

    params.insert(OAUTH_SIGNATURE.to_owned(), b64);

    let header = create_header_params(&params);

    let res = make_request_header(Method::POST, url, Body::empty(), &header).await;
    println!("{}", res);
    Ok(())
}

async fn get_access_token(
    private_key: &[u8],
    oauth_token: &str,
    oauth_verifier: &str,
) -> Result<()> {
    let nonce = get_nonce();
    let timestamp = get_timestamp();
    let url = "https://some-jira.atlassian.net/plugins/servlet/oauth/access-token";

    let mut params = BTreeMap::new();
    params.insert(OAUTH_CONSUMER_KEY.to_owned(), CONSUMER_KEY.to_owned());
    params.insert(OAUTH_NONCE.to_owned(), nonce.clone());
    params.insert(OAUTH_VERSION.to_owned(), OAUTH_1.to_owned());
    params.insert(OAUTH_TIMESTAMP.to_owned(), timestamp.to_string());
    params.insert(OAUTH_SIGNATURE_METHOD.to_owned(), SIG_METHOD.to_owned());
    params.insert(OAUTH_TOKEN.to_owned(), oauth_token.to_owned());
    params.insert(OAUTH_VERIFIER.to_owned(), oauth_verifier.to_owned());

    let encoded_url = encode(url);
    let parameters = create_params(&params);
    let encoded_parameters = encode(&parameters);
    let combined = format!("POST&{}&{}", encoded_url, encoded_parameters);

    let b64 = sign(&private_key, &combined);

    params.insert(OAUTH_SIGNATURE.to_owned(), b64);

    let header = create_header_params(&params);

    let res = make_request_header(Method::POST, url, Body::empty(), &header).await;
    println!("{}", res);
    Ok(())
}
