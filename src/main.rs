//
// rlpcli
// Copyright (C) 2021-2025 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

use clap::{command, Arg, ArgAction};
use env_logger::{Builder, Env};
use lesspass::{Algorithm, CharacterSet, generate_entropy, generate_salt, render_password};
use log::{debug, info, trace, warn, LevelFilter};
use serde::{Deserialize, Deserializer, Serialize};
use std::{env, cell::OnceCell, fs, path};
use ureq::Agent;
use url::Url;
use xdg::BaseDirectories;

const APP_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Serialize, Debug)]
struct Auth {
    email: String,
    password: String
}

#[derive(Serialize, Debug)]
struct Refresh {
    refresh: String
}

#[derive(Deserialize, Debug)]
struct Token {
    access: String,
    refresh: String
}

#[derive(Deserialize, Debug)]
pub struct Sites {
    pub results: Vec<Site>
}

#[derive(Deserialize, Eq, Ord, PartialEq, PartialOrd, Debug)]
pub struct Site {
    #[serde(deserialize_with = "id_deserializer")]
    pub id: String,
    pub site: String,
    pub login: String,
    pub lowercase: bool,
    pub uppercase: bool,
    pub symbols: bool,
    #[serde(flatten, deserialize_with = "digits_deserializer")]
    pub digits: bool,
    pub length: u8,
    pub counter: u32
}

/// Some server implementations (like Rockpass) store IDs in simple integers instead of strings,
/// this function deserializes unsigned integers or strings.
fn id_deserializer<'de, D>(deserializer: D) -> Result<String, D::Error> where D: Deserializer<'de>, {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInteger {
        String(String),
        Integer(u64)
    }
    match StringOrInteger::deserialize(deserializer)? {
        StringOrInteger::String(string) => Ok(string),
        StringOrInteger::Integer(integer) => Ok(integer.to_string())
    }
}

/// The numbers field is deprecated and has been replaced by digits, this function checks if what
/// arrives is digits or numbers and, if both, the value of digits is used.
fn digits_deserializer<'de, D>(deserializer: D) -> Result<bool, D::Error> where D: Deserializer<'de>, {
    #[derive(Deserialize)]
    struct DigitsOrNumbers {
        digits: Option<bool>,
        numbers: Option<bool>
    }
    let DigitsOrNumbers {digits, numbers} = DigitsOrNumbers::deserialize(deserializer)?;
    digits.or(numbers).ok_or(serde::de::Error::missing_field("digits or numbers"))
}

struct LessPassClient {
    host: Url,
    auth: Option<Auth>,
    token: OnceCell<Token>,
    agent: Agent
}

impl LessPassClient {
    /// Configure the client itself
    fn new(host: Url, user: Option<String>, pass: Option<String>) -> LessPassClient {
        LessPassClient {
            host,
            auth: if let (Some(email), Some(password)) = (user, pass) {
                Some(Auth {email, password})
            } else {
                None
            },
            token: OnceCell::new(),
            agent: Agent::new()
        }
    }

    /// Perform authentication
    fn auth(&self) -> Result<(), String> {
        // Try to get token form cache file
        let token_cache_file = match BaseDirectories::with_prefix(APP_NAME) {
            Ok(base_directories) => {
                match base_directories.place_cache_file(format!("{}.token", self.host.host_str().unwrap_or_else(|| self.host.as_str()).replace('/', ""))) {
                    Ok(token_cache_file) => {
                        info!("Using cache file {} for read and store token", token_cache_file.as_path().display());
                        token_cache_file
                    },
                    Err(e) => {
                        warn!("There is a problem accessing to cache file caused by {}, disabling cache", e);
                        path::PathBuf::new()
                    }
                }
            },
            Err(e) => {
                warn!("There is a problem getting base directories caused by {}, disabling cache", e);
                path::PathBuf::new()
            }
        };
        let token = if token_cache_file == path::PathBuf::new() {
            String::new()
        } else {
            fs::read_to_string(token_cache_file.as_path()).unwrap_or(String::new())
        };
        trace!("Current token '{}'", token);
        // Try refresh token
        let refreshed_token = match self.refresh_token(&token) {
            Ok(refreshed_token) => refreshed_token,
            Err(_) => {
                // Token cannot be refreshed we need to obtain a new one
                warn!("The stored token has expired or is invalid, it is necessary to re-authenticate with username and password");
                self.get_token()?
            }
        };
        trace!("Access token '{}'", refreshed_token.access);
        trace!("Refresh token '{}'", refreshed_token.refresh);
        // Save the new refresh token
        if token_cache_file != path::PathBuf::new() {
            match fs::write(token_cache_file.as_path(), &refreshed_token.refresh) {
                Ok(_) => debug!("Refreshed token stored successfully"),
                Err(e) => warn!("There is a problem storing refreshed token file caused by {}", e)
            }
        }
        // Stores the token in the client
        self.token.set(refreshed_token).map_err(|_| String::from("It is not possible to call this function more than once"))
    }

    /// Call to obtain a new access and refresh token using user and password
    fn get_token(&self) -> Result<Token, String> {
        // Safe to unwrap as host has been checked before
        let url = self.host.join("auth/jwt/create/").unwrap();
        match &self.auth {
            Some(auth) => {
                trace!("Using {} as LESSPASS_USER", auth.email);
                trace!("Using {} (value is masked) as LESSPASS_PASS", "*".repeat(auth.password.len()));
                match self.agent.post(url.as_str()).send_json(auth) {
                    Ok(response) => {
                        let token: Token = response.into_json().map_err(|e| format!("Unexpected response, {}", e))?;
                        info!("Token created successfully");
                        Ok(token)
                    },
                    Err(ureq::Error::Status(code, _)) => Err(format!("Error getting authorization token, unexpected status code {}", code)),
                    Err(_) => Err(format!("Error making request to {}", url))
                }
            },
            None => Err(String::from("You must set the environment variables LESSPASS_USER and LESSPASS_PASS"))
        }
    }

    /// Call to obtain a new access and refresh token using a refresh token
    fn refresh_token(&self, token: &str) -> Result<Token, String> {
        // If token is empty simply return an error
        if token.is_empty() || token == "\n" {
            debug!("Token file does not exists or is empty");
            return Err(String::from("Invalid token found"))
        }
        // Safe to unwrap as host has been checked before
        let url = self.host.join("auth/jwt/refresh/").unwrap();
        let refresh = Refresh {
            refresh: String::from(token)
        };
        match self.agent.post(url.as_str()).send_json(refresh) {
            Ok(response) => {
                let token: Token = response.into_json().map_err(|e| format!("Unexpected response, {}", e))?;
                info!("Token refreshed successfully");
                Ok(token)
            },
            Err(ureq::Error::Status(code, _)) => Err(format!("Error getting authorization token, unexpected status code {}", code)),
            Err(_) => Err(format!("Error making request to {}", url))
        }
    }

    fn get_sites(&self) -> Result<Sites, String> {
        // Safe to unwrap as host has been checked before
        let url = self.host.join("passwords/").unwrap();
        let token = match self.token.get() {
            Some(token) => &token.access,
            None => return Err(String::from("A token must be obtained first"))
        };
        let authorization = format!("Bearer {}", token);
        match self.agent.get(url.as_str()).set("Authorization", &authorization).call() {
            Ok(response) => {
                let sites: Sites = response.into_json().map_err(|e| format!("Unexpected response, {}", e))?;
                info!("Site list obtained successfully");
                Ok(sites)
            },
            Err(ureq::Error::Status(code, _)) => Err(format!("Error getting authorization token, unexpected status code {}", code)),
            Err(_) => Err(format!("Error making request to {}", url))
        }
    }
}


fn format_site(site: &Site) -> String {
    format!("ID: {}\nSite: {}\nLogin: {}\nLowercase: {}\nUppercase: {}\nSymbols: {}\nDigits: {}\nLength: {}\nCouter: {}",
        site.id,
        site.site,
        site.login,
        site.lowercase,
        site.uppercase,
        site.symbols,
        site.digits,
        site.length,
        site.counter)
}

fn get_password(master_password: &str, site: &Site) -> Result<String, String> {
    trace!("Using {} (value is masked) as LESSPASS_MASTERPASS", "*".repeat(master_password.len()));
    let mut charset = CharacterSet::All;
    if ! site.lowercase {
        debug!("Lowercase characters excluded");
        charset.remove(CharacterSet::Lowercase);
    }
    if ! site.uppercase {
        debug!("Uppercase characters excluded");
        charset.remove(CharacterSet::Uppercase);
    }
    if ! site.symbols {
        debug!("Symbol characters excluded");
        charset.remove(CharacterSet::Symbols);
    }
    if ! site.digits {
        debug!("Numeric characters excluded");
        charset.remove(CharacterSet::Numbers);
    }
    if charset.is_empty() {
        return Err(String::from("There is a problem with site settings, all characters have been excluded"))
    }
    let salt = generate_salt(&site.site, &site.login, site.counter);
    let entropy = generate_entropy(master_password, &salt, Algorithm::SHA256, 100000);
    let password = render_password(&entropy, charset, site.length.into());
    info!("Returning site password");
    Ok(password)
}

fn main() -> Result<(), String> {
    let matches = command!()
        .arg(Arg::new("site")
             .help("site to obtain password"))
        .arg(Arg::new("id")
             .short('i')
             .long("id")
             .help("Search or list by id instead of site")
             .action(ArgAction::SetTrue))
        .arg(Arg::new("login")
             .short('l')
             .long("login")
             .help("Print the site login instead of password")
             .action(ArgAction::SetTrue))
        .arg(Arg::new("settings")
             .short('s')
             .long("settings")
             .help("Print the site settings instead of password")
             .action(ArgAction::SetTrue))
        .arg(Arg::new("verbosity")
             .short('v')
             .long("verbose")
             .action(ArgAction::Count)
             .help("Sets the level of verbosity"))
        .get_matches();
    // Read mandatory environment variable HOST
    let host = Url::parse(&env::var("LESSPASS_HOST")
        .map_err(|_| String::from("You must configure LESSPASS_HOST environment variable"))?)
        .map_err(|e| format!("LESSPASS_HOST is not a valid URL, {}", e))?;
    // Configure loglevel
    match matches.get_count("verbosity") {
        0 => Builder::from_env(Env::default().filter_or(format!("{}_LOGLEVEL", APP_NAME.to_uppercase()), "off")).init(),
        1 => Builder::new().filter_level(LevelFilter::Info).init(),
        2 => Builder::new().filter_level(LevelFilter::Debug).init(),
        _ => Builder::new().filter_level(LevelFilter::Trace).init()
    };
    info!("Log level {:?}", log::max_level());
    debug!("Using {} as LESSPASS_HOST", host);
    // Get user and pass
    let user = env::var("LESSPASS_USER").ok();
    let pass = env::var("LESSPASS_PASS").ok();
    // Configure client
    let lesspass_client = LessPassClient::new(host, user, pass);
    // Perform auth
    lesspass_client.auth()?;
    // Get the site list
    let mut sites = lesspass_client.get_sites()?;
    // Return site list or site
    match matches.get_one::<String>("site") {
        Some(site) => {
            debug!("Looking for site {}", site);
            // Check if the requested password is an id or a site
            let password = if matches.get_flag("id") {
                trace!("Searching by ID");
                sites.results.iter().find(|&s| s.id == *site)
            } else {
                trace!("Searching by name");
                sites.results.iter().find(|&s| s.site == *site)
            };
            match password {
                Some(password) => {
                    debug!("Site found");
                    if matches.get_flag("login") {
                        // User wants site login
                        info!("Returning site login");
                        println!("{}", password.login);
                    } else if matches.get_flag("settings") {
                        // User wants site settings
                        info!("Returning site settings");
                        println!("{}", format_site(password));
                    } else {
                        // Try to get master password from environ
                        match env::var("LESSPASS_MASTERPASS") {
                            // Master password suplied, print site password
                            Ok(var) => println!("{}", get_password(&var, password)?),
                            // Master password not suplied, print all site settings
                            Err(_) => {
                                info!("Master password not suplied, returning site settings");
                                println!("{}", format_site(password));
                            }
                        }
                    }
                },
                None => println!("Site '{}' not found in site list", site)
            }
        },
        None => {
            info!("Returning site list");
            if matches.get_flag("id") {
                sites.results.sort();
                for site in sites.results.iter() {
                    println!("{}: {}", site.id, site.site);
                }
            } else {
                sites.results.sort_by_key(|k| k.site.clone());
                for site in sites.results.iter() {
                    println!("{}", site.site);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AH: (&str, &str) = ("authorization", "Bearer access_token");
    const JH: (&str, &str) = ("content-type", "application/json");

    #[test]
    fn get_token() {
        let mut server = mockito::Server::new();
        let url = Url::parse(&server.url()).unwrap();
        let client = LessPassClient::new(url, Some("user".to_string()), Some("pass".to_string()));
        let request_body = r#"{"email":"user","password":"pass"}"#;
        let response_body = r#"{"access":"access_token","refresh":"refresh_token"}"#;
        let mock = server.mock("POST", "/auth/jwt/create/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_body(mockito::Matcher::JsonString(request_body.to_string()))
            .with_body(response_body)
            .create();
        let token = client.get_token().unwrap();
        assert_eq!("access_token", token.access);
        assert_eq!("refresh_token", token.refresh);
        mock.assert();
        let response_body = "{}";
        let mock = server.mock("POST", "/auth/jwt/create/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_body(mockito::Matcher::JsonString(request_body.to_string()))
            .with_body(response_body)
            .create();
        let token = client.get_token();
        assert!(token.is_err());
        mock.assert();
    }

    #[test]
    fn refresh_token() {
        let mut server = mockito::Server::new();
        let url = Url::parse(&server.url()).unwrap();
        let client = LessPassClient::new(url, Some("user".to_string()), Some("pass".to_string()));
        let request_body = r#"{"refresh":"sometoken"}"#;
        let response_body = r#"{"access":"access_token","refresh":"refresh_token"}"#;
        let mock = server.mock("POST", "/auth/jwt/refresh/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_body(mockito::Matcher::JsonString(request_body.to_string()))
            .with_body(response_body)
            .create();
        let token = client.refresh_token("sometoken").unwrap();
        assert_eq!("access_token", token.access);
        assert_eq!("refresh_token", token.refresh);
        mock.assert();
        let request_body = r#"{"refresh":"badtoken"}"#;
        let response_body = "{}";
        let mock = server.mock("POST", "/auth/jwt/refresh/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_body(mockito::Matcher::JsonString(request_body.to_string()))
            .with_body(response_body)
            .create();
        let token = client.refresh_token("badtoken");
        assert!(token.is_err());
        mock.assert();
    }

    #[test]
    fn get_sites() {
        let mut server = mockito::Server::new();
        let url = Url::parse(&server.url()).unwrap();
        let client = LessPassClient::new(url, None, None);
        client.token.set(Token {
            access: "access_token".to_string(),
            refresh: "refresh_token".to_string()
        }).unwrap();
        let response_body = r#"{"results":[{"id":"1","site":"site","login":"login","lowercase":true,"uppercase":true,"symbols":true,"digits":false,"length":20,"counter":1},
        {"id":2,"site":"othersite","login":"otherlogin","lowercase":false,"uppercase":false,"symbols":false,"numbers":true,"length":30,"counter":10},
        {"id":"double-one","site":"doubleone","login":"doubleonelogin","lowercase":false,"uppercase":false,"symbols":false,"digits":false,"numbers":true,"length":8,"counter":2},
        {"id":4,"site":"doubletwo","login":"doubletwologin","lowercase":false,"uppercase":false,"symbols":false,"digits":true,"numbers":false,"length":16,"counter":5}]}"#;
        let mock = server.mock("GET", "/passwords/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_header(AH.0, AH.1)
            .with_body(response_body)
            .create();
        let sites = client.get_sites().unwrap();
        assert_eq!("1".to_string(), sites.results[0].id);
        assert_eq!("2".to_string(), sites.results[1].id);
        assert_eq!("site".to_string(), sites.results[0].site);
        assert_eq!("othersite".to_string(), sites.results[1].site);
        assert_eq!("login".to_string(), sites.results[0].login);
        assert_eq!("otherlogin".to_string(), sites.results[1].login);
        assert!(sites.results[0].lowercase);
        assert!(sites.results[0].uppercase);
        assert!(sites.results[0].symbols);
        assert!(sites.results[1].digits);
        assert!(!sites.results[2].digits);
        assert!(sites.results[3].digits);
        assert_eq!(20, sites.results[0].length);
        assert_eq!(30, sites.results[1].length);
        assert_eq!(1, sites.results[0].counter);
        assert_eq!(10, sites.results[1].counter);
        mock.assert();
        let response_body = "{}";
        let mock = server.mock("GET", "/passwords/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .with_body(response_body)
            .create();
        let sites = client.get_sites();
        assert!(sites.is_err());
        mock.assert();
    }

    #[test]
    fn fmt_site() {
        let site = Site {
            id: "uuid".to_string(),
            site: "site".to_string(),
            login: "login".to_string(),
            lowercase: true,
            uppercase: true,
            symbols: false,
            digits: true,
            length: 254,
            counter: 12345
        };
        let fmt_site = format_site(&site);
        assert_eq!("ID: uuid\nSite: site\nLogin: login\nLowercase: true\nUppercase: true\nSymbols: false\nDigits: true\nLength: 254\nCouter: 12345".to_string(), fmt_site);
    }

    #[test]
    fn get_passwd() {
        let site = Site {
            id: "uuid".to_string(),
            site: "site".to_string(),
            login: "login".to_string(),
            lowercase: true,
            uppercase: true,
            symbols: false,
            digits: true,
            length: 25,
            counter: 12345
        };
        let password = get_password("masterpass", &site).unwrap();
        assert_eq!("m8odYG7Vb75Ck7xQV5kDQtIzp", password);
        let site = Site {
            id: "uuid".to_string(),
            site: "site".to_string(),
            login: "login".to_string(),
            lowercase: true,
            uppercase: true,
            symbols: true,
            digits: true,
            length: 20,
            counter: 2
        };
        let password = get_password("masterpass", &site).unwrap();
        assert_eq!("(Q8FWP=[q3kGj_T<;p4I", password);
        let site = Site {
            id: "uuid".to_string(),
            site: "site".to_string(),
            login: "login".to_string(),
            lowercase: false,
            uppercase: false,
            symbols: false,
            digits: false,
            length: 25,
            counter: 12345
        };
        let password = get_password("masterpass", &site);
        assert!(password.is_err());
    }
}
