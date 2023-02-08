#[macro_use]
extern crate log;

use clap::{command, Arg, ArgAction};
use env_logger::Builder;
use lesspass::{Algorithm, CharacterSet, generate_entropy, generate_salt, render_password};
use log::LevelFilter;
use serde::{Deserialize, Deserializer, Serialize};
use ureq::Agent;
use url::Url;
use xdg::BaseDirectories;

use std::{env, fs, path, process};

const APP_NAME: &str = "rlpcli";

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
    pub numbers: bool,
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

fn print_site(site: &Site) {
    println!("ID: {}", site.id);
    println!("Site: {}", site.site);
    println!("Login: {}", site.login);
    println!("Lowercase: {}", site.lowercase);
    println!("Uppercase: {}", site.uppercase);
    println!("Symbols: {}", site.symbols);
    println!("Numbers: {}", site.numbers);
    println!("Length: {}", site.length);
    println!("Couter: {}", site.counter);
}

struct LessPassAuthenticatedClient<'a> {
    host: &'a Url,
    token: String,
    agent: &'a Agent
}

struct LessPassClient {
    host: Url,
    auth: Option<Auth>,
    agent: Agent
}

impl LessPassAuthenticatedClient<'_> {
    fn get_sites(&self) -> Result<Sites, String> {
        // Safe to unwrap as host has been checked before
        let url = self.host.join("passwords/").unwrap();
        let authorization = format!("Bearer {}", self.token);
        match self.agent.get(url.as_str()).set("Authorization", &authorization).call() {
            Ok(response) => {
                let sites: Sites = response.into_json().map_err(|e| format!("Unexpected response, {}", e))?;
                Ok(sites)
            },
            Err(ureq::Error::Status(code, _)) => Err(format!("Error getting authorization token, unexpected status code {}", code)),
            Err(_) => Err(format!("Error making request to {}", url))
        }
    }
}

impl LessPassClient {
    /// Configure the client itself
    fn new(host: Url, user: Option<String>, pass: Option<String>) -> LessPassClient {
        LessPassClient {
            host,
            auth: if user.is_some() && pass.is_some() {
                Some(Auth {
                    // Safe to unwrap as they have been checked before
                    email: user.unwrap(),
                    password: pass.unwrap()
                })
            } else {
                None
            },
            agent: Agent::new()
        }
    }

    /// Perform authentication
    fn auth(&self) -> Result<LessPassAuthenticatedClient, String> {
        // Try to get token form cache file
        let token_cache_file = match BaseDirectories::with_prefix(APP_NAME) {
            Ok(base_directories) => {
                match base_directories.place_cache_file("token") {
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
        Ok(LessPassAuthenticatedClient {
            host: &self.host,
            token: refreshed_token.access,
            agent: &self.agent
        })
    }

    /// Call to obtain a new access and refresh token using user and password
    fn get_token(&self) -> Result<Token, String> {
        // Safe to unwrap as host has been checked before
        let url = self.host.join("auth/jwt/create/").unwrap();
        match &self.auth {
            Some(auth) => {
                trace!("Using {} as LESSPASS_USER", auth.email);
                trace!("Using {} (value is masked) as LESSPASS_PASS", "*".repeat(auth.password.len()));
                match self.agent.post(url.as_str()).send_json(&auth) {
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
        if token == "" || token == "\n" {
            debug!("Token file does not exists or is empty");
            return Err(String::from("Invalid token found"))
        }
        // Safe to unwrap as host has been checked before
        let url = self.host.join("auth/jwt/refresh/").unwrap();
        let refresh = Refresh {
            refresh: String::from(token)
        };
        match self.agent.post(url.as_str()).send_json(&refresh) {
            Ok(response) => {
                let token: Token = response.into_json().map_err(|e| format!("Unexpected response, {}", e))?;
                info!("Token refreshed successfully");
                Ok(token)
            },
            Err(ureq::Error::Status(code, _)) => Err(format!("Error getting authorization token, unexpected status code {}", code)),
            Err(_) => Err(format!("Error making request to {}", url))
        }
    }
}

fn main() {
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
    let host = match env::var("LESSPASS_HOST") {
        Ok(host) => match Url::parse(&host) {
            Ok(host) => host,
            Err(_) => {
                println!("LESSPASS_HOST is not a valid URL");
                process::exit(0x0100);
            }
        },
        Err(_) => {
            println!("You must configure LESSPASS_HOST environment variable");
            process::exit(0x0100);
        }
    };
    // Configure loglevel
    match matches.get_count("verbosity") {
        0 => Builder::new().filter_level(LevelFilter::Off).init(),
        1 => Builder::new().filter_level(LevelFilter::Info).init(),
        2 => Builder::new().filter_level(LevelFilter::Debug).init(),
        3 | _ => Builder::new().filter_level(LevelFilter::Trace).init()
    };
    info!("Log level {:?}", log::max_level());
    trace!("Using {} as LESSPASS_HOST", host);
    // Get user and pass
    let user = env::var("LESSPASS_USER").ok();
    let pass = env::var("LESSPASS_PASS").ok();
    // Configure client
    let lesspass_client = LessPassClient::new(host, user, pass);
    // Configure client and perform auth
    let lesspass_authenticated_client = match lesspass_client.auth() {
        Ok(authenticated_client) => authenticated_client,
        Err(e) => {
            println!("{}", e);
            process::exit(0x0100);
        }
    };
    // Get the site list
    let mut sites = match lesspass_authenticated_client.get_sites() {
        Ok(sites) => {
            info!("Site list obtained successfully");
            sites
        },
        Err(err) => {
            println!("{}", err);
            process::exit(0x0100);
        }
    };
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
                        print_site(password);
                    } else {
                        // Try to get master password from environ
                        match env::var("LESSPASS_MASTERPASS") {
                            Ok(var) => {
                                trace!("Using {} (value is masked) as LESSPASS_MASTERPASS", "*".repeat(var.len()));
                                let mut charset = CharacterSet::All;
                                if ! password.lowercase {
                                    debug!("Lowercase characters excluded");
                                    charset.remove(CharacterSet::Lowercase);
                                }
                                if ! password.uppercase {
                                    debug!("Uppercase characters excluded");
                                    charset.remove(CharacterSet::Uppercase);
                                }
                                if ! password.symbols {
                                    debug!("Symbol characters excluded");
                                    charset.remove(CharacterSet::Symbols);
                                }
                                if ! password.numbers {
                                    debug!("Numeric characters excluded");
                                    charset.remove(CharacterSet::Numbers);
                                }
                                if charset.is_empty() {
                                    println!("There is a problem with site settings, all characters have been excluded");
                                    process::exit(0x0100);
                                }
                                let salt = generate_salt(&password.site, &password.login, password.counter);
                                let entropy = generate_entropy(&var, &salt, Algorithm::SHA256, 100000);
                                let password = render_password(&entropy, charset, password.length.into());
                                info!("Returning site password");
                                println!("{}", password);
                            },
                            // Master password not suplied, print all site settings
                            Err(_) => {
                                info!("Master password not suplied, returning site settings");
                                print_site(password);
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
}
