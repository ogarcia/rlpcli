#[macro_use]
extern crate log;
extern crate clap;
extern crate xdg;
use clap::{command, Arg, ArgAction};
use env_logger::Builder;
use lesspass::{Algorithm, CharacterSet, generate_entropy, generate_salt, render_password};
use log::LevelFilter;
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;
use xdg::BaseDirectories;

use std::{env, fs, path, process};

#[derive(Serialize, Debug)]
pub struct Auth {
    pub email: String,
    pub password: String
}

#[derive(Serialize, Debug)]
pub struct Refresh {
    pub refresh: String
}

#[derive(Deserialize, Debug)]
pub struct Token {
    pub access: String,
    pub refresh: String
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

fn build_url(host: &str, path: &str) -> Url {
    let host_url = match Url::parse(&host) {
        Ok(host) => host,
        Err(_) => {
            println!("LESSPASS_HOST is not a valid URL");
            process::exit(0x0100);
        }
    };
    host_url.join(path).unwrap()
}

async fn get_token(host: &str, user: &str, pass: &str) -> Result<Token, String> {
    let url = build_url(host, "auth/jwt/create/");
    let auth = Auth {
        email: String::from(user),
        password: String::from(pass)
    };
    match Client::new().post(url.as_str()).json(&auth).send().await {
        Ok(response) => {
            if response.status() == 200 || response.status() == 201 {
                let token: Token = match response.json().await {
                    Ok(token) => token,
                    Err(err) => return Err(format!("Unexpected response, {}", err))
                };
                Ok(token)
            } else {
                Err(format!("Error getting authorization token, unexpected status code {}", response.status()))
            }
        },
        Err(_) => Err(format!("Error making request to {}", url))
    }
}

async fn refresh_token(host: &str, token: &str) -> Result<Token, String> {
    // If token is empty simply return an error
    if token == "" || token == "\n" {
        debug!("Token file does not exists or is empty");
        return Err("Invalid token found".to_string())
    }
    let url = build_url(host, "auth/jwt/refresh/");
    let refresh = Refresh {
        refresh: String::from(token)
    };
    match Client::new().post(url.as_str()).json(&refresh).send().await {
        Ok(response) => {
            if response.status() == 200 || response.status() == 201 {
                let token: Token = match response.json().await {
                    Ok(token) => token,
                    Err(err) => return Err(format!("Unexpected response, {}", err))
                };
                Ok(token)
            } else {
                Err(format!("Error refreshing authorization token, unexpected status code {}", response.status()))
            }
        },
        Err(_) => Err(format!("Error making request to {}", url))
    }
}

async fn get_sites(host: &str, token: &str) -> Result<Sites, String> {
    let url = build_url(host, "passwords/");
    let authorization = format!("Bearer {}", token);
    match Client::new().get(url.as_str()).header("Authorization", authorization).send().await {
        Ok(response) => {
            if response.status() == 200 {
                let sites: Sites = match response.json().await {
                    Ok(sites) => sites,
                    Err(err) => return Err(format!("Unexpected response, {}", err))
                };
                Ok(sites)
            } else {
                Err(format!("Error getting sites list, unexpected status code {}", response.status()))
            }
        },
        Err(_) => Err(format!("Error making request to {}", url))
    }
}

#[tokio::main]
async fn main() {
    pub const APP_NAME: &str = "rlpcli";

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
        Ok(var) => var,
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

    // Try to get token form cache file
    let token_cache_file = match BaseDirectories::with_prefix(APP_NAME).unwrap().place_cache_file("token") {
        Ok(token_cache_file) => {
            debug!("Using cache file {} for read and store token", token_cache_file.as_path().display());
            token_cache_file
        },
        Err(err) => {
            warn!("There is a problem accessing to cache file caused by {}, disabling cache", err);
            path::PathBuf::new()
        }
    };
    let token = match fs::read_to_string(token_cache_file.as_path()) {
        Ok(token) => {
            trace!("Current token '{}'", token);
            token
        },
        Err(_) => String::from("")
    };

    // Try refresh token first
    let requested_token = match refresh_token(&host, &token).await {
        Ok(refreshed_token) => {
            info!("Token refreshed successfully");
            refreshed_token
        },
        Err(_) => {
            // Token cannot be refreshed we need to obtain a new one
            warn!("Stored token is expired or invalid, it is necessary to re-authenticate with username and password");
            let user = match env::var("LESSPASS_USER") {
                Ok(var) => var,
                Err(_) => {
                    println!("You must configure LESSPASS_USER environment variable");
                    process::exit(0x0100);
                }
            };
            trace!("Using {} as LESSPASS_USER", user);
            let pass = match env::var("LESSPASS_PASS") {
                Ok(var) => var,
                Err(_) => {
                    println!("You must configure LESSPASS_PASS environment variable");
                    process::exit(0x0100);
                }
            };
            trace!("Using {} (value is masked) as LESSPASS_PASS", "*".repeat(pass.len()));
            match get_token(&host, &user, &pass).await {
                Ok(new_token) => {
                    info!("New token obtained successfully");
                    new_token
                },
                Err(err) => {
                    println!("{}", err);
                    process::exit(0x0100);
                }
            }
        }
    };

    trace!("Access token '{}'", requested_token.access);
    trace!("Refresh token '{}'", requested_token.refresh);

    // Save new refresh token
    if token_cache_file != path::PathBuf::new() {
        match fs::write(token_cache_file.as_path(), &requested_token.refresh) {
            Ok(_) => debug!("Refreshed token stored successfully"),
            Err(err) => warn!("There is a problem storing refreshed token file caused by {}", err)
        };
    }

    // Get the site list
    let mut sites = match get_sites(&host, &requested_token.access).await {
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
