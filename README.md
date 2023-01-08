# rlpcli

A tiny CLI helper written in [Rust][1] to get [LessPass][2] paswords and
site settings directly from a LessPass server.

If you are looking for a full implementation of client and library see
[lesspass-client][3].

[1]: https://www.rust-lang.org/
[2]: https://lesspass.com/
[3]: https://github.com/ogarcia/lesspass-client

## Installation

### From binary

Simply download latest release from [releases page][releases]. If you are an
Arch Linux user you can install it from [AUR][package].

[releases]: https://github.com/ogarcia/rlpcli/releases
[package]: https://aur.archlinux.org/packages/rlpcli

### From source

#### Installing Rust

rlpcli build has been tested with current Rust stable release version. You
can install Rust from your distribution package or [use `rustup`][rustup].
```
rustup default stable
```

If you prefer, you can use the stable version only for install rlpcli.
```
rustup override set stable
```

[rustup]: https://rustup.rs/

#### Installing rlpcli

To build rlpcli binary simply execute the following commands.
```sh
git clone https://github.com/ogarcia/rlpcli.git
cd rlpcli
cargo build --release
```

After build the binary is located in `target/release/rlpcli`.

## Usage

In first time use you must configure the following evironment variables.

| Variable | Used for |
| --- | --- |
| LESSPASS_HOST | URL of API server (ex. https://api.lesspass.com) |
| LESSPASS_USER | Username (ex. user@example.com) |
| LESSPASS_PASS | Password |

Now you can run `rlpcli` to get a list of sites stored in server.

After first run, _rlpcli_ stores the login token in your `XDG_CACHE_HOME`
directory, you can run commands with only `LESSPASS_HOST` environment
variable.

For get LessPass configuration of a site run `rlpcli SITENAME` being
sitename one of the list given in `rlpcli` command.

If you set `LESSPASS_MASTERPASS` environment variable with your LessPass
master password, _rlpcli_ returns the password of site instead of site
configuration.

There are other uses, run `rlpcli -h` to see the help.
