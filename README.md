# rlpcli

A tiny CLI written in [Rust][rust] to get passwords and site settings
directly from a [LessPass][lesspass] API server like [Rockpass][rockpass].

If you are looking for a full implementation of CLI client and library see
[lesspass-client][lesspassclient].

[rust]: https://www.rust-lang.org/
[lesspass]: https://github.com/lesspass/lesspass
[rockpass]: https://gitlab.com/ogarcia/rockpass
[lesspassclient]: https://gitlab.com/ogarcia/lesspass-client

## Installation

### From binary

Simply download latest release from [releases page][releases].

[releases]: https://gitlab.com/ogarcia/lesspass-client/-/releases

### From source

#### Installing Rust

rlpcli build has been tested with current Rust stable release version. You
can install Rust from your distribution package or [use `rustup`][rustup].
```
rustup default stable
```

If you prefer, you can use the stable version only for install rlpcli (you
must clone the repository first).
```
rustup override set stable
```

[rustup]: https://rustup.rs/

#### Installing rlpcli

To build rlpcli binary simply execute the following commands.
```shell
git clone https://gitlab.com/ogarcia/rlpcli.git
cd rlpcli
cargo build --release
```

After build the binary is located in `target/release/rlpcli`.

### Arch Linux package

rlpcli is packaged in Arch Linux and can be downloaded from the [AUR][aur].

[aur]: https://aur.archlinux.org/packages/rlpcli

## Usage

In first time use you must configure the following evironment variables.

| Variable | Used for |
| --- | --- |
| LESSPASS_HOST | URL of API server (ex. https://api.lesspass.com) |
| LESSPASS_USER | Username (ex. user@example.com) |
| LESSPASS_PASS | Your API password (see [here][apipwd] for more info) |
| LESSPASS_MASTERPASS | Your LessPass master password (optional, see below) |

Now you can run `rlpcli` to get a list of sites stored in server.

After first run, _rlpcli_ stores the login token in your `XDG_CACHE_HOME`
directory, you can run commands with only `LESSPASS_HOST` environment
variable.

For get LessPass configuration of a site run `rlpcli SITENAME` being
sitename one of the list given in `rlpcli` command.

If you set `LESSPASS_MASTERPASS` environment variable with your LessPass
master password, _rlpcli_ returns the password of site instead of site
configuration.

[apipwd]: https://gitlab.com/ogarcia/lesspass-client#how-to-get-the-api-password

### Usage example

Basic usage.
```shell
$ export LESSPASS_HOST=https://api.lesspass.com
$ export LESSPASS_USER=user@example.com
$ export LESSPASS_PASS="Kd*k5i63iN$^z)?V"
$ rlpcli
site.com
www.example.com
other.com
...

$ rlpcli www.example.com
ID: 962a2469-f2d0-40c9-adba-7236c050ff6c
Site: www.example.com
Login: user@sample.com
Lowercase: true
Uppercase: true
Symbols: false
Numbers: true
Length: 16
Couter: 4
```

If you have the same site with different users you can list and get the site
settings by ID.
```shell
$ rlpcli -i
004f5a30-3333-49e8-82d8-b970b6948632: site.com
02344541-6d99-44db-910e-a6c69da9a85f: site.com
04025507-7e74-476d-977f-76ef78e79b04: www.example.com

$ rlpcli -i 004f5a30-3333-49e8-82d8-b970b6948632
ID: 004f5a30-3333-49e8-82d8-b970b6948632
Site: site.com
Login: one@example.com
Lowercase: true
Uppercase: true
Symbols: true
Numbers: true
Length: 16
Couter: 1

$ rlpcli -i 02344541-6d99-44db-910e-a6c69da9a85f
ID: 02344541-6d99-44db-910e-a6c69da9a85f
Site: site.com
Login: two@example.com
Lowercase: true
Uppercase: true
Symbols: true
Numbers: true
Length: 16
Couter: 1
```

Note on IDs: Depending on the server implementation, IDs can be UUIDs,
integers or other strings, this is irrelevant for the operation of rlpcli.

If you set the master password you can get the password directly instead of
the site settings.
```shell
$ export LESSPASS_HOST=https://api.lesspass.com
$ export LESSPASS_USER=user@example.com
$ export LESSPASS_PASS="Kd*k5i63iN$^z)?V"
$ export LESSPASS_MASTERPASS="very difficult master password"
$ rlpcli www.example.com
B4y)rE1^iX3oS-}]

# You can also ask for ID
$ rlpcli -i 004f5a30-3333-49e8-82d8-b970b6948632
Q7kvjy2w=iD9s$Dk

# And copy with xclip
$ rlpcli -i 004f5a30-3333-49e8-82d8-b970b6948632 | xclip
```

There are other uses, run `rlpcli -h` to see the help.
