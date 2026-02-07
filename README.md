# jokoway

<p align="center">
  <img src="images/jokoway-logo.png" width="100%" alt="jokoway logo">
</p>

Jokoway is a high-performance API Gateway built on Pingora (Rust) with dead-simple YAML configs. Inspired by Traefik’s expressive routing rules and Kong’s DB-less declarative configuration model.

<p align="center">
  This is not intended for use in a production environment. This project is actually for learning and experimenting with Rust.
</p>

<p align="center">
  ⚠️ If you want to try it, go ahead, and I really appreciate any feedback. ⚠️ 
</p>

## 🌟 Key Features

* **Expressive Routing**: Traefik-style routing rules.
* **DB-less Declarative Config**: Manage your configuration without a database.
* **Highly Customizable**: Extend Jokoway's functionality with extensions.
* **Lets Encrypt**: Automatically issue and renew SSL certificates. (Supports HTTP-01 and TLS-ALPN-01 challenges)

## 🔧 Installation

```sh
git clone --depth 1 https://github.com/hijriyan/jokoway.git
cd jokoway
cargo build --release
# The binary will be available at target/release/jokoway
```

## 🔨 Usage

```sh
./target/release/jokoway -c jokoway.yml
```

see [jokoway.yml](jokoway.yml) for an example config.
