# Deploy go-httpbin with jokoway

## Prerequisites

- Docker
- Docker Compose
- A domain name
- A DNS CNAME record pointing to your server's IP address

## Steps

1. Clone the repository
2. Edit `jokoway.yml` to replace `httpbin.kuli.dev` with your domain name
3. Run `docker-compose up -d`
4. If staging certificate is issued, replace `ca_server` with `https://acme-v02.api.letsencrypt.org/directory` in `jokoway.yml`
5. Run `docker-compose down` and `docker-compose up -d`

## Testing

Visit <https://httpbin.kuli.dev> to see if production certificate is issued.
