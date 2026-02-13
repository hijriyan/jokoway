# HTTPBin Example

This example shows how to use Jokoway to proxy HTTP, HTTPS, WS, and WSS traffic to httpbin.

## How to Run

```bash
# Run Jokoway
docker compose up -d
```

### Tests

#### HTTP

```bash
$ curl http://localhost:2014/hostname -H "host: httpbin.kuli.dev"

{
  "hostname": "go-httpbin"
}
```

Testing HTTPS, since jokoway use self-sign cert, we need to use `--insecure` flag

```bash
$ curl https://localhost:2024/hostname -H "host: httpbin.kuli.dev" --insecure

{
  "hostname": "go-httpbin"
}
```

### Websocket


You can test the websocket endpoint using software such as Postman, Hoppscotch, etc.

Here are the available websocket endpoints:

```
ws://localhost:2014/websocket/echo?max_fragment_size=2048&max_message_size=10240
```
