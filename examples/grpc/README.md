# gRPC Rust Demo

This example demonstrates how to use Jokoway as a gRPC proxy for a Rust-based gRPC service.

## Architecture

1.  **gRPC Client**: Sends gRPC requests (HTTP/2) with grpcurl or gRPC-Web to Jokoway.
2.  **Jokoway**: Acts as a reverse proxy (`grpc-gateway`), forwarding requests to the gRPC server. It also includes a middleware that intercepts and modifies the responses.
3.  **gRPC Server**: A Rust service (`grpc-server`) implementing the `helloworld.Greeter` service.

## Prerequisites

-   [Rust toolchain](https://rustup.rs/)
-   [grpcurl](https://github.com/fullstorydev/grpcurl) (optional, for testing)
-   Node.js and npm (for the web client demo)

## Files

-   `proto/helloworld.proto`: gRPC service definition.
-   `src/bin/grpc-server.rs`: Rust implementation of the Greeter service.
-   `src/bin/grpc-gateway.rs`: Jokoway proxy configuration and middleware implementation.
-   `client/`: A Vite-based web client demonstrating gRPC-Web support.

## Running the Demo

1. **Start the gRPC server**:
    In a new terminal, run:
    ```bash
    cargo run --bin grpc-server
    ```

2. **Start the Jokoway gateway**:
    In another terminal, run:
    ```bash
    cargo run --bin grpc-gateway
    ```

3. **Verify the service**:
    You can use `grpcurl` to test the gRPC service through the Jokoway gateway. The original response from the server is modified by the gateway's middleware.
    ```bash
    grpcurl -plaintext -import-path proto -proto helloworld.proto -d '{"name": "Jokoway"}' localhost:8080 helloworld.Greeter/SayHello
    ```

    The expected response is:
    ```json
    {
      "message": "Hello, Jokoway! (intercepted by gateway)"
    }
    ```

## Running the Web App Demo (Connect-Web)

A browser client application using `@connectrpc/connect-web` is provided in the `client` directory to demonstrate Jokoway's support for proxying gRPC-Web from browser applications.

1. **Ensure the gRPC server and gateway are running** (as described above).

2. **Navigate to the client directory and install dependencies:**
    ```bash
    cd client
    npm install
    ```

3. **Generate the TypeScript Client Code:**
    ```bash
    npx buf generate ../proto/helloworld.proto
    ```

4. **Start the Vite Web Application:**
    ```bash
    npm run dev
    ```

5. **Test the Application:**
    Open `http://localhost:4173` in your browser. You will see a web page. Interacting with the "Say Hello" button triggers a `gRPC-Web` request. The Vite proxy seamlessly proxies this to Jokoway which handles the transition to the gRPC connection to the Rust backend!
