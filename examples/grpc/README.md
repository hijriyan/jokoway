# gRPC Python Demo

This example demonstrates how to use Jokoway as a gRPC proxy for a Python-based gRPC service.

## Architecture

1.  **gRPC Client**: Sends gRPC requests (HTTP/2) with grpcurl or gRPC-Web to Jokoway.
2.  **Jokoway**: Acts as a reverse proxy, forwarding requests to the gRPC server.
3.  **gRPC Server**: A Python service implementing the `helloworld.Greeter` service.

## Prerequisites

-   [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/)
-   [grpcurl](https://github.com/fullstorydev/grpcurl) (optional, for testing)

## Files

-   `proto/helloworld.proto`: gRPC service definition.
-   `server.py`: Python implementation of the Greeter service.
-   `jokoway.yml`: Jokoway configuration for gRPC proxying.
-   `docker-compose.yml`: Orchestrates the services.

## Running the Demo

1. **Generate gRPC code**:
    ```bash
    python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. proto/helloworld.proto
    ```

2. **Start the services**:
    ```bash
    docker-compose up --build
    ```

3. **Verify the service**:
    You can use `grpcurl` to test the gRPC service through Jokoway:
    ```bash
    grpcurl -plaintext -import-path proto -proto helloworld.proto -d '{"name": "Jokoway"}' localhost:8080 helloworld.Greeter/SayHello
    ```

    The expected response is:
    ```json
    {
      "message": "Hello, Jokoway!"
    }
    ```

## Running the Web App Demo (Connect-Web)

A browser client application using `@connectrpc/connect-web` is provided in the `client` directory to demonstrate Jokoway's support for proxying gRPC-Web from browser applications.

1. **Start the Jokoway and Python Backend services:**
    ```bash
    docker-compose up --build -d
    ```

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
    Open `http://localhost:4173` in your browser. You will see a web page. Interacting with the "Say Hello" button triggers a `gRPC-Web` request. The Vite proxy seamlessly proxies this to Jokoway which handles the transition to the gRPC connection to the Python backend!
