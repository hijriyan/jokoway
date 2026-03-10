import { useState } from 'react'
import './App.css'

import { createClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import { Greeter } from "../gen/helloworld_pb";
// The transport defines what type of endpoint we're hitting.
// In our example we'll be communicating with a Connect endpoint.
// If your endpoint only supports gRPC-web, make sure to use
// `createGrpcWebTransport` instead.
const transport = createGrpcWebTransport({
  baseUrl: "/api",
});

// Here we make the client itself, combining the service
// definition with the transport.
const client = createClient(Greeter, transport);

const sayHello = async (name: string) => {
  const response = await client.sayHello({ name });
  console.log(response.message);
  return response.message;
}

const sayHelloStream = async (name: string, onMessage: (msg: string) => void) => {
  const responseStream = client.sayHelloStream({ name });
  for await (const response of responseStream) {
    console.log("Stream received:", response.message);
    onMessage(response.message);
  }
}

function App() {
  const [message, setMessage] = useState("")
  const [streamMessages, setStreamMessages] = useState<string[]>([])

  const handleStreamClick = async () => {
    setStreamMessages([]); // Clear previous stream
    await sayHelloStream("Jokoway", (msg) => {
      setStreamMessages((prev) => [...prev, msg]);
    });
  };

  return (
    <>
      <div className="card">
        <h2>Unary Call</h2>
        <button onClick={() => sayHello("Jokoway").then((message) => setMessage(message))}>Say Hello (Unary)</button>
        <p>{message}</p>
      </div>

      <div className="card">
        <h2>Server Streaming Call</h2>
        <button onClick={handleStreamClick}>Say Hello (Stream)</button>
        <div style={{ marginTop: "1rem", textAlign: "left", background: "#f0f0f0", padding: "1rem", borderRadius: "8px", minHeight: "100px", color: "#333" }}>
          {streamMessages.length === 0 ? <p>No stream data yet...</p> : (
            <ul>
              {streamMessages.map((msg, i) => (
                <li key={i}>{msg}</li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </>
  )
}

export default App
