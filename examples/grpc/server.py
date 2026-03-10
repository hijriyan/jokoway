import logging
import signal
import sys
from concurrent import futures

import grpc
import helloworld_pb2
import helloworld_pb2_grpc

import time

class Greeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        logging.info(f"Received request for: {request.name}")
        return helloworld_pb2.HelloReply(message=f"Hello, {request.name}!")

    def SayHelloStream(self, request, context):
        logging.info(f"Received stream request for: {request.name}")
        for i in range(5):
            yield helloworld_pb2.HelloReply(message=f"Hello {request.name}, this is message {i + 1} of 5!")
            time.sleep(1)

def serve():
    port = "50051"
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logging.info(f"Server started, listening on {port}")

    def handle_sigterm(*_):
        logging.info("Shutting down...")
        server.stop(0)
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    server.wait_for_termination()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    serve()
