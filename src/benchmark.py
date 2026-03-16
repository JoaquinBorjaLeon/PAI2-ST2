"""
Benchmark de rendimiento y escalabilidad para PAI2.

Permite comparar transporte TLS 1.3 vs transporte sin TLS
usando el mismo protocolo de aplicacion (longitud + JSON).
"""

import argparse
import concurrent.futures
import json
import socket
import ssl
import statistics
import struct
import time
from typing import Dict, List, Tuple


def send_msg(sock, data):
    json_data = json.dumps(data).encode("utf-8")
    length_prefix = struct.pack("!I", len(json_data))
    sock.sendall(length_prefix + json_data)


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_msg(sock):
    raw_length = _recv_exact(sock, 4)
    if not raw_length:
        return None
    length = struct.unpack("!I", raw_length)[0]
    raw_data = _recv_exact(sock, length)
    if not raw_data:
        return None
    return json.loads(raw_data.decode("utf-8"))


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    if p <= 0:
        return min(values)
    if p >= 100:
        return max(values)
    ordered = sorted(values)
    idx = (len(ordered) - 1) * (p / 100.0)
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    frac = idx - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def create_socket(args):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(args.timeout)

    if args.mode == "plain":
        raw.connect((args.host, args.port))
        return raw

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(args.ca_cert)

    wrapped = ctx.wrap_socket(raw, server_hostname=args.host)
    wrapped.connect((args.host, args.port))
    return wrapped


def run_client(client_id: int, args, run_tag: str) -> Dict:
    username = f"bench_{run_tag}_{client_id:04d}"
    password = "BenchPass_123"

    start = time.perf_counter()
    sent_messages = 0

    try:
        sock = create_socket(args)

        send_msg(sock, {
            "action": "register",
            "username": username,
            "password": password,
        })
        reg = recv_msg(sock)
        if reg is None:
            raise RuntimeError("Sin respuesta en registro")

        send_msg(sock, {
            "action": "login",
            "username": username,
            "password": password,
        })
        login = recv_msg(sock)
        if login is None or login.get("status") != "ok":
            raise RuntimeError(f"Login fallido: {login}")

        for i in range(args.messages_per_client):
            send_msg(sock, {
                "action": "send_message",
                "message": f"mensaje benchmark {i} de {username}",
            })
            response = recv_msg(sock)
            if response is None or response.get("status") != "ok":
                raise RuntimeError(f"send_message fallo: {response}")
            sent_messages += 1

        send_msg(sock, {"action": "logout"})
        _ = recv_msg(sock)

        elapsed = time.perf_counter() - start
        try:
            sock.close()
        except Exception:
            pass

        return {
            "ok": True,
            "elapsed": elapsed,
            "messages": sent_messages,
            "error": "",
        }

    except Exception as exc:
        elapsed = time.perf_counter() - start
        return {
            "ok": False,
            "elapsed": elapsed,
            "messages": sent_messages,
            "error": str(exc),
        }


def summarize(results: List[Dict], wall_time: float, args):
    ok = [r for r in results if r["ok"]]
    ko = [r for r in results if not r["ok"]]
    latencies = [r["elapsed"] for r in ok]
    total_messages = sum(r["messages"] for r in results)

    print("=" * 70)
    print("RESULTADOS BENCHMARK")
    print("=" * 70)
    print(f"Modo transporte:           {args.mode}")
    print(f"Host/Puerto:               {args.host}:{args.port}")
    print(f"Clientes concurrentes:     {args.clients}")
    print(f"Mensajes por cliente:      {args.messages_per_client}")
    print(f"Clientes exitosos:         {len(ok)}")
    print(f"Clientes fallidos:         {len(ko)}")
    print(f"Mensajes enviados totales: {total_messages}")
    print(f"Tiempo total (wall):       {wall_time:.4f} s")

    throughput = total_messages / wall_time if wall_time > 0 else 0.0
    print(f"Throughput aprox:          {throughput:.2f} msg/s")

    if latencies:
        print(f"Latencia cliente promedio: {statistics.mean(latencies):.4f} s")
        print(f"Latencia cliente mediana:  {statistics.median(latencies):.4f} s")
        print(f"Latencia cliente p95:      {percentile(latencies, 95):.4f} s")
        print(f"Latencia cliente p99:      {percentile(latencies, 99):.4f} s")

    if ko:
        print("\nPrimeros errores:")
        for item in ko[:10]:
            print(f"  - {item['error']}")

    print("=" * 70)


def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark PAI2 TLS vs sin TLS")
    parser.add_argument("--mode", choices=["tls", "plain"], default="tls")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--clients", type=int, default=300)
    parser.add_argument("--messages-per-client", type=int, default=1)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--ca-cert", default="cert.pem")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.port is None:
        args.port = 8443 if args.mode == "tls" else 8080
    if args.workers is None:
        args.workers = args.clients

    run_tag = str(int(time.time()))
    start = time.perf_counter()

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(run_client, i, args, run_tag) for i in range(args.clients)]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    wall_time = time.perf_counter() - start
    summarize(results, wall_time, args)


if __name__ == "__main__":
    main()
