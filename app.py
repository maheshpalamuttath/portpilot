from flask import Flask, render_template, jsonify, request
import subprocess
import socket
import json

app = Flask(__name__)


def get_docker_ports():
    """Get Docker container port mappings."""
    containers = []

    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--format",
                "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        for line in result.stdout.strip().splitlines():
            if not line:
                continue

            parts = line.split("|", 3)

            if len(parts) != 4:
                continue

            container_id, name, image, ports = parts

            containers.append({
                "id": container_id,
                "name": name,
                "image": image,
                "ports": ports
            })

    except Exception as e:
        print("Docker error:", e)

    return containers


def get_host_ports():
    """Get host listening TCP/UDP ports using ss."""
    ports = []

    try:
        result = subprocess.run(
            ["ss", "-lntupH"],
            capture_output=True,
            text=True,
            timeout=10
        )

        for line in result.stdout.strip().splitlines():
            parts = line.split()

            if len(parts) < 5:
                continue

            protocol = parts[0]

            if protocol.startswith("tcp"):
                proto = "TCP"
            elif protocol.startswith("udp"):
                proto = "UDP"
            else:
                continue

            local_address = parts[4]

            # Extract port from address
            try:
                if local_address.startswith("["):
                    # IPv6 format
                    port = int(local_address.rsplit(":", 1)[1].rstrip("]"))
                else:
                    port = int(local_address.rsplit(":", 1)[1])
            except Exception:
                continue

            process = ""

            if len(parts) >= 7:
                process = " ".join(parts[6:])

            ports.append({
                "port": port,
                "protocol": proto,
                "address": local_address,
                "process": process
            })

    except Exception as e:
        print("ss error:", e)

    return ports


def scan_ports():
    host_ports = get_host_ports()
    docker_containers = get_docker_ports()

    result = []

    # Merge host listening ports
    for item in host_ports:
        result.append({
            "port": item["port"],
            "protocol": item["protocol"],
            "address": item["address"],
            "process": item["process"],
            "source": "Host"
        })

    # Add Docker information where possible
    docker_by_port = {}

    for container in docker_containers:
        ports_text = container["ports"]

        # Docker port output example:
        # 0.0.0.0:8090->80/tcp
        # :::8090->80/tcp

        for mapping in ports_text.split(","):
            mapping = mapping.strip()

            if "->" not in mapping:
                continue

            try:
                host_part, container_part = mapping.split("->", 1)

                host_port = host_part.rsplit(":", 1)[1]
                host_port = int(host_port)

                container_port = container_part

                protocol = "TCP"

                if "/" in container_part:
                    container_port, proto = container_part.split("/", 1)
                    protocol = proto.upper()

                key = (host_port, protocol)

                docker_by_port.setdefault(key, []).append({
                    "name": container["name"],
                    "image": container["image"],
                    "container_port": container_port
                })

            except Exception:
                continue

    # Attach Docker information
    for item in result:
        key = (item["port"], item["protocol"])

        if key in docker_by_port:
            containers = docker_by_port[key]

            names = []

            for container in containers:
                names.append(
                    f'{container["name"]} → {container["container_port"]}'
                )

            item["source"] = "Docker"
            item["docker"] = ", ".join(names)

    # Remove duplicates
    unique = {}

    for item in result:
        key = (item["port"], item["protocol"], item["address"])

        if key not in unique:
            unique[key] = item

    return sorted(
        unique.values(),
        key=lambda x: (x["port"], x["protocol"])
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/ports")
def ports():
    return jsonify(scan_ports())


@app.route("/api/find-port")
def find_port():
    start = request.args.get("start", default=8000, type=int)
    end = request.args.get("end", default=9000, type=int)

    used = set()

    for item in scan_ports():
        used.add(item["port"])

    available = []

    for port in range(start, end + 1):
        if port not in used:
            available.append(port)

        if len(available) >= 10:
            break

    return jsonify({
        "available": available
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
