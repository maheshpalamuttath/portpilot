from flask import Flask, render_template, jsonify, request
import subprocess

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

            try:
                if local_address.startswith("["):
                    port = int(
                        local_address.rsplit(":", 1)[1].rstrip("]")
                    )
                else:
                    port = int(
                        local_address.rsplit(":", 1)[1]
                    )
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
    """
    Return one row per actual host port + protocol.

    IPv4 and IPv6 bindings of the same port are merged.
    Multiple Docker containers using the same host port
    are also shown in the same row.
    """

    host_ports = get_host_ports()
    docker_containers = get_docker_ports()

    ports = {}

    # ---------------------------------------------------------
    # HOST PORTS
    # ---------------------------------------------------------

    for item in host_ports:

        key = (
            item["port"],
            item["protocol"]
        )

        if key not in ports:
            ports[key] = {
                "port": item["port"],
                "protocol": item["protocol"],
                "address": [],
                "process": [],
                "source": "Host"
            }

        if item["address"] not in ports[key]["address"]:
            ports[key]["address"].append(
                item["address"]
            )

        if (
            item["process"]
            and item["process"] not in ports[key]["process"]
        ):
            ports[key]["process"].append(
                item["process"]
            )

    # ---------------------------------------------------------
    # DOCKER PORTS
    # ---------------------------------------------------------

    for container in docker_containers:

        ports_text = container["ports"]

        for mapping in ports_text.split(","):

            mapping = mapping.strip()

            if "->" not in mapping:
                continue

            try:

                host_part, container_part = mapping.split(
                    "->",
                    1
                )

                # Examples:
                #
                # 0.0.0.0:5000
                # :::5000
                # 127.0.0.1:8080

                host_port = int(
                    host_part.rsplit(":", 1)[1]
                )

                container_port = container_part
                protocol = "TCP"

                if "/" in container_part:

                    container_port, proto = (
                        container_part.rsplit("/", 1)
                    )

                    protocol = proto.upper()

                key = (
                    host_port,
                    protocol
                )

                if key not in ports:

                    ports[key] = {
                        "port": host_port,
                        "protocol": protocol,
                        "address": [],
                        "process": [],
                        "source": "Docker"
                    }

                item = ports[key]

                # Docker takes priority as the source
                item["source"] = "Docker"

                # -------------------------------------------------
                # ADDRESS
                # -------------------------------------------------

                address = host_part.rsplit(":", 1)[0]

                if address == "0.0.0.0":

                    display_address = "0.0.0.0"

                elif address in ("::", ""):

                    display_address = "::"

                else:

                    display_address = address

                if (
                    display_address
                    not in item["address"]
                ):

                    item["address"].append(
                        display_address
                    )

                # -------------------------------------------------
                # CONTAINER
                # -------------------------------------------------

                container_info = (
                    f'{container["name"]} → '
                    f'{container_port}'
                )

                if (
                    container_info
                    not in item["process"]
                ):

                    item["process"].append(
                        container_info
                    )

            except Exception as e:

                print(
                    "Docker mapping error:",
                    mapping,
                    e
                )

                continue

    # ---------------------------------------------------------
    # FORMAT RESULT
    # ---------------------------------------------------------

    result = []

    for item in ports.values():

        result.append({
            "port": item["port"],
            "protocol": item["protocol"],
            "address": ", ".join(
                item["address"]
            ),
            "process": ", ".join(
                item["process"]
            ),
            "source": item["source"]
        })

    # ---------------------------------------------------------
    # SORT
    # ---------------------------------------------------------

    return sorted(
        result,
        key=lambda x: (
            x["port"],
            x["protocol"]
        )
    )


@app.route("/")
def index():

    return render_template(
        "index.html"
    )


@app.route("/api/ports")
def ports():

    return jsonify(
        scan_ports()
    )


@app.route("/api/find-port")
def find_port():

    start = request.args.get(
        "start",
        default=8000,
        type=int
    )

    end = request.args.get(
        "end",
        default=9000,
        type=int
    )

    used = set()

    for item in scan_ports():

        used.add(
            item["port"]
        )

    available = []

    for port in range(
        start,
        end + 1
    ):

        if port not in used:

            available.append(
                port
            )

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
