import os
import sys
import yaml
import base64
import logging
import traceback
from flask import Flask, Response, request, url_for
from clash_config_merger import (
    Config,
    generate,
    TEMPLATE,
    retrieve,
    convert_raw_list_to_rule_provider,
)

logging.basicConfig(
    level=logging.INFO,
    filename="clash-config-merger.log",
    format="%(asctime)s.%(msecs)d %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

app = Flask(__name__)


@app.get("/clash/config.yaml")
def generate_yaml():
    args = request.values.to_dict()
    if os.path.exists("upstreams.yaml"):
        with open("upstreams.yaml") as f:
            args["all_upstream"] = yaml.safe_load(f)
    elif env := os.environ.get("UPSTREAMS"):
        args["all_upstream"] = yaml.safe_load(base64.b64decode(env))
    else:
        return "No upstreams", 500
    client_ip = request.headers.get("X-Real-IP", request.remote_addr)
    logging.info(f"{client_ip} {args}")
    try:
        config = Config(**args)
        clash_config = generate(config)
        if config.use_relay_rule_provider:
            for rp, value in clash_config["rule-providers"].items():
                value["url"] = url_for(
                    "forward", key=rp, _external=True, _scheme="http"
                )
        stream = yaml.safe_dump(clash_config, allow_unicode=True, sort_keys=False)
    except Exception as e:
        logging.error(f"Generate config failed: {e}\n{traceback.format_exc()}")
        return str(e), 500
    return Response(stream, content_type="text/yaml; charset=utf-8")


@app.get("/clash/forward")
def forward():
    key = request.values.get("key")
    if key not in TEMPLATE["rule-providers"]:
        return "Not found", 404
    url = TEMPLATE["rule-providers"][key]["url"]
    if url.endswith("#convert"):
        return (
            retrieve(url[:-8], 86400, convert_raw_list_to_rule_provider),
            200,
            {"Content-Type": "text/yaml; charset=utf-8"},
        )
    return retrieve(url, 86400), 200, {"Content-Type": "text/yaml; charset=utf-8"}


if __name__ == "__main__":
    from gevent.pywsgi import WSGIServer

    logging.info(f"Python version: {sys.version}")
    bind = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    http_server = WSGIServer((bind, port), app)
    http_server.serve_forever()
