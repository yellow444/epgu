import base64
import json
import logging
import os
import os.path
import sys
from os import environ

sys.path.append(r'/usr/local/lib/pycades.so')

import debugpy
import pycades
import requests
from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, request

# Enable logging
production =  environ.get('production')
if production is None:
    debugpy.listen(("0.0.0.0", 5678))
    debugpy.wait_for_client()
    logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.DEBUG)
else:
    logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
    
logger = logging.getLogger(__name__)

# Flask
app = Flask(__name__)
wsgi_app = app.wsgi_app
# environment 
load_dotenv(find_dotenv())

# global
accessTkn_esia = ""
api_key = os.getenv('apikey', 'my api key')
TSAAddress = os.getenv('TSAAddress', 'http://testca2012.cryptopro.ru/tsp/tsp.srf')
esia_host = os.getenv('esia_host', 'https://esia-portal1.test.gosuslugi.ru')
svcdev_host = os.getenv('svcdev_host', 'https://svcdev-beta.test.gosuslugi.ru')

@app.route("/", methods=["GET"])
def home_route():
    Version = pycades.About()
    ModuleVersion = pycades.ModuleVersion()
    return "<div>Version:" + Version.Version + "</div>" + "<div>ModuleVersion:" + ModuleVersion + "</div>"

@app.route("/check", methods=["GET"])
def check_route():
    return "Ok"

@app.route("/accessTkn_esia", methods=["POST"])
def accessTkn_esia():
    global accessTkn_esia
    global api_key
    global esia_host
    if request.method=="POST":
        try:
            posted_data = "{}"
            if request.is_json:
                posted_data = request.get_json()
            if "api_key" in posted_data:
                api_keyData = str(posted_data["api_key"])
            else:
                api_keyData = api_key            
            sign = signkey(api_keyData)
            host = esia_host + "/esia-rs/api/public/v1/orgs/ext-app/" + api_key + "/tkn?signature=" + sign
            response = requests.get(host).content
            res = json.loads(response)
            result = "{}"
            if "accessTkn" in res:
                accessTkn_esia = res["accessTkn"]
                if api_keyData and api_keyData != "":
                    api_key = api_keyData
            return jsonify(res)
        except Exception as err:
            return jsonify(err)

def signkey(api_key):
    global TSAAddress
    store = pycades.Store()
    store.Open(pycades.CADESCOM_CONTAINER_STORE, pycades.CAPICOM_MY_STORE, pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)
    certs = store.Certificates
    assert(certs.Count != 0), "Certificates with private key not found"
    signer = pycades.Signer()
    signer.Certificate = certs.Item(1)
    signer.CheckCertificate = True
    signer.TSAAddress = TSAAddress
    signedData = pycades.SignedData()
    signedData.ContentEncoding = pycades.CADESCOM_BASE64_TO_BINARY
    message = api_key
    message_bytes = message.encode("utf-8")
    base64_message = base64.b64encode(message_bytes)
    signedData.Content = base64_message.decode("utf-8")
    bDetached = int (1)
    signature = signedData.SignCades(signer, pycades.CADESCOM_CADES_BES, bDetached )
    signature = signature.replace("\r\n", "", )
    signature = signature + "=" * (4 - len(signature) % 4)
    message_bytes = base64.b64decode( signature)
    result = (base64.urlsafe_b64encode (message_bytes)).decode("utf-8")
    return result


@app.route("/order", methods=["POST"])
def order():
    global accessTkn_esia
    global svcdev_host
    if request.method=="POST":
        posted_data = "{}"
        if request.is_json:
            posted_data = request.get_json()
        head = {"Authorization": "Bearer {}".format(accessTkn_esia), "content-type": "application/json"}
        host = svcdev_host + "/api/gusmev/order"
        result = requests.post(host, headers=head, data=json.dumps(posted_data), verify=False)
        return json.loads(result.content.decode('utf-8'))


@app.route("/push", methods=["POST"])
def push():
    global accessTkn_esia
    global svcdev_host
    if request.method=="POST":
        posted_data = "{}"
        if request.is_json:
            posted_data = request.get_json()
        head = {"Authorization": "Bearer {}".format(accessTkn_esia), "content-type": "application/json"}
        host = svcdev_host + "/api/gusmev/push"
        result = requests.post(host, headers=head, data=json.dumps(posted_data), verify=False)
        return json.loads(result.content.decode('utf-8'))


@app.route("/push/chunked", methods=["POST"])
def chunked():
    global accessTkn_esia
    global svcdev_host
    if request.method=="POST":
        posted_data = "{}"
        if request.is_json:
            posted_data = request.get_json()
        head = {"Authorization": "Bearer {}".format(accessTkn_esia), "content-type": "application/json"}
        host = svcdev_host + "/api/gusmev/push/chunked"
        result = requests.post(host, headers=head, data=json.dumps(posted_data), verify=False)
        return json.loads(result.content.decode('utf-8'))


@app.route("/status", methods=["POST"])
def status():
    global accessTkn_esia
    global svcdev_host
    if request.method=="POST":
        posted_data = "{}"
        if request.is_json:
            posted_data = request.get_json()
        orderId = str(posted_data["orderId"])
        head = {"Authorization": "Bearer {}".format(accessTkn_esia), "content-type": "application/json"}
        host = svcdev_host + "/api/gusmev/order" + orderId + "?embed=STATUS_HISTORY"
        result = requests.post(host, headers=head, data=json.dumps(posted_data), verify=False)
        return json.loads(result.content.decode('utf-8'))

def create_app(testing=False):
    """Application factory, used to create application"""
    app = Flask("app")
    app.config.from_object("app.config")
    if testing is True:
        app.config["TESTING"] = True
    app.configure_extensions(app)
    app.configure_cli(app)
    app.configure_apispec(app)
    app.register_blueprints(app)
    return app

if __name__ == "__main__":
    import os
    HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
    try:
        PORT = int(os.environ.get("SERVER_PORT", "5000"))
    except ValueError:
        PORT = 5000
    app.run(host = HOST, port = PORT)
