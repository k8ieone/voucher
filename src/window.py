# window.py
#
# Copyright 2025 Kate
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk

from platformdirs import user_data_path
from urllib.parse import uses_params, urlparse, parse_qs
from pathlib import Path
from uuid import uuid4
# TODO: Get rid of sleep
from time import sleep

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import base64
import requests

@Gtk.Template(resource_path='/one/k8ie/Voucher/window.ui')
class VoucherWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'VoucherWindow'
    uses_params = ['', 'quorra+http', 'quorra+https']
    manual_activation_button = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.KEY_LOCATION = user_data_path("voucher") / "key.pem"
        if not user_data_path("voucher").exists():
            user_data_path("voucher").mkdir()


    def display_dialog(self, message, text=None):
        d = Adw.AlertDialog(heading=message, body=text)
        d.add_response(id="ok", label="Awesome!")
        d.present(parent=self)


    def device_registration(self, api_addr, token):
        device_name = None
        # First generate a private key
        private_key = Ed25519PrivateKey.generate()
        # Prepare the registration request with the associated public key
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_pem_str = public_key_pem.decode('utf-8')
        body = {"pubkey": public_pem_str}
        headers = {"x-registration-token": token}
        # Send the registration request
        r = requests.post(api_addr + "/mobile/register", json=body, headers=headers)
        print(r.request.body)
        if r.status_code == 201:
            self.display_dialog("Activation successful", "This device has been successfully activated!")
            # Save the private key to a file
            with open(self.KEY_LOCATION, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        else:
            self.display_dialog("Activation failed", r.text)


    def sign_message(self, message):
        with open(self.KEY_LOCATION, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        # Signing requires binary data
        signature = private_key.sign(message.encode('utf-8'))
        # Resulting signature is also binary data which we can't send in JSON
        # so we base64-encode the signature data first
        return base64.b64encode(signature).decode('utf-8')


    def aqr_identify(self, api_addr, session):
        action = "identify"
        message = "{} {}".format(action, str(uuid4()))
        signature = self.sign_message(message)
        body = {"signature": signature, "message": message}
        params = {"session": session}
        r = requests.post(api_addr + "/mobile/aqr/identify", json=body, params=params)
        if r.status_code == 200:
            self.display_dialog("Session identified", "bottom text")
        else:
            self.display_dialog("Request failed", r.text)


    def aqr_authenticate(self, api_addr, session):
        action = "accepted"
        message = str(uuid4())
        signature = self.sign_message(message)
        body = {"signature": signature, "message": message, "state": action}
        params = {"session": session}
        r = requests.post(api_addr + "/mobile/aqr/authenticate", json=body, params=params)
        if r.status_code == 200:
            self.display_dialog("Session confirmed", "bottom text")
        else:
            self.display_dialog("Request failed", r.text)


    def extract_base_path(self, addr):
        marker = "/mobile/"
        idx = addr.find(marker)
        base_path = addr[:idx]
        return base_path


    def handle_uri(self, uri):
        parsed = urlparse(uri)
        scheme = "http://"
        if parsed.scheme == "quorra+https":
            scheme = "https://"
        queries = parse_qs(parsed.query)
        last_segment = parsed.path.split("/")[-1]
        base_path = self.extract_base_path(parsed.path)
        api_addr = scheme + parsed.netloc + base_path
        if last_segment == "register":
            if self.KEY_LOCATION.exists():
                self.display_dialog("Voucher is already active", "More than one activation is not supported.")
            else:
                self.device_registration(api_addr, queries["t"][0])
        if last_segment == "login":
            if not self.KEY_LOCATION.exists():
                self.display_dialog("Please activate Voucher first", "This application hasn't been activated yet.")
            else:
                self.aqr_identify(api_addr, queries["s"][0])
                sleep(10)
                self.aqr_authenticate(api_addr, queries["s"][0])
