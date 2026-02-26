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
from gi.repository import Gio

from urllib.parse import uses_params, urlparse, parse_qs

import bech32
import keyring

import hmac
import hashlib
from mnemonic import Mnemonic
import bip32utils

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1,
    ECDSA,
    derive_private_key,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

import requests
from requests.exceptions import HTTPError

TASK_DATA = {}

@Gtk.Template(resource_path='/one/k8ie/Voucher/window.ui')
class VoucherWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'VoucherWindow'
    uses_params.append('lightning')
    manual_activation_button = Gtk.Template.Child()
    main_status = Gtk.Template.Child()
    main_nav_view = Gtk.Template.Child()
    confirmation_page = Gtk.Template.Child()
    confirm_button = Gtk.Template.Child()
    reject_button = Gtk.Template.Child()
    spinner_dialog = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.settings = self.get_application().settings
        identities = self.settings.get_strv("identities")
        if len(identities) == 0:
            self.generate_key("key 1")
        print(self.settings.get_strv("identities"))
        print(keyring.get_password("Voucher", "key 1"))
        self.setup_buttons()
        # if keyring.get_credential("Voucher", "test") is None:
        #     keyring.set_password("Voucher", "test", "whatever")
        #     self.after_device_registered()
        # print(keyring.get_password("Voucher", "test"))
        # else:
        #     self.generate_key()

    def setup_buttons(self):
        # self.main_status.set_title("Voucher is ready")
        # self.main_status.set_description("Scan a Quorra login code to sign in")
        # self.main_status.set_child(None)
        self.confirm_button.connect("clicked", self.authenticate)
        self.reject_button.connect("clicked", self.canclel_authenticate)


    def display_dialog(self, message, text=None):
        # Prevents a critical Adwaita warning
        if text is None:
            d = Adw.AlertDialog(heading=message)
        else:
            d = Adw.AlertDialog(heading=message, body=text)
        d.add_response(id="ok", label="Awesome!")
        d.present(parent=self)


    def finish_identify(self, window, task, whatevs):
        """Callback - function called after an identify request finishes"""
        task_data = TASK_DATA[task.get_task_data()]
        self.spinner_dialog.force_close()
        if task.propagate_boolean():
            self.main_nav_view.push(self.confirmation_page)
        else:
            self.display_dialog("Request failed", task_data["result"]["data"])
        # Cleanup
        del TASK_DATA[task.get_task_data()]

    def finish_authenticate_request(self, window, task, whatevs):
        """Callback - function called after an authenticate request finishes"""
        task_data = TASK_DATA[task.get_task_data()]
        self.spinner_dialog.force_close()
        if task.propagate_boolean():
            d = Adw.AlertDialog(heading="Session authorized")
            d.add_response(id="ok", label="Awesome!")
            d.connect("closed", self.pop_confirmation_page)
            d.present(parent=self)
        else:
            self.display_dialog("Request failed", task_data["result"]["data"])
        # Cleanup
        del TASK_DATA[task.get_task_data()]

    def threaded_request(self, callback, method, address, body={}, headers={}, params={}):
        """Starts a request in a thread."""
        task = Gio.Task.new(self, Gio.Cancellable(), callback, None)
        task.set_return_on_cancel(False)
        task.run_in_thread(self._task_internal_method)
        task_data = {"method": method, "address": address, "body": body, "headers": headers, "params": params}
        TASK_DATA[id(task_data)] = task_data
        task.set_task_data(id(task_data))
        return task

    def _task_internal_method (self, task, source_object, task_data, cancellable):
        """Called by threaded_request in a thread"""

        if task.return_error_if_cancelled():
            task.return_value(None)

        # Task data is just an id of the actual data. So, we need to get
        # the actual data from our instance-wide dictionary
        task_data = TASK_DATA[task.get_task_data()]
        method = task_data["method"]
        address = task_data["address"]
        body = task_data["body"]
        headers = task_data["headers"]
        params = task_data["params"]
        match method:
            case "post":
                r = requests.post(address, json=body, headers=headers, params=params)
            case "get":
                r = requests.get(address, json=body, headers=headers, params=params)
        result = {"status": r.status_code, "data": r.text}
        TASK_DATA[task.get_task_data()]["result"] = result
        try:
            r.raise_for_status()
        except HTTPError:
            task.return_boolean(False)
        else:
            task.return_boolean(True)


    def identify(self):
        print("TODO: Identify")
        # action = "identify"
        # message = "{} {}".format(action, str(uuid4()))
        # signature = self.sign_message(message)
        # body = {"signature": signature, "message": message}
        # params = {"session": session}
        # self.spinner_dialog.present(parent=self)
        # self.threaded_request(self.finish_identify, "post", api_addr + "/mobile/aqr/identify", body=body, params=params)


    def canclel_authenticate(self, widget):
        # self.authenticate("rejected")
        self.main_nav_view.pop()


    def pop_confirmation_page(self, widget):
        self.main_nav_view.pop()


    def authenticate(self, widget):
        # I really don't like that we're using a window-wide object property to store the request data
        # on the other hand, why not
        queries = parse_qs(self.current_request.query)
        api_path = self.current_request.scheme + "://" + self.current_request.netloc + self.current_request.path
        signature, pub_key_hex = self.sign_k1(queries["k1"][0], self.current_request.hostname)
        params = {}
        for key, value in queries.items():
            params[key] = value[0]
        params["sig"] = signature
        params["key"] = pub_key_hex
        print(params)
        self.spinner_dialog.present(parent=self)
        self.threaded_request(self.finish_authenticate_request, "get", api_path, params=params)


    def generate_key(self, name: str) -> None:
        mnemo = Mnemonic("english").generate(strength=256)
        keyring.set_password("Voucher", name, mnemo)
        # TODO: Don't overwrite the whole list
        self.settings.set_strv("identities", [name])


    def derive_lnurl_master_key(self, name: str) -> bytes:
        """
        Derive the LNURL-auth master key from a BIP-39 mnemonic.
        Uses BIP-32 derivation path m/138'/0 as per the LNURL-auth spec.
        """
        seed = Mnemonic.to_seed(keyring.get_password("Voucher", name))

        # Derive the root key from the seed
        root_key = bip32utils.BIP32Key.fromEntropy(seed)

        # Derive m/138'/0 (138' is hardened, as per LNURL-auth spec)
        lnurl_master = root_key.ChildKey(138 + bip32utils.BIP32_HARDEN).ChildKey(0)

        return lnurl_master.PrivateKey()


    def derive_domain_key(self, master_key: bytes, domain: str) -> EllipticCurvePrivateKey:
        """
        Derive a domain-specific private key using HMAC-SHA256.
        The master key is the HMAC secret, the domain is the message.
        The resulting 32 bytes are used directly as a SECP256K1 private key.
        """
        domain_key_bytes = hmac.new(
            key=master_key,
            msg=domain.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()

        # Convert the 32 raw bytes into a SECP256K1 private key
        private_key = derive_private_key(
            int.from_bytes(domain_key_bytes, byteorder="big"),
            SECP256K1(),
            default_backend(),
        )

        return private_key


    def get_public_key_hex(self, private_key: EllipticCurvePrivateKey) -> str:
        """Get the compressed public key in hex (this is your linking key for the domain)."""
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        ).hex()


    def der_to_low_s_der(self, der_sig: bytes) -> bytes:
        """
        Convert a DER-encoded signature to a 64-byte compact signature.
        Each of r and s is zero-padded to 32 bytes.
        """
        SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        SECP256K1_HALF_N = SECP256K1_N // 2
        r, s = decode_dss_signature(der_sig)
        if s > SECP256K1_HALF_N:
            s = SECP256K1_N - s
        return encode_dss_signature(r, s)

    def sign_k1(self, k1_hex: str, domain: str) -> str:
        """
        Sign the k1 challenge provided by the LNURL-auth service.
        k1 is a 32-byte hex string provided by the service.
        Returns the DER-encoded signature as hex.
        """
        master_key = self.derive_lnurl_master_key("key 1")
        domain_key = self.derive_domain_key(master_key, domain)
        pub_key_hex = self.get_public_key_hex(domain_key)

        k1_bytes = bytes.fromhex(k1_hex)
        signature = domain_key.sign(k1_bytes, ECDSA(Prehashed(hashes.SHA256())))
        signature_tweaked = self.der_to_low_s_der(signature)
        return (signature_tweaked.hex(), pub_key_hex)


    def handle_uri(self, uri):
        # TODO: Error handling for invalid URLs
        ln_parsed = urlparse(uri)
        # TODO: Don't hard-code lnurl?
        # TODO: Check for decoding errors
        lnurl_decoded = bech32.decode_bytes("lnurl", ln_parsed.path).decode("utf-8")
        parsed = urlparse(lnurl_decoded)
        # scheme = "http://"
        # if parsed.scheme == "quorra+https":
        #     scheme = "https://"
        queries = parse_qs(parsed.query)
        if "k1" in queries.keys() and "tag" in queries.keys() and queries["tag"] == ["login"]:
            # TODO: Only call identify when talking to Quorra
            self.current_request = (parsed)
            self.identify()
            self.main_nav_view.push(self.confirmation_page)
