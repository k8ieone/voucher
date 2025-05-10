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

from urllib.parse import uses_params, urlparse, parse_qs

import requests

@Gtk.Template(resource_path='/one/k8ie/Voucher/window.ui')
class VoucherWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'VoucherWindow'
    uses_params = ['', 'quorra+http', 'quorra+https']
    manual_activation_button = Gtk.Template.Child()


    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def display_dialog(self, message, text=None):
        d = Adw.AlertDialog(heading=message, body=text)
        d.add_response(id="ok", label="Awesome!")
        d.present(parent=self)

    def device_registration(self, api_addr, token, device_name=None):
        # TODO: First generate a private key
        # Prepare the registration request with the associated TODO: public key
        body = {"pubkey": "totally a valid key"}
        headers = {"x-registration-token": token}
        # Send the registration request
        r = requests.post(api_addr + "/mobile/register", json=body, headers=headers)
        print(r.text)
        print(r.request.body)
        print(token)
        if r.status_code == 201:
            self.display_dialog("Activation successful", "This device has been successfully activated!")
        # TODO: Save the private key to a file

    def extract_base_path(self, addr):
        marker = "/mobile/"
        idx = addr.find(marker)
        base_path = addr[:idx]
        return base_path

    def handle_uri(self, uri):
        parsed = urlparse(uri)
        print(parsed)
        scheme = "http://"
        if parsed.scheme == "quorra+https":
            scheme = "https://"
        queries = parse_qs(parsed.query)
        print(queries)
        last_segment = parsed.path.split("/")[-1]
        base_path = self.extract_base_path(parsed.path)
        api_addr = scheme + parsed.netloc + base_path
        if last_segment == "register":
            self.device_registration(api_addr, queries["t"][0])
