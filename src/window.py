# window.py
#
# Copyright 2026 Kate
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

import requests
from requests.exceptions import HTTPError

from .menu_button import VoucherMenuButton
from .keys import VoucherKeysTab
from .sites import VoucherSitesTab
from .status import VoucherStatusTab
from .confirmation import VoucherConfirmationPage
from .spinner_dialog import VoucherSpinnerDialog

from .lnutils import sign_k1

TASK_DATA = {}

def threaded_request(callback, method, address, body={}, headers={}, params={}):
    """Starts a request in a thread."""
    task = Gio.Task.new(None, Gio.Cancellable(), callback, None)
    task.set_return_on_cancel(False)
    task.run_in_thread(_task_internal_method)
    task_data = {"method": method, "address": address, "body": body, "headers": headers, "params": params}
    TASK_DATA[id(task_data)] = task_data
    task.set_task_data(id(task_data))
    return task

def _task_internal_method (task, source_object, task_data, cancellable):
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

@Gtk.Template(resource_path='/one/k8ie/Voucher/window.ui')
class VoucherWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'VoucherWindow'
    uses_params.append('lightning')
    main_view = Gtk.Template.Child()
    spinner_dialog = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.settings = self.get_application().settings
        identities = self.settings.get_strv("identities")
        if len(identities) == 0:
            self.generate_key("key 1", self.settings)
        print(self.settings.get_strv("identities"))
        print(keyring.get_password("Voucher", "key 1"))
        #self.setup_buttons()
        # if keyring.get_credential("Voucher", "test") is None:
        #     keyring.set_password("Voucher", "test", "whatever")
        #     self.after_device_registered()
        # print(keyring.get_password("Voucher", "test"))
        # else:
        #     self.generate_key()
        # test = VoucherConfirmationPage(appname="qra.mcld.eu")
        # test = VoucherConfirmationPage(appname="Authentik", address="https://qra.mcld.eu")
        # test = VoucherConfirmationPage(appname="Dex Demo", provider_address="http://localhost:8080")
        # self.main_view.push(test)
        #self.display_dialog("hihjiifsf", "jaksdfjsalkfa", [{"id": "whatever", "label": "Whatever"}])


    def display_dialog(self, message, text=None, responses=[{"id": "ok", "label": "Okay"}]):
        # Prevents a critical Adwaita warning
        if text is None:
            d = Adw.AlertDialog(heading=message)
        else:
            d = Adw.AlertDialog(heading=message, body=text)
        for response in responses:
            d.add_response(**response)
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


    def identify(self):
        print("TODO: Identify")
        # action = "identify"
        # message = "{} {}".format(action, str(uuid4()))
        # signature = self.sign_message(message)
        # body = {"signature": signature, "message": message}
        # params = {"session": session}
        # self.spinner_dialog.present(parent=self)
        # threaded_request(self.finish_identify, "post", api_addr + "/mobile/aqr/identify", body=body, params=params)


    def pop_confirmation_page(self, widget):
        self.main_view.pop()


    def authenticate(self):
        # I really don't like that we're using a window-wide object property to store the request data
        # on the other hand, why not
        queries = parse_qs(self.current_request.query)
        api_path = self.current_request.scheme + "://" + self.current_request.netloc + self.current_request.path
        signature, pub_key_hex = sign_k1(queries["k1"][0], self.current_request.hostname)
        params = {}
        for key, value in queries.items():
            params[key] = value[0]
        params["sig"] = signature
        params["key"] = pub_key_hex
        print(params)
        self.spinner_dialog.present(parent=self)
        threaded_request(self.finish_authenticate_request, "get", api_path, params=params)


    def handle_uri(self, uri):
        # TODO: Error handling for invalid URLs
        ln_parsed = urlparse(uri)
        # TODO: Don't hard-code lnurl?
        # TODO: Check for decoding errors
        lnurl_decoded = bech32.decode_bytes("lnurl", ln_parsed.path).decode("utf-8")
        parsed = urlparse(lnurl_decoded)
        print(parsed)
        # scheme = "http://"
        # if parsed.scheme == "quorra+https":
        #     scheme = "https://"
        queries = parse_qs(parsed.query)
        if "k1" in queries.keys() and "tag" in queries.keys() and queries["tag"] == ["login"]:
            # TODO: Only call identify when talking to Quorra
            self.current_request = (parsed)
            self.identify()
            self.main_view.push(VoucherConfirmationPage(appname=parsed.hostname))
