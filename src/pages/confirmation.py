# confirmation.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk
from gi.repository import GObject

@Gtk.Template(resource_path='/one/k8ie/Voucher/pages/confirmation.ui')
class VoucherConfirmationPage(Adw.NavigationPage):
    __gtype_name__ = 'VoucherConfirmationPage'

    application_name = Gtk.Template.Child()
    oidc_url = Gtk.Template.Child()
    via_label = Gtk.Template.Child()

    appname = GObject.Property(type=str, default="unknown")
    provider_address = GObject.Property(type=str, default="unknown")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.provider_address != "unknown":
            self.oidc_url.set_label(self.provider_address)
            self.oidc_url.set_visible(True)
            self.via_label.set_visible(True)
        self.application_name.set_label(self.appname)

    @Gtk.Template.Callback()
    def on_confirm(self, widget):
        self.get_root().authenticate()

    @Gtk.Template.Callback()
    def on_cancel(self, widget):
        self.get_parent().pop()
