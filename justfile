# run:
# 	flatpak-builder --force-clean --sandbox --user --install-deps-from=flathub --ccache --disable-tests --repo=flatpak-repo flatpak-build one.k8ie.Voucher.json
app_id := "one.k8ie.Voucher"
manifest := app_id + ".json"
command := "voucher" # Change this if your manifest's "command" is different, e.g., "my-app"

# 1. Build the app incrementally (NO --force-clean, NO --install)
build:
    flatpak-builder --force-clean --sandbox --user --install-deps-from=flathub --ccache --disable-tests flatpak-build {{manifest}}

# 2. Run directly from the build directory
run: build
    flatpak-builder --run flatpak-build {{manifest}} {{command}}

