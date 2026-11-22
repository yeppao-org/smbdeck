"""README screenshots, taken from the local demo (fake data only).

Runs in the official Playwright image, attached to the demo's network. A
small forwarder makes the console reachable as http://localhost:8080, a secure
context for the browser, so the copy buttons (clipboard API) show as they do
over HTTPS.
"""
import os
import socket
import sys
import threading
import time

from playwright.sync_api import sync_playwright

UPSTREAM = (os.environ.get("UPSTREAM_HOST", "web"), int(os.environ.get("UPSTREAM_PORT", "8080")))
BASE = "http://localhost:8080"
OUT = os.environ.get("OUT", "/out")
WIDE = {"width": 1440, "height": 960}
PHONE = {"width": 390, "height": 844}


def forward():
    """Accept on localhost:8080 and relay each connection to the console."""
    server = socket.create_server(("127.0.0.1", 8080))

    def pipe(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def serve():
        while True:
            client, _ = server.accept()
            upstream = socket.create_connection(UPSTREAM)
            threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
            threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()


def settle(page):
    page.wait_for_load_state("networkidle")
    time.sleep(1.4)  # entrance animations


def login(page, name, password):
    page.goto(BASE + "/login")
    page.fill("#login-name", name)
    page.fill("#login-password", password)
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")


def shot(page, name, full=False):
    settle(page)
    page.evaluate("window.scrollTo(0, 0)")
    time.sleep(0.2)
    page.screenshot(path=os.path.join(OUT, name), full_page=full)
    print("wrote", name)


def main():
    forward()
    with sync_playwright() as p:
        browser = p.chromium.launch()

        def context(scheme="dark", lang="en-US", viewport=WIDE):
            return browser.new_context(viewport=viewport, device_scale_factor=2, color_scheme=scheme,
                                       locale=lang, extra_http_headers={"Accept-Language": lang})

        # Sign-in page.
        ctx = context()
        page = ctx.new_page()
        page.goto(BASE + "/login")
        shot(page, "login.png")

        # Administrator views.
        login(page, "admin", "demo-admin-password")
        shot(page, "overview.png", full=True)

        page.goto(BASE + "/users")
        page.fill("#new-name", "dave")
        page.click("form[action='/users'] button[type=submit]")
        page.wait_for_load_state("networkidle")
        shot(page, "accounts.png")

        page.goto(BASE + "/shares/Photos")
        page.click("button.folder[data-folder='Photos']")
        shot(page, "share.png", full=True)

        page.goto(BASE + "/users")
        page.click("a[data-dialog='del-bob']")
        shot(page, "dialog.png")
        page.keyboard.press("Escape")

        page.goto(BASE + "/audit")
        shot(page, "journal.png")
        ctx.close()

        # Light scheme, French.
        ctx = context(scheme="light", lang="fr-FR")
        page = ctx.new_page()
        login(page, "admin", "demo-admin-password")
        shot(page, "overview-light-fr.png", full=True)
        ctx.close()

        # An account that is not an administrator.
        ctx = context()
        page = ctx.new_page()
        login(page, "alice", "demo-alice-password")
        shot(page, "my-account.png")
        ctx.close()

        # Phone.
        ctx = context(viewport=PHONE)
        page = ctx.new_page()
        login(page, "admin", "demo-admin-password")
        shot(page, "phone.png")
        ctx.close()

        browser.close()


if __name__ == "__main__":
    sys.exit(main())
