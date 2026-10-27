import argparse
import threading
import webbrowser

from trafficlog.server import Application, LocalServer


def main():
    parser = argparse.ArgumentParser(description="MikroTik Traffic Log")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    app = Application()
    try:
        server = LocalServer(("127.0.0.1", args.port), app)
    except OSError:
        parser.exit(1, f"Port {args.port} is unavailable. Choose another with --port.\n")
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"MikroTik Traffic Log: {url}\nExit: Ctrl+C or Quit in the browser.", flush=True)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\nCleaning up capture…", flush=True)
    finally:
        app.close()
        if app.capture and (app.capture.cleanup_errors or app.capture.thread and app.capture.thread.is_alive()):
            print("Router cleanup incomplete. Restart and open Router changes. The router expiry task remains in place.", flush=True)
        server.server_close()


if __name__ == "__main__":
    main()
