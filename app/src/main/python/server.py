# Demarre le serveur NETTOYAGE ANDROID PRO dans l'appli (sans Termux)
import os
import threading


def start(root, port, here):
    os.environ["NAP_ROOT"] = root
    os.environ["NAP_PORT"] = str(port)
    os.environ["NAP_HERE"] = here
    import nap_app

    def run():
        nap_app.app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False)

    threading.Thread(target=run, daemon=True).start()
    return True
