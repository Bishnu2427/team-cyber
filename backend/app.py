from gevent import monkey
monkey.patch_all()

import json
import gevent
import redis as redis_lib
from flask import Flask
from flask_cors import CORS
from backend.config import Config
from backend.extensions import mongo, jwt, socketio


def create_app(config_class=Config):
    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static",
    )
    app.config.from_object(config_class)

    CORS(app)
    mongo.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode="gevent")

    from backend.api.auth import auth_bp
    from backend.api.scans import scans_bp
    from backend.api.reports import reports_bp
    from backend.api.views import views_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")
    app.register_blueprint(views_bp)

    socketio.start_background_task(_redis_bridge, app)

    return app


def _redis_bridge(app):
    """
    Poll Redis 'scan:events' and forward to WebSocket clients.
    Uses get_message() loop instead of listen() — required for gevent compatibility.
    Auto-reconnects on failure.
    """
    with app.app_context():
        redis_url = app.config["REDIS_URL"]
        while True:
            try:
                r = redis_lib.from_url(
                    redis_url,
                    socket_timeout=None,
                    socket_connect_timeout=5,
                )
                pubsub = r.pubsub()
                pubsub.subscribe("scan:events")
                print("[redis_bridge] subscribed to scan:events")

                while True:
                    msg = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if msg and msg["type"] == "message":
                        try:
                            payload = json.loads(msg["data"])
                            socketio.emit(payload["event"], payload["data"])
                        except Exception as exc:
                            print(f"[redis_bridge] emit error: {exc}")
                    gevent.sleep(0.05)   # yield so other greenlets can run

            except Exception as exc:
                print(f"[redis_bridge] connection lost ({exc}), reconnecting in 3s…")
                gevent.sleep(3)


app = create_app()

if __name__ == "__main__":
    # use_reloader=False is required — gevent monkey-patch is incompatible with fork
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)
