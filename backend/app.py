from gevent import monkey
monkey.patch_all()

import json
import gevent
import redis as redis_lib
from flask import Flask, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from backend.config import Config
from backend.extensions import mongo, jwt, socketio


limiter = Limiter(key_func=get_remote_address, default_limits=["200 per minute"])


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
    limiter.init_app(app)

    from backend.api.auth import auth_bp
    from backend.api.scans import scans_bp
    from backend.api.reports import reports_bp
    from backend.api.views import views_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")
    app.register_blueprint(views_bp)

    # Apply tighter rate limits to auth endpoints
    limiter.limit("10 per minute")(auth_bp)

    # Security headers on every response
    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
        # Only add HSTS for HTTPS
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

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
                    gevent.sleep(0.05)

            except Exception as exc:
                print(f"[redis_bridge] connection lost ({exc}), reconnecting in 3s…")
                gevent.sleep(3)


app = create_app()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)
