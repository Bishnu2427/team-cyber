from flask import Blueprint, render_template

views_bp = Blueprint("views", __name__)


@views_bp.route("/")
def index():
    return render_template("landing.html")


@views_bp.route("/login")
def login():
    return render_template("auth/login.html")


@views_bp.route("/register")
def register():
    return render_template("auth/register.html")


@views_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard/index.html")


@views_bp.route("/scans/new")
def new_scan():
    return render_template("scans/new.html")


@views_bp.route("/scans/<scan_id>")
def scan_detail(scan_id):
    return render_template("scans/detail.html", scan_id=scan_id)
