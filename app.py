from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import socket
import ssl
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import requests

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///security_audits.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class AuditLog(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  domain = db.Column(db.String(150), nullable=False)
  score = db.Column(db.Integer, nullable=False)
  issues_count = db.Column(db.Integer, nullable=False)
  timestamp = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
  db.create_all()


def check_ssl(domain):
  try:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=3) as sock:
      with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
        cert = ssock.getpeercert()
        exp_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (exp_date - datetime.now()).days
        return {
            "valid": True,
            "days_left": days_left,
            "issuer": dict(x[0] for x in cert["issuer"]).get(
                "organizationName", "Unknown"
            ),
        }
  except Exception:
    return {"valid": False, "error": "SSL missing or connection failed"}


def check_headers(domain):
  issues = []
  recommendations = []
  headers_status = {}

  # Udhëzuesit dhe rekomandimet për çdo header
  remediation_db = {
      "Strict-Transport-Security": {
          "risk": "High (Mungon mbrojtja nga lidhjet e pasigurta HTTP)",
          "fix": (
              "Add 'Strict-Transport-Security: max-age=31536000;"
              " includeSubDomains' header to force HTTPS."
          ),
      },
      "Content-Security-Policy": {
          "risk": "High (I ekspozuar ndaj sulmeve Cross-Site Scripting - XSS)",
          "fix": (
              "Define a Content-Security-Policy (CSP) header to restrict"
              " untrusted scripts and resources."
          ),
      },
      "X-Frame-Options": {
          "risk": "Medium (I ekspozuar ndaj sulmeve Clickjacking)",
          "fix": (
              "Add 'X-Frame-Options: SAMEORIGIN' to prevent framing of your"
              " website."
          ),
      },
  }

  try:
    res = requests.get(f"https://{domain}", timeout=4)
    for header_name, info in remediation_db.items():
      if header_name in res.headers:
        headers_status[header_name] = "Present"
      else:
        headers_status[header_name] = "Missing"
        issues.append(f"Missing security header: {header_name}")
        recommendations.append({
            "header": header_name,
            "risk": info["risk"],
            "fix": info["fix"],
        })
  except Exception:
    issues.append("Could not establish HTTPS connection for header check.")

  return headers_status, issues, recommendations


def enterprise_scan(domain):
  clean_domain = (
      domain.replace("https://", "").replace("http://", "").strip().split("/")[0]
  )
  score = 100
  issues = []

  with ThreadPoolExecutor(max_workers=2) as executor:
    ssl_future = executor.submit(check_ssl, clean_domain)
    headers_future = executor.submit(check_headers, clean_domain)

    ssl_res = ssl_future.result()
    headers_res, header_issues, recommendations = headers_future.result()

  issues.extend(header_issues)

  if not ssl_res["valid"]:
    score -= 40
    issues.append("Critical: SSL/TLS certificate is missing or invalid.")
    recommendations.append({
        "header": "SSL/TLS Certificate",
        "risk": "Critical (E gjithë pamja e të dhënave udhëton e paenkriptuar)",
        "fix": (
            "Install a valid SSL certificate (e.g., via Let's Encrypt or"
            " Cloudflare) to enable HTTPS."
        ),
    })
  else:
    if ssl_res["days_left"] < 30:
      score -= 15
      issues.append(
          f"Warning: SSL certificate expires soon ({ssl_res['days_left']}"
          " days)."
      )

  score -= len(header_issues) * 15
  score = max(0, score)

  new_log = AuditLog(domain=clean_domain, score=score, issues_count=len(issues))
  db.session.add(new_log)
  db.session.commit()

  return {
      "domain": clean_domain,
      "score": score,
      "ssl": ssl_res,
      "headers": headers_res,
      "issues": issues,
      "recommendations": recommendations,
  }


@app.route("/", methods=["GET", "POST"])
def index():
  data = None
  if request.method == "POST":
    domain = request.form.get("domain")
    if domain:
      data = enterprise_scan(domain)

  history = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all()
  return render_template("index.html", data=data, history=history)


if __name__ == "__main__":
  app.run(debug=True, port=5000)

