"""Zero-Touch Authentifizierungs-Schicht fuer den darts-caller.

Diese Modul kapselt:

* Laden von `manifest.sig.json` (neben der EXE bzw. in `sys._MEIPASS`).
* Persistenz der `credentials.json` (instance_id / api_key / instance_nonce)
  unter `%APPDATA%\\<EXT_ID>` (Windows) bzw. `~/.config/<EXT_ID>` (POSIX),
  Dateirechte `0600` / restriktive ACL.
* Auto-Registrierung gegen `POST /api/ext/register` mit Backoff
  5s / 30s / 5min.
* Token-Refresh ueber `POST /api/ext/token` (HS256 JWT) inkl. Hintergrund-
  Thread, der spaetestens 30s vor `exp` erneuert. Bei 401/403 werden die
  lokalen Credentials geloescht und es wird neu registriert.

Es findet **keinerlei** Nutzer-Interaktion statt - weder Pair-Code noch
TOFU-Bestaetigung. Eine signierte und im Caller gelistete Extension
bekommt automatisch vollen Zugriff, alle anderen werden abgelehnt.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import platform
import socket
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse, urlunparse

import requests
import urllib3


# Caller benutzt ein self-signed Zertifikat auf 127.0.0.1; die Warnung dazu
# wuerde sonst bei jedem HTTP-Call ausgegeben.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


# Backoff-Sequenz fuer fehlgeschlagene Registrierungen (in Sekunden).
REGISTER_BACKOFF_SECONDS = (5, 30, 300)

# Transport-level exceptions that may occur if the caller has not finished
# binding its TCP listener yet (race at simultaneous startup). Only these
# exceptions are retried by `_request_with_connect_retry`; any successful
# HTTP response (including 4xx/5xx) is returned as-is.
_RETRYABLE_EXC = (
    requests.exceptions.ConnectionError,
    requests.exceptions.ConnectTimeout,
    requests.exceptions.ReadTimeout,
)

# Default total budget for the startup-safe connect retry (seconds).
DEFAULT_CONNECT_RETRY_SECONDS = 30.0

# JWT spaetestens N Sekunden vor `exp` erneuern.
TOKEN_REFRESH_MARGIN_SECONDS = 30

# Fallback-Refresh-Intervall, falls `exp` nicht ausgewertet werden kann.
TOKEN_REFRESH_FALLBACK_SECONDS = 5 * 60

DEFAULT_CALLER_URL = "https://127.0.0.1:8079"


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignedManifest:
    ext_id: str
    version: str
    sha256: str
    kid: str
    sig_b64: str

    @classmethod
    def from_dict(cls, data: dict) -> "SignedManifest":
        missing = [f for f in ("ext_id", "version", "sha256", "kid", "sig_b64") if not data.get(f)]
        if missing:
            raise ValueError(f"manifest.sig.json fehlt Pflichtfelder: {', '.join(missing)}")
        return cls(
            ext_id=str(data["ext_id"]),
            version=str(data["version"]),
            sha256=str(data["sha256"]),
            kid=str(data["kid"]),
            sig_b64=str(data["sig_b64"]),
        )


def _candidate_manifest_paths() -> list[Path]:
    """Suche-Reihenfolge fuer `manifest.sig.json`.

    1. Verzeichnis der laufenden EXE (PyInstaller-Onefile: `sys.executable`).
    2. PyInstaller-Onefile-Bundle (`sys._MEIPASS`).
    3. Verzeichnis des aufgerufenen Python-Skripts (`sys.argv[0]`).
    4. Aktuelles Arbeitsverzeichnis.
    """
    candidates: list[Path] = []
    try:
        if getattr(sys, "frozen", False):
            candidates.append(Path(sys.executable).resolve().parent)
    except Exception:
        pass

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass))

    if sys.argv and sys.argv[0]:
        try:
            candidates.append(Path(sys.argv[0]).resolve().parent)
        except Exception:
            pass

    candidates.append(Path.cwd())

    # Deduplizieren, Reihenfolge erhalten.
    seen: set[Path] = set()
    unique: list[Path] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return [p / "manifest.sig.json" for p in unique]


def load_manifest(explicit_path: Optional[str] = None) -> SignedManifest:
    """Liest `manifest.sig.json` und gibt das geparste Objekt zurueck.

    Bricht bei Fehlern hart mit `sys.exit(1)` ab.
    """
    paths: list[Path] = []
    if explicit_path:
        paths.append(Path(explicit_path))
    paths.extend(_candidate_manifest_paths())

    for path in paths:
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.error(
                "[AUTH] manifest.sig.json bei %s konnte nicht gelesen/geparst werden: %s",
                path,
                exc,
            )
            sys.exit(1)
        try:
            manifest = SignedManifest.from_dict(data)
        except ValueError as exc:
            log.error("[AUTH] manifest.sig.json bei %s ist ungueltig: %s", path, exc)
            sys.exit(1)
        log.debug("[AUTH] manifest.sig.json geladen: %s (ext_id=%s, version=%s, kid=%s)",
                 path, manifest.ext_id, manifest.version, manifest.kid)
        return manifest

    searched = "\n  - ".join(str(p) for p in paths)
    log.error(
        "[AUTH] manifest.sig.json nicht gefunden. Erwartet neben der EXE.\n"
        "  Gesuchte Pfade:\n  - %s",
        searched,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

@dataclass
class Credentials:
    instance_id: str
    api_key: str
    instance_nonce: str

    def to_dict(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "api_key": self.api_key,
            "instance_nonce": self.instance_nonce,
        }


def default_credentials_dir(ext_id: str) -> Path:
    """Liefert den plattformspezifischen Default-Pfad fuer das Credentials-Verzeichnis."""
    if os.name == "nt":
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(appdata) / ext_id
    return Path.home() / ".config" / ext_id


def _restrict_permissions(path: Path) -> None:
    """Setzt 0600 unter POSIX bzw. eine restriktive ACL unter Windows."""
    try:
        if os.name == "nt":
            # Verwende `icacls`, um Vererbung zu entfernen und nur dem
            # aktuellen Benutzer Lese-/Schreibrechte zu gewaehren.
            import subprocess
            user = os.environ.get("USERNAME") or ""
            try:
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r"],
                    check=False, capture_output=True,
                )
                if user:
                    subprocess.run(
                        ["icacls", str(path), "/grant:r", f"{user}:(R,W)"],
                        check=False, capture_output=True,
                    )
            except FileNotFoundError:
                # icacls nicht verfuegbar - tolerieren.
                pass
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        log.warning("[AUTH] Konnte Dateirechte fuer %s nicht setzen: %s", path, exc)


class CredentialsStore:
    """Liest/schreibt `credentials.json` an einem festen Pfad."""

    FILENAME = "credentials.json"

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.path = self.directory / self.FILENAME

    def load(self) -> Optional[Credentials]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            log.warning("[AUTH] credentials.json nicht lesbar (%s): %s", self.path, exc)
            return None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            log.warning("[AUTH] credentials.json ist ungueltig (%s): %s - wird ignoriert.",
                        self.path, exc)
            return None
        try:
            return Credentials(
                instance_id=str(data["instance_id"]),
                api_key=str(data["api_key"]),
                instance_nonce=str(data["instance_nonce"]),
            )
        except (KeyError, TypeError) as exc:
            log.warning("[AUTH] credentials.json unvollstaendig: %s - wird ignoriert.", exc)
            return None

    def save(self, creds: Credentials) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(creds.to_dict(), indent=2), encoding="utf-8")
        try:
            os.replace(tmp, self.path)
        except OSError:
            tmp.replace(self.path)
        _restrict_permissions(self.path)

    def delete(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return
        except OSError as exc:
            log.warning("[AUTH] credentials.json konnte nicht geloescht werden: %s", exc)

    def ensure_nonce(self) -> str:
        """Lese existierende nonce oder erzeuge eine neue UUID4 und persistiere sie sofort."""
        existing = self.load()
        if existing and existing.instance_nonce:
            return existing.instance_nonce
        nonce = str(uuid.uuid4())
        if existing:
            existing.instance_nonce = nonce
            self.save(existing)
        else:
            # Noch keine Credentials da; nonce muss separat gehalten werden,
            # bis die Registrierung erfolgreich ist. Schreibe nichts auf Disk.
            pass
        return nonce


# ---------------------------------------------------------------------------
# JWT helpers (nur fuer `exp`-Auswertung)
# ---------------------------------------------------------------------------

def _decode_jwt_exp(token: str) -> Optional[int]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(decoded)
        exp = data.get("exp")
        return int(exp) if exp is not None else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class CallerAuthError(Exception):
    """Wird fuer harte Auth-Fehler verwendet (z. B. invalid_signature)."""


class _SoftRegistrationError(CallerAuthError):
    """Transient registration / token failure (network, 5xx, 401, 429).

    The outer retry loop should keep trying with backoff.
    """


class _HardRegistrationError(CallerAuthError):
    """Permanent registration / token failure.

    Examples: invalid signature, revoked kid/version/instance,
    ext_id_not_in_registry, binary_mismatch. The user has to fix the
    extension (re-sign / update). Never retried.
    """


HARD_FAIL_ERRORS = {
    "invalid_signature",
    "ext_id_not_in_registry",
    "kid_revoked",
    "version_revoked",
    # Binary-Bind (Caller hasht die EXE des verbindenden Prozesses und
    # vergleicht mit `sha256` aus dem Manifest). Retry ist sinnlos, solange
    # Manifest und EXE auf der Platte nicht zusammenpassen.
    "binary_mismatch",
}


def _normalize_caller_url(url: str) -> str:
    """Stellt sicher, dass die URL ein Schema enthaelt; default `https://`."""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"caller-url ohne netloc: {url}")
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def caller_url_from_connection(connection: str) -> str:
    """Konvertiert einen `-CON host:port`-Wert in eine `https://`-Caller-URL."""
    if not connection:
        return DEFAULT_CALLER_URL
    return _normalize_caller_url(connection.strip())


class CallerAuthClient:
    """Kapselt Manifest, Credentials, Register-/Token-Flow und JWT-Refresh."""

    def __init__(
        self,
        manifest: SignedManifest,
        credentials_dir: Path,
        caller_url: str,
        http_session: Optional[requests.Session] = None,
        on_token_refresh: Optional[Callable[[str], None]] = None,
        connect_retry_seconds: float = DEFAULT_CONNECT_RETRY_SECONDS,
    ) -> None:
        self.manifest = manifest
        self.caller_url = _normalize_caller_url(caller_url)
        self.store = CredentialsStore(Path(credentials_dir))
        self.session = http_session or requests.Session()
        # Selbstsigniertes Caller-Cert ist erlaubt.
        self.session.verify = False
        self._on_token_refresh = on_token_refresh
        self._connect_retry_seconds = float(connect_retry_seconds)

        self._credentials: Optional[Credentials] = None
        self._jwt: Optional[str] = None
        self._jwt_exp: Optional[int] = None

        self._refresh_thread: Optional[threading.Thread] = None
        self._refresh_stop = threading.Event()
        self._refresh_lock = threading.Lock()

    # ---- public API ----------------------------------------------------

    @property
    def jwt(self) -> Optional[str]:
        return self._jwt

    @property
    def credentials(self) -> Optional[Credentials]:
        return self._credentials

    def ensure_credentials(self) -> Credentials:
        """Liefert gueltige Credentials. Registriert bei Bedarf automatisch."""
        if self._credentials is None:
            self._credentials = self.store.load()
        if self._credentials is None:
            self._credentials = self._register_with_backoff()
        return self._credentials

    def acquire_token(self) -> str:
        """Holt ein frisches JWT. Re-registriert bei 401 (transient).

        - HTTP 401 on /api/ext/token is recoverable: discard the cached
          api_key (in-memory + on disk), re-run /api/ext/register, and
          retry /api/ext/token exactly once with the new api_key.
        - HTTP 403 (kid_revoked / version_revoked / instance_revoked /
          ...) is permanent and is propagated as `_HardRegistrationError`.
        """
        creds = self.ensure_credentials()
        try:
            return self._request_token(creds)
        except _HardRegistrationError as exc:
            log.error("[auth] permanent failure: %s", exc)
            raise
        except _SoftRegistrationError as exc:
            # Per spec: only 401 on /api/ext/token triggers re-register.
            log.warning("[auth] token rejected (401), re-registering")
            self.force_reauth()
            try:
                creds = self.ensure_credentials()
            except _HardRegistrationError as hard:
                log.error("[auth] permanent failure: %s", hard)
                raise
            jwt = self._request_token(creds)
            log.info("[auth] re-registration succeeded, new api_key cached")
            return jwt

    def force_reauth(self) -> None:
        """Clear cached api_key / instance_id / JWT and delete on-disk creds.

        Does NOT touch the manifest or any signing assets. After calling
        this, the next `acquire_token()` will run the full register flow.
        Intended to be invoked by the SocketIO connect layer whenever the
        server rejects the handshake with `invalid auth token`.
        """
        self._reset_credentials()

    def start_refresh_loop(self) -> None:
        """Startet (falls noch nicht laufend) den JWT-Refresh-Hintergrund-Thread."""
        if self._refresh_thread and self._refresh_thread.is_alive():
            return
        self._refresh_stop.clear()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, name="caller-auth-refresh", daemon=True,
        )
        self._refresh_thread.start()

    def stop_refresh_loop(self) -> None:
        self._refresh_stop.set()

    def info(self) -> dict:
        """`GET /api/ext/info` (best-effort; ohne harte Fehler)."""
        try:
            resp = self.session.get(f"{self.caller_url}/api/ext/info", timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except (requests.RequestException, ValueError) as exc:
            log.debug("[AUTH] /api/ext/info fehlgeschlagen: %s", exc)
        return {}

    # ---- internals -----------------------------------------------------

    def _register_with_backoff(self) -> Credentials:
        nonce = str(uuid.uuid4())
        attempt = 0
        while True:
            try:
                creds = self._register(nonce)
                self.store.save(creds)
                log.info("[auth] registration succeeded, api_key cached")
                return creds
            except _HardRegistrationError as exc:
                log.error("[auth] permanent failure: %s", exc)
                raise
            except _SoftRegistrationError as exc:
                delay = REGISTER_BACKOFF_SECONDS[
                    min(attempt, len(REGISTER_BACKOFF_SECONDS) - 1)
                ]
                log.warning(
                    "[auth] transient failure, will retry (backoff %ss): %s",
                    delay, exc,
                )
                attempt += 1
                if self._refresh_stop.wait(delay):
                    raise
            except CallerAuthError as exc:
                # Unclassified (e.g. invalid_json from _register).
                delay = REGISTER_BACKOFF_SECONDS[
                    min(attempt, len(REGISTER_BACKOFF_SECONDS) - 1)
                ]
                log.warning(
                    "[auth] transient failure, will retry (backoff %ss): %s",
                    delay, exc,
                )
                attempt += 1
                if self._refresh_stop.wait(delay):
                    raise
            except requests.RequestException as exc:
                delay = REGISTER_BACKOFF_SECONDS[
                    min(attempt, len(REGISTER_BACKOFF_SECONDS) - 1)
                ]
                log.warning(
                    "[auth] transient failure, will retry (backoff %ss): %s",
                    delay, exc,
                )
                attempt += 1
                if self._refresh_stop.wait(delay):
                    raise

    def _request_with_connect_retry(self, method: str, url: str, **kwargs):
        """Issue an HTTP request and retry only on transport-level errors.

        Tolerates a short startup window where the caller's TCP listener
        is not yet bound (e.g. when caller and extensions are launched
        simultaneously). Any successful HTTP response (including 4xx/5xx)
        is returned to the caller unchanged. Only `_RETRYABLE_EXC`
        exceptions trigger a retry; all other exceptions propagate.
        """
        deadline = time.monotonic() + self._connect_retry_seconds
        backoff = 0.5
        attempt = 0
        last_exc: Optional[BaseException] = None
        while True:
            attempt += 1
            try:
                return self.session.request(method, url, **kwargs)
            except _RETRYABLE_EXC as exc:
                last_exc = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    log.error(
                        "[auth] connect deadline reached after %.0fs: %s",
                        self._connect_retry_seconds, exc,
                    )
                    raise CallerAuthError(
                        f"connect deadline reached after "
                        f"{self._connect_retry_seconds:.0f}s: {exc}"
                    ) from exc
                wait = min(backoff, 2.0, remaining)
                log.warning(
                    "[auth] caller not reachable yet "
                    "(attempt %d, retry in %.1fs): %s",
                    attempt, wait, exc,
                )
                # Cooperative wait: stops early if shutdown is requested.
                if self._refresh_stop.wait(wait):
                    # Treat shutdown as the final failure for this call.
                    raise CallerAuthError(
                        f"connect aborted after {attempt} attempt(s): "
                        f"{last_exc}"
                    ) from last_exc
                backoff *= 1.5

    def _register(self, nonce: str) -> Credentials:
        body = {
            "ext_id":         self.manifest.ext_id,
            "version":        self.manifest.version,
            "sha256":         self.manifest.sha256,
            "kid":            self.manifest.kid,
            "sig_b64":        self.manifest.sig_b64,
            "instance_nonce": nonce,
            "client_info": {
                "host": socket.gethostname(),
                "os":   platform.platform(),
            },
        }
        url = f"{self.caller_url}/api/ext/register"
        log.debug("[AUTH] POST %s (ext_id=%s, version=%s)",
                  url, self.manifest.ext_id, self.manifest.version)
        resp = self._request_with_connect_retry("POST", url, json=body, timeout=10)
        if resp.status_code == 200:
            try:
                payload = resp.json()
            except ValueError as exc:
                raise CallerAuthError(f"register: invalid_json:{exc}")
            try:
                return Credentials(
                    instance_id=str(payload["instance_id"]),
                    api_key=str(payload["api_key"]),
                    instance_nonce=nonce,
                )
            except KeyError as exc:
                raise CallerAuthError(f"register: missing_field:{exc}")
        # Error path. Per spec: 401/429/5xx are transient (soft), every
        # other 4xx is permanent (hard). A soft register failure is
        # distinct from a soft token failure in `acquire_token` -- here
        # it means "keep retrying with backoff".
        try:
            err = resp.json().get("error", f"http_{resp.status_code}")
        except ValueError:
            err = f"http_{resp.status_code}"
        status = resp.status_code
        if err in HARD_FAIL_ERRORS:
            raise _HardRegistrationError(err)
        if status == 401 or status == 429 or 500 <= status < 600:
            raise _SoftRegistrationError(err)
        if 400 <= status < 500:
            raise _HardRegistrationError(err)
        # Anything else: be conservative and treat as soft.
        raise _SoftRegistrationError(err)

    def _request_token(self, creds: Credentials) -> str:
        url = f"{self.caller_url}/api/ext/token"
        headers = {"Authorization": f"Bearer {creds.api_key}"}
        resp = self._request_with_connect_retry(
            "POST", url, json={}, headers=headers, timeout=10,
        )
        if resp.status_code == 200:
            try:
                payload = resp.json()
                jwt = str(payload["jwt"])
            except (ValueError, KeyError) as exc:
                raise CallerAuthError(f"token: invalid_response:{exc}")
            with self._refresh_lock:
                self._jwt = jwt
                exp = payload.get("exp")
                self._jwt_exp = int(exp) if exp is not None else _decode_jwt_exp(jwt)
            if self._on_token_refresh:
                try:
                    self._on_token_refresh(jwt)
                except Exception as exc:  # callback darf den Auth-Loop nicht killen
                    log.debug("[AUTH] on_token_refresh callback hat geworfen: %s", exc)
            return jwt
        if resp.status_code == 401:
            # Transient: cached api_key is no longer valid (caller restart
            # with rotated jwt-secret, deleted extensions.json, ...).
            raise _SoftRegistrationError("invalid_auth_token")
        if resp.status_code == 403:
            # Permanent: kid/version/instance revoked or similar.
            try:
                err = resp.json().get("error", "forbidden")
            except ValueError:
                err = "forbidden"
            raise _HardRegistrationError(err)
        try:
            err = resp.json().get("error", f"http_{resp.status_code}")
        except ValueError:
            err = f"http_{resp.status_code}"
        raise CallerAuthError(err)

    def _reset_credentials(self) -> None:
        self.store.delete()
        with self._refresh_lock:
            self._credentials = None
            self._jwt = None
            self._jwt_exp = None

    def _refresh_loop(self) -> None:
        while not self._refresh_stop.is_set():
            with self._refresh_lock:
                exp = self._jwt_exp
            if exp is None:
                wait = TOKEN_REFRESH_FALLBACK_SECONDS
            else:
                wait = max(5, exp - int(time.time()) - TOKEN_REFRESH_MARGIN_SECONDS)
            if self._refresh_stop.wait(wait):
                return
            try:
                self.acquire_token()
                log.debug("[AUTH] JWT erneuert.")
            except CallerAuthError as exc:
                log.warning("[AUTH] JWT-Refresh fehlgeschlagen: %s", exc)
                # Backoff im naechsten Loop-Durchgang via Fallback-Wait.
                with self._refresh_lock:
                    self._jwt_exp = None
            except requests.RequestException as exc:
                log.warning("[AUTH] Caller fuer JWT-Refresh nicht erreichbar: %s", exc)
                with self._refresh_lock:
                    self._jwt_exp = None
