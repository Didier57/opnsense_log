"""Generate an OPNsense API key over SSH.

OPNsense has no CLI to create API keys, so we run a small PHP snippet on the
firewall that mirrors the GUI exactly: it uses the ``OPNsense\\Auth\\User`` MVC
model, calls ``apikeys->add()`` (which stores the secret hashed), persists the
configuration and prints the plaintext key/secret once. The SSH connection is
built from the runtime settings saved in the web UI (not the env defaults).
"""
from __future__ import annotations

import base64
import logging
import re

from .settings_store import get_opnsense_settings
from .ssh import OPNsenseSSH, SSHError

logger = logging.getLogger("opnsense.apikeygen")

_KEY_RE = re.compile(r"^KEY=(\S+)$", re.M)
_SECRET_RE = re.compile(r"^SECRET=(\S+)$", re.M)
_USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]+")

_PHP = r"""<?php
require_once('config.inc');
$model = new \OPNsense\Auth\User();
$user = $model->getUserByName('__USERNAME__');
if ($user === null) {
    fwrite(STDERR, "user not found\n");
    exit(1);
}
$tmp = $user->apikeys->add();
if (empty($tmp) || empty($tmp['key']) || empty($tmp['secret'])) {
    fwrite(STDERR, "could not create key\n");
    exit(1);
}
$model->serializeToConfig(false, true);
\OPNsense\Core\Config::getInstance()->save();
echo "KEY=" . $tmp['key'] . "\n";
echo "SECRET=" . $tmp['secret'] . "\n";
"""


def _build_ssh() -> OPNsenseSSH:
    cfg = get_opnsense_settings(mask_password=False)
    return OPNsenseSSH(
        host=cfg["opnsense_host"],
        port=cfg["opnsense_ssh_port"],
        username=cfg["opnsense_username"],
        auth_type=cfg["opnsense_auth_type"],
        password=cfg.get("opnsense_password"),
        key_path=cfg["opnsense_key_path"],
    )


def generate_api_key(username: str = "root") -> dict:
    """Create an OPNsense API key for ``username`` over SSH.

    Returns ``{"ok": bool, "key"?, "secret"?, "error"?}``.
    """
    safe_username = username if _USERNAME_RE.fullmatch(username or "") else "root"
    script = _PHP.replace("__USERNAME__", safe_username)
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    command = (
        "sh -c 'echo " + encoded + " | base64 -d > /tmp/ola_apikey.php; "
        "cd /usr/local/etc/inc && /usr/local/bin/php /tmp/ola_apikey.php; "
        "rm -f /tmp/ola_apikey.php'"
    )
    try:
        ssh = _build_ssh()
        output = ssh.run(command)
    except SSHError as exc:
        logger.warning("API key generation failed: %s", exc)
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("API key generation error")
        return {"ok": False, "error": str(exc)}

    key_match = _KEY_RE.search(output)
    secret_match = _SECRET_RE.search(output)
    if not key_match or not secret_match:
        return {"ok": False, "error": "Could not read the generated API key"}
    return {"ok": True, "key": key_match.group(1), "secret": secret_match.group(1)}
