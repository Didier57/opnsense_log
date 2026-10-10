"""Generate an OPNsense API key over SSH.

OPNsense has no CLI to create API keys, so we run a small PHP snippet on the
firewall that mirrors the GUI: it appends a new ``key|hashed-secret`` pair to the
target user's ``apikeys`` and persists the configuration with ``write_config``.
The plaintext key/secret are printed once and captured immediately; the script
also verifies that the key landed in ``/conf/config.xml``. The SSH connection is
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
require_once('util.inc');
global $config;
$name = '__USERNAME__';
$key = rtrim(strtr(base64_encode(random_bytes(60)), '+/', '-_'), '=');
$secret = rtrim(strtr(base64_encode(random_bytes(60)), '+/', '-_'), '=');
$chars = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
$salt = '';
for ($i = 0; $i < 16; $i++) {
    $salt .= $chars[random_int(0, strlen($chars) - 1)];
}
$hash = crypt($secret, '$6$' . $salt . '$');
$found = false;
if (isset($config['system']['user']) && is_array($config['system']['user'])) {
    foreach ($config['system']['user'] as $i => $u) {
        if (isset($u['name']) && $u['name'] === $name) {
            $existing = isset($config['system']['user'][$i]['apikeys']) ? $config['system']['user'][$i]['apikeys'] : array();
            $items = array();
            if (is_array($existing) && isset($existing['item'])) {
                $items = $existing['item'];
            } elseif (is_string($existing)) {
                foreach (explode("\n", $existing) as $line) {
                    $line = trim($line);
                    if ($line === '') { continue; }
                    $p = explode('|', $line, 2);
                    $items[] = array('key' => $p[0], 'secret' => isset($p[1]) ? $p[1] : '');
                }
            }
            $items[] = array('key' => $key, 'secret' => $hash);
            $config['system']['user'][$i]['apikeys'] = array('item' => $items);
            $found = true;
            break;
        }
    }
}
if (!$found) {
    fwrite(STDERR, "user not found\n");
    exit(1);
}
write_config('API key created by OPNsense Log Analyzer');
$saved = @file_get_contents('/conf/config.xml');
if ($saved === false || strpos($saved, $key) === false) {
    fwrite(STDERR, "config verification failed\n");
    exit(2);
}
echo "KEY=" . $key . "\n";
echo "SECRET=" . $secret . "\n";
"""


def _build_ssh(instance_id: str | None = None) -> OPNsenseSSH:
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance_id)
    return OPNsenseSSH(
        host=cfg["opnsense_host"],
        port=cfg["opnsense_ssh_port"],
        username=cfg["opnsense_username"],
        auth_type=cfg["opnsense_auth_type"],
        password=cfg.get("opnsense_password"),
        key_path=cfg["opnsense_key_path"],
    )


def generate_api_key(username: str = "root", instance_id: str | None = None) -> dict:
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
        ssh = _build_ssh(instance_id)
        output, stderr = ssh.run_capture(command)
    except SSHError as exc:
        logger.warning("API key generation failed: %s", exc)
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("API key generation error")
        return {"ok": False, "error": str(exc)}

    key_match = _KEY_RE.search(output)
    secret_match = _SECRET_RE.search(output)
    if not key_match or not secret_match:
        detail = (stderr.strip() or output.strip())[:400]
        logger.warning("API key generation output: %s", detail)
        return {"ok": False, "error": f"Could not read the generated API key: {detail}"}
    if stderr.strip():
        logger.warning("API key generation warnings: %s", stderr.strip()[:400])
    return {"ok": True, "key": key_match.group(1), "secret": secret_match.group(1)}
