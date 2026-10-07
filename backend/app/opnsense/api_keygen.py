"""Generate an OPNsense API key over SSH.

OPNsense has no CLI to create API keys, so we run a small PHP snippet on the
firewall that mirrors the GUI: it appends a new key/secret pair (secret stored
hashed) to the target user's ``apikeys`` and writes the configuration. The
plaintext key/secret are printed once and captured immediately.
"""
from __future__ import annotations

import base64
import logging
import re

from .ssh import OPNsenseSSH, SSHError

logger = logging.getLogger("opnsense.apikeygen")

_KEY_RE = re.compile(r"^KEY=(\S+)$", re.M)
_SECRET_RE = re.compile(r"^SECRET=(\S+)$", re.M)

_PHP = r"""<?php
require_once('config.inc');
require_once('util.inc');
global $config;
$name = 'root';
$rand = function ($n) {
    return rtrim(strtr(base64_encode(random_bytes($n)), '+/', '-_'), '=');
};
$key = $rand(24);
$secret = $rand(24);
$salt = rtrim(strtr(base64_encode(random_bytes(9)), '+/', './'), '=');
$hash = crypt($secret, '$6$' . $salt . '$');
$found = false;
if (!isset($config['system']['user']) || !is_array($config['system']['user'])) {
    $config['system']['user'] = array();
}
foreach ($config['system']['user'] as $i => $u) {
    if (isset($u['name']) && $u['name'] === $name) {
        if (!isset($config['system']['user'][$i]['apikeys']['item'])) {
            $config['system']['user'][$i]['apikeys']['item'] = array();
        }
        $config['system']['user'][$i]['apikeys']['item'][] = array(
            'key' => $key,
            'secret' => $hash,
            'descr' => 'OPNsense_log',
        );
        $found = true;
        break;
    }
}
if (!$found) {
    fwrite(STDERR, "user not found\n");
    exit(1);
}
write_config('API key created by OPNsense Log Analyzer');
echo "KEY=" . $key . "\n";
echo "SECRET=" . $secret . "\n";
"""


def generate_api_key(username: str = "root") -> dict:
    """Create an OPNsense API key for ``username`` over SSH.

    Returns ``{"ok": bool, "key"?, "secret"?, "error"?}``.
    """
    script = _PHP.replace("$name = 'root';", f"$name = '{username}';")
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    command = (
        "sh -c 'echo " + encoded + " | base64 -d > /tmp/ola_apikey.php; "
        "cd /usr/local/etc/inc && /usr/local/bin/php /tmp/ola_apikey.php; "
        "rm -f /tmp/ola_apikey.php'"
    )
    try:
        ssh = OPNsenseSSH()
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
