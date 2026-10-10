from app.opnsense import api_keygen as ak


class _FakeSSH:
    def run_capture(self, command: str):
        return "KEY=abc123\nSECRET=secret456\n", ""


def test_generate_api_key_threads_instance(monkeypatch):
    seen = {}

    def fake_build(instance_id=None):
        seen["instance_id"] = instance_id
        return _FakeSSH()

    monkeypatch.setattr(ak, "_build_ssh", fake_build)
    result = ak.generate_api_key("root", instance_id="inst42")
    assert result == {"ok": True, "key": "abc123", "secret": "secret456"}
    assert seen["instance_id"] == "inst42"


def test_build_ssh_uses_instance(monkeypatch):
    seen = {}

    def fake_get(mask_password=True, instance_id=None):
        seen["instance_id"] = instance_id
        return {
            "opnsense_host": "fw.example",
            "opnsense_ssh_port": 22,
            "opnsense_username": "root",
            "opnsense_auth_type": "password",
            "opnsense_password": "p",
            "opnsense_key_path": "",
        }

    monkeypatch.setattr(ak, "get_opnsense_settings", fake_get)
    ak._build_ssh("inst7")
    assert seen["instance_id"] == "inst7"
