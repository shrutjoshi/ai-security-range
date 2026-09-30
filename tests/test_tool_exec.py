from ai_security_range.models import ToolCall
from ai_security_range.security import tool_exec


def v(tool, args=None, parameterized=False):
    return tool_exec.classify(ToolCall(tool=tool, args=args or {}, parameterized=parameterized))


def test_fixed_shell_is_safe():
    assert v("shell.run").safe


def test_command_injection():
    r = v("shell.run", {"host": "8.8.8.8; cat /etc/passwd"})
    assert not r.safe and r.attack == "Command injection"


def test_sql_injection():
    r = v("db.query", {"id": "42 OR 1=1; DROP TABLE orders"})
    assert not r.safe and r.attack == "SQL injection"


def test_parameterized_sql_is_safe():
    assert v("db.query", {"sku": "ABALONE-12"}, parameterized=True).safe


def test_path_traversal():
    r = v("fs.read", {"name": "../../../../etc/shadow"})
    assert not r.safe and r.attack == "Path traversal"


def test_ssrf_metadata_endpoint():
    r = v("http.fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
    assert not r.safe and r.attack == "SSRF"


def test_public_url_is_safe():
    assert v("http.fetch", {"url": "https://api.example.com/v1/data"}).safe
