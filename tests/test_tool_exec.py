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


# --- bypass regressions (hard Breaker round) -------------------------------


def test_newline_command_injection():
    r = v("shell.run", {"host": "8.8.8.8\nid"})
    assert not r.safe and r.attack == "Command injection"


def test_plain_shell_argument_is_safe():
    assert v("shell.run", {"host": "8.8.8.8"}).safe


def test_ssrf_obfuscated_hosts():
    for url in (
        "http://2852039166/latest/meta-data/",  # decimal 169.254.169.254
        "http://127.1/admin",
        "http://0x7f.0.0.1/",
        "http://localhost:8080/admin",
        "http://metadata.google.internal/computeMetadata/v1/",
        "169.254.169.254/latest/meta-data/",  # no scheme
        "http://[::ffff:169.254.169.254]/",
    ):
        r = v("http.fetch", {"url": url})
        assert not r.safe and r.attack == "SSRF", url


def test_numeric_looking_public_host_is_safe():
    assert v("http.fetch", {"url": "https://8.8.8.8/dns-query"}).safe
    assert v("http.fetch", {"url": "https://123.example.com/"}).safe


def test_absolute_path_is_traversal():
    r = v("fs.read", {"name": "/etc/passwd"})
    assert not r.safe and r.attack == "Path traversal"


def test_encoded_traversal():
    r = v("fs.read", {"name": "..%2f..%2fetc%2fpasswd"})
    assert not r.safe and r.attack == "Path traversal"


def test_relative_filename_with_dots_is_safe():
    assert v("fs.read", {"name": "reports/q3..final.csv"}).safe


def test_tool_family_uses_whole_tokens():
    # "push", "shared", "hash" contain "sh"; "thread" contains "read".
    assert v("git.push", {"msg": "fix; cleanup"}).safe
    assert v("crypto.hash", {"data": "a|b"}).safe
    assert not v("fs.read_shared", {"name": "../x"}).safe
