from ai_security_range.security import permissions


def test_minimal_set():
    r = permissions.check(["calendar.read", "email.send"], ["calendar.read", "email.send"])
    assert r.minimal and not r.over_grants and not r.missing


def test_over_grant():
    r = permissions.check(["calendar.read", "email.send"],
                          ["calendar.read", "email.send", "calendar.write"])
    assert not r.minimal and r.over_grants == ["calendar.write"]


def test_under_grant():
    r = permissions.check(["photos.read", "storage.write"], ["photos.read"])
    assert not r.minimal and r.missing == ["storage.write"]
