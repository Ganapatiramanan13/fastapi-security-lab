"""
Focused regression test for the weak-JWT exploit's baseline reporting.

exploits/exploit_weak_jwt.py must only claim Alice's legitimate token
"correctly got 403" from /admin when that response really was 403. If an
earlier demonstration (the mass-assignment exploit) has already promoted
Alice to admin in the vulnerable database, her legitimate token would
instead receive 200, and the script must NOT make the false claim — it
must warn that the baseline is unexpected and that the database needs
reseeding.

These tests exercise describe_baseline() directly. It is a pure function
of the HTTP status code, so no live server, no network, and no database
access is involved: importing the exploit module has no side effects (its
main() runs only under __main__), which is why this file deliberately does
NOT import vulnerable_app or use TestClient — running it cannot touch or
reset the real SQLite databases.
"""

from exploits.exploit_weak_jwt import (
    EXPECTED_BASELINE_STATUS,
    EXPECTED_SUB1_STATUS,
    describe_baseline,
    describe_sub1_note,
)

# The exact phrase that must never be printed unless the baseline truly held.
FALSE_CLAIM = "correctly got 403"
RESEED_COMMAND = "python -m vulnerable_app.seed_data"
# The sub="1" NOTE's false claim: that the forged token resolves to the
# ordinary "user" role. It must only appear on an actual 403.
SUB1_FALSE_CLAIM = 'resolves to Alice\'s\nreal DB role ("user"), and correctly gets 403'


class TestWeakJwtBaseline:
    """REGRESSION: the baseline claim must track the real status code."""

    def test_403_baseline_reports_success(self):
        """A genuine 403 baseline is allowed to make the 'correctly got 403' claim."""
        ok, message = describe_baseline(EXPECTED_BASELINE_STATUS)
        assert ok is True
        assert FALSE_CLAIM in message

    def test_200_baseline_suppresses_false_claim(self):
        """
        Alice already promoted to admin -> her legitimate token gets 200.
        The script must not claim she "correctly got 403"; it must warn and
        tell the user to reseed.
        """
        ok, message = describe_baseline(200)
        assert ok is False
        assert FALSE_CLAIM not in message
        assert "WARNING" in message
        assert "200" in message
        assert RESEED_COMMAND in message

    def test_other_unexpected_status_also_warns(self):
        """Any non-403 status is treated as an invalid baseline, not a pass."""
        ok, message = describe_baseline(401)
        assert ok is False
        assert FALSE_CLAIM not in message
        assert RESEED_COMMAND in message


class TestWeakJwtSub1Note:
    """REGRESSION: the sub="1" forged-token NOTE must track the real status."""

    def test_403_note_makes_user_role_claim(self):
        """A genuine 403 lets the NOTE explain the role-from-DB behavior."""
        as_expected, message = describe_sub1_note(EXPECTED_SUB1_STATUS)
        assert as_expected is True
        assert SUB1_FALSE_CLAIM in message

    def test_200_note_suppresses_user_role_claim(self):
        """
        Alice promoted to admin -> the sub="1" token is admitted with 200.
        The NOTE must not claim it resolves to "user" / correctly gets 403;
        it must describe the observed status and point to reseeding.
        """
        as_expected, message = describe_sub1_note(200)
        assert as_expected is False
        assert SUB1_FALSE_CLAIM not in message
        assert "200" in message
        assert RESEED_COMMAND in message

    def test_other_status_also_warns(self):
        """Any non-403 status suppresses the claim and warns."""
        as_expected, message = describe_sub1_note(401)
        assert as_expected is False
        assert SUB1_FALSE_CLAIM not in message
        assert RESEED_COMMAND in message
