from experiments.compare_verification import run


def test_six_comparison_scenarios():
    observed = run()
    expected = {
        'Active trusted': (True, True, True),
        'Revoked': (True, True, False),
        'Untrusted issuer': (True, True, False),
        'Altered claim': (False, False, False),
        'Expired': (True, True, False),
        'Mismatched anchor issuer': (True, True, False),
    }
    assert {c['case']: (c['digest_only'], c['signature_only'], c['educhaintrust']) for c in observed['cases']} == expected
