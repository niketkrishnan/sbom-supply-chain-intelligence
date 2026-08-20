from sbom import Component


def test_public_entry_point_imports():
    assert Component is not None
