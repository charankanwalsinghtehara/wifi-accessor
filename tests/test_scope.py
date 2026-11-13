from security.scope_validator import ScopeValidator

def test_allowed_domain_scope() -> None:
    validator = ScopeValidator()
    assert validator.validate_scope('website', 'example.com', {}) is True

def test_allowed_network_scope() -> None:
    validator = ScopeValidator()
    assert validator.validate_scope('network', '10.0.0.0/24', {}) is True

def test_rejects_out_of_scope_target() -> None:
    validator = ScopeValidator()
    assert validator.validate_scope('website', 'unauthorized.example.net', {}) is False
