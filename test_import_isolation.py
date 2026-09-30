"""Prove test module cannot inherit an already-imported production app."""
import app
import test_safety
assert test_safety.upstream is not app, 'Safety tests reused the production app singleton'
assert test_safety.upstream.DEFAULT_CONFIG_FILE == str(test_safety.MAIN), 'Tests can reach production main configuration'
assert test_safety.upstream.DEFAULT_CONFIG_DIR == str(test_safety.CONF / 'unbound.conf.d') + '/'
print('TEST IMPORT ISOLATION PASS')
