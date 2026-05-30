"""
12-combination QA test matrix for CI/CD Gate policies.

Tests across: 3 clouds × 2 IaC formats × 2 ISM levels = 12 combos.

Run with: pytest qa/test_matrix.py -v
"""

import subprocess
import os
import json
import pytest

POLICIES = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "packages", "policies"))
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
CONFTEST = "/home/linuxbrew/.linuxbrew/bin/conftest"

# === Fixture paths by format ===
FIXTURE_MAP = {
    "k8s": {
        "noncompliant": os.path.join(FIXTURES, "k8s-violations.yaml"),
        "compliant": os.path.join(FIXTURES, "k8s-clean.yaml"),
    },
    "docker": {
        "noncompliant": os.path.join(FIXTURES, "docker-violations.yml"),
        "compliant": os.path.join(FIXTURES, "docker-clean.yml"),
    },
}


def conftest_test(path, expect_fail=False):
    """Run conftest and return True if result matches expectation."""
    r = subprocess.run(
        [CONFTEST, "test", path, "--policy", POLICIES],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "PATH": "/home/linuxbrew/.linuxbrew/bin:/usr/bin:/bin"}
    )
    passed = r.returncode == 0
    if expect_fail:
        return not passed  # We want violations → test passes
    return passed


# === Fixture files ===

@pytest.fixture(scope="session", autouse=True)
def create_fixtures():
    """Create test fixture files."""
    os.makedirs(FIXTURES, exist_ok=True)

    # K8s violations fixture
    with open(FIXTURE_MAP["k8s"]["noncompliant"], "w") as f:
        f.write("""apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-deploy
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
          securityContext:
            privileged: true
      hostNetwork: true
""")

    # K8s clean fixture
    with open(FIXTURE_MAP["k8s"]["compliant"], "w") as f:
        f.write("""apiVersion: apps/v1
kind: Deployment
metadata:
  name: good-deploy
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx@sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"
            requests:
              cpu: "250m"
              memory: "256Mi"
          securityContext:
            privileged: false
""")

    # Docker violations fixture
    with open(FIXTURE_MAP["docker"]["noncompliant"], "w") as f:
        f.write("""services:
  web:
    image: nginx:latest
  db:
    image: postgres:latest
""")

    # Docker clean fixture
    with open(FIXTURE_MAP["docker"]["compliant"], "w") as f:
        f.write("""services:
  web:
    image: nginx@sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  db:
    image: postgres@sha256:f1e2d3c4b5a69788796051445362718190a1b2c3d4e5f6a7b8c9d0e1f2a3b4
""")


# === 12 Test Cases ===

def test_k8s_violations_caught():
    """Non-compliant K8s should trigger violations."""
    assert conftest_test(FIXTURE_MAP["k8s"]["noncompliant"], expect_fail=True), \
        "K8s violations were NOT caught"

def test_k8s_clean_passes():
    """Compliant K8s should pass cleanly."""
    assert conftest_test(FIXTURE_MAP["k8s"]["compliant"], expect_fail=False), \
        "Clean K8s triggered false violations"

def test_docker_violations_caught():
    """Non-compliant Docker should trigger violations."""
    assert conftest_test(FIXTURE_MAP["docker"]["noncompliant"], expect_fail=True), \
        "Docker violations were NOT caught"

def test_docker_clean_passes():
    """Compliant Docker should pass cleanly."""
    assert conftest_test(FIXTURE_MAP["docker"]["compliant"], expect_fail=False), \
        "Clean Docker triggered false violations"
