#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Zero-Dependency Standalone Test Runner for VCF Enterprise MCP Control Plane.
Runs all in-memory unit tests using standard library unittest.
Usage:
    python run_tests.py
"""

import sys
import os
import unittest

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(base_dir, "src")
    sys.path.insert(0, src_dir)
    sys.path.insert(0, base_dir)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(base_dir, "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    sys.exit(0 if result.wasSuccessful() else 1)
