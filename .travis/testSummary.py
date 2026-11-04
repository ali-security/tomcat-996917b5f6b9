#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prints the JUnit results of "ant test" to stdout: one line per test suite,
# per-connector and overall totals, and every skipped test with its reason.
# antTest.sh sends the ant output itself to ant-test.log, so without this the
# CI log would carry no test counts at all.

import glob
import os
import re
import sys

LOG_DIR = sys.argv[1] if len(sys.argv) > 1 else "output/build/logs"
SUMMARY = re.compile(
    r"Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)")


def source_reason(cls, method):
    """Reason for a skip that JUnit reported without a message."""
    path = os.path.join("test", cls.replace(".", "/") + ".java")
    if not os.path.exists(path):
        return "no message; source " + path + " not found"
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    base = re.sub(r"\[.*\]$", "", method or "")
    decl = None
    if base:
        for i, line in enumerate(lines):
            if re.search(r"\bvoid\s+" + re.escape(base) + r"\s*\(", line):
                decl = i
                break
    if decl is not None:
        # @Ignore (and a comment explaining it) just above the method
        for j in range(decl - 1, max(-1, decl - 8), -1):
            if "@Ignore" in lines[j]:
                ctx = [l.strip() for l in lines[max(0, j - 3):j + 1]
                       if l.strip().startswith(("//", "*", "/*", "@Ignore"))]
                return "method @Ignore in source: " + " ".join(ctx)
        # an assumption inside the method body
        for j in range(decl, min(len(lines), decl + 60)):
            if "Assume." in lines[j]:
                return "assumption in source: " + lines[j].strip()
            if j > decl and re.match(r"\s{4}}\s*$", lines[j]):
                break
    for i, line in enumerate(lines):
        if line.strip().startswith("@Ignore"):
            ctx = [l.strip() for l in lines[max(0, i - 3):i + 1]
                   if l.strip().startswith(("//", "*", "/*", "@Ignore"))]
            return "@Ignore in source: " + " ".join(ctx)
    for line in lines:
        if "Assume." in line:
            return "assumption in source: " + line.strip()
    return "no reason given in source"


def main():
    files = sorted(glob.glob(os.path.join(LOG_DIR, "TEST-*.txt")))
    totals = {}
    skips = []
    print("==================== JUnit per-suite results ====================")
    for f in files:
        name = os.path.basename(f)[len("TEST-"):-len(".txt")]
        connector = name.rsplit(".", 1)[-1] if name.rsplit(".", 1)[-1] in (
            "NIO", "NIO2", "APR") else "OTHER"
        cls = name[:-(len(connector) + 1)] if connector != "OTHER" else name
        text = open(f, encoding="utf-8", errors="replace").read()
        m = SUMMARY.search(text)
        if not m:
            print("NO SUMMARY  " + name)
            continue
        run, fail, err, skip = (int(x) for x in m.groups())
        t = totals.setdefault(connector, [0, 0, 0, 0, 0])
        t[0] += 1
        t[1] += run
        t[2] += fail
        t[3] += err
        t[4] += skip
        print("%-90s Tests run: %d, Failures: %d, Errors: %d, Skipped: %d"
              % (name, run, fail, err, skip))
        last = None
        for line in text.splitlines():
            if line.startswith("Testcase: "):
                last = line[len("Testcase: "):].split(" took ")[0].strip()
            elif line.startswith("\tSKIPPED"):
                msg = line[len("\tSKIPPED"):].lstrip(":").strip()
                method = last.split("(")[0] if last else ""
                if not msg or msg in ("null", "got: <false>, expected: is <true>"):
                    msg = (msg + "; " if msg else "") + source_reason(cls, method)
                skips.append((name, last or "(class)", msg))
    print()
    print("==================== Skipped tests (with reasons) ====================")
    for name, case, msg in skips:
        print("SKIPPED %s :: %s -- %s" % (name, case, msg))
    print()
    print("==================== JUnit totals ====================")
    g = [0, 0, 0, 0, 0]
    for connector in sorted(totals):
        t = totals[connector]
        print("%-6s suites: %d, tests run: %d, passed: %d, failures: %d, errors: %d, skipped: %d"
              % (connector, t[0], t[1], t[1] - t[2] - t[3] - t[4], t[2], t[3], t[4]))
        g = [a + b for a, b in zip(g, t)]
    print("TOTAL  suites: %d, tests run: %d, passed: %d, failures: %d, errors: %d, skipped: %d"
          % (g[0], g[1], g[1] - g[2] - g[3] - g[4], g[2], g[3], g[4]))


if __name__ == "__main__":
    main()
