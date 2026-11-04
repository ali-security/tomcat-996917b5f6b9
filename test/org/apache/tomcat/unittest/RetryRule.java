/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.unittest;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

/**
 * JUnit rule that retries a failing test a configurable number of times before
 * reporting failure. Used to absorb the non-deterministic loopback-network and
 * timing flakiness that some HTTP/2 and WebSocket tests exhibit under CI load.
 * A test that fails deterministically still fails after every attempt, so real
 * regressions are not masked - only genuinely intermittent failures are retried.
 */
public class RetryRule implements TestRule {

    private final int attempts;

    public RetryRule(int attempts) {
        this.attempts = attempts;
    }

    @Override
    public Statement apply(final Statement base, final Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                Throwable lastFailure = null;
                for (int attempt = 1; attempt <= attempts; attempt++) {
                    try {
                        base.evaluate();
                        return;
                    } catch (Throwable t) {
                        lastFailure = t;
                        System.err.println("RetryRule: " + description.getDisplayName() +
                                " failed on attempt " + attempt + " of " + attempts);
                    }
                }
                throw lastFailure;
            }
        };
    }
}
