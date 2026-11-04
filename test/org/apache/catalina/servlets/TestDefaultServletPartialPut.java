/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.servlets;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import javax.servlet.ServletContext;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Session;
import org.apache.catalina.Wrapper;
import org.apache.catalina.session.FileStore;
import org.apache.catalina.session.PersistentManager;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests for the handling of the temporary file used to process a partial PUT
 * (CVE-2025-24813). The temporary file must not be named after the request
 * path (so different, path equivalent, resources can not share it and an
 * attacker can not control its name) and it must not be left behind once the
 * request has been processed.
 */
public class TestDefaultServletPartialPut extends TomcatBaseTest {

    private static final String SECRET = "This is security sensitive content";
    private static final String INJECTED = "This is content injected by an attacker";
    private static final String TEMP_FILE_PREFIX = "put-part-";

    private File tempDocBase;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        tempDocBase = Files.createTempDirectory(getTemporaryDirectory().toPath(), "partialput").toFile();
        addDeleteOnTearDown(tempDocBase);
    }


    /*
     * A security sensitive file is uploaded with partial PUT to a sub-directory
     * (/secret/data.txt). An attacker then uses partial PUT for the path
     * equivalent resource in the parent directory (/secret.data.txt) to try and
     * read the sensitive content via the shared temporary file.
     */
    @Test
    public void testPathEquivalentPartialPutCannotReadContent() throws Exception {
        Context ctxt = startServer(null);
        Assert.assertTrue(new File(tempDocBase, "secret").mkdirs());

        byte[] secret = SECRET.getBytes(StandardCharsets.ISO_8859_1);
        Assert.assertEquals(HttpURLConnection.HTTP_CREATED, partialPut("/secret/data.txt", secret.length, secret));

        // Attacker only provides the first byte, the rest is taken from the
        // temporary file
        byte[] attack = "X".getBytes(StandardCharsets.ISO_8859_1);
        Assert.assertEquals(HttpURLConnection.HTTP_CREATED, partialPut("/secret.data.txt", secret.length, attack));

        String leaked = get("/secret.data.txt");
        Assert.assertEquals(secret.length, leaked.length());
        Assert.assertEquals('X', leaked.charAt(0));
        Assert.assertFalse("Sensitive content disclosed via partial PUT temporary file",
                leaked.contains(SECRET.substring(1)));

        // The sensitive resource itself is unchanged
        Assert.assertEquals(SECRET, get("/secret/data.txt"));

        assertNoPartialPutTempFiles(ctxt, ".secret.data.txt");
    }


    /*
     * An attacker uses partial PUT for /secret.data.txt to plant content in the
     * temporary file. A partial PUT for the path equivalent, security sensitive,
     * resource /secret/data.txt must not pick up that content.
     */
    @Test
    public void testPathEquivalentPartialPutCannotInjectContent() throws Exception {
        Context ctxt = startServer(null);
        Assert.assertTrue(new File(tempDocBase, "secret").mkdirs());

        byte[] injected = INJECTED.getBytes(StandardCharsets.ISO_8859_1);
        Assert.assertEquals(HttpURLConnection.HTTP_CREATED, partialPut("/secret.data.txt", injected.length, injected));

        // First part of a security sensitive file
        byte[] firstPart = "OK".getBytes(StandardCharsets.ISO_8859_1);
        Assert.assertEquals(HttpURLConnection.HTTP_CREATED, partialPut("/secret/data.txt", injected.length, firstPart));

        String content = get("/secret/data.txt");
        Assert.assertEquals(injected.length, content.length());
        Assert.assertTrue(content.startsWith("OK"));
        Assert.assertFalse("Attacker content injected via partial PUT temporary file",
                content.contains(INJECTED.substring(firstPart.length)));

        assertNoPartialPutTempFiles(ctxt, ".secret.data.txt");
    }


    /*
     * With file based session persistence using the default location, a
     * partial PUT for /<name>.session must not be able to create a session file
     * that the session store will then deserialize.
     */
    @Test
    public void testPartialPutCannotCreateSessionFile() throws Exception {
        FileStore store = new FileStore();
        Context ctxt = startServer(store);

        byte[] payload = serializedSession(".attacker", "attacker", "injected");
        Assert.assertEquals(HttpURLConnection.HTTP_CREATED, partialPut("/attacker.session", payload.length, payload));

        // The session store must not find a session for the attacker controlled
        // session ID
        Session session = store.load(".attacker");
        Assert.assertNull("Session injected via partial PUT temporary file", session);

        File tempDir = (File) ctxt.getServletContext().getAttribute(ServletContext.TEMPDIR);
        Assert.assertFalse(new File(tempDir, ".attacker.session").exists());

        assertNoPartialPutTempFiles(ctxt, ".attacker.session");
    }


    /*
     * The temporary file must be removed if the partial PUT fails while the
     * request body is being read.
     */
    @Test
    public void testTempFileRemovedOnIncompleteBody() throws Exception {
        Context ctxt = startServer(null);

        try (Socket socket = new Socket("localhost", getPort())) {
            socket.setSoTimeout(30000);
            OutputStream os = socket.getOutputStream();
            String request = "PUT /aborted.txt HTTP/1.1\r\n" +
                    "Host: localhost:" + getPort() + "\r\n" +
                    "Content-Range: bytes=0-99/100\r\n" +
                    "Content-Length: 100\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    "0123456789";
            os.write(request.getBytes(StandardCharsets.ISO_8859_1));
            os.flush();
            // Body is truncated
            socket.shutdownOutput();

            // Wait for the server to complete processing of the request
            InputStream is = socket.getInputStream();
            try {
                while (is.read() != -1) {
                    // Swallow the response
                }
            } catch (IOException ioe) {
                // Connection may be reset. Ignore.
            }
        }

        assertNoPartialPutTempFiles(ctxt, ".aborted.txt");
    }


    private Context startServer(FileStore store) throws Exception {
        Tomcat tomcat = getTomcatInstance();
        Context ctxt = tomcat.addContext("", tempDocBase.getAbsolutePath());

        if (store != null) {
            // Default store directory is the work directory of the context
            PersistentManager manager = new PersistentManager();
            manager.setStore(store);
            ctxt.setManager(manager);
        }

        Wrapper w = Tomcat.addServlet(ctxt, "default", DefaultServlet.class.getName());
        w.addInitParameter("readonly", "false");
        w.addInitParameter("allowPartialPut", "true");
        ctxt.addServletMappingDecoded("/", "default");

        tomcat.start();

        // Disable caching
        ctxt.getResources().setCachingAllowed(false);

        return ctxt;
    }


    private int partialPut(String path, int totalLength, byte[] body) throws IOException {
        URL url = new URL("http://localhost:" + getPort() + path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            connection.setRequestMethod("PUT");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Range",
                    "bytes=0-" + (body.length - 1) + "/" + totalLength);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(body);
            }
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }


    private String get(String path) throws IOException {
        ByteChunk responseBody = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + path, responseBody, null);
        Assert.assertEquals(HttpURLConnection.HTTP_OK, rc);
        return new String(responseBody.getBytes(), responseBody.getStart(), responseBody.getLength(),
                StandardCharsets.ISO_8859_1);
    }


    private void assertNoPartialPutTempFiles(Context ctxt, String pathDerivedName) throws InterruptedException {
        File tempDir = (File) ctxt.getServletContext().getAttribute(ServletContext.TEMPDIR);
        Assert.assertNotNull(tempDir);

        // Clean-up may complete just after the response has been sent
        int count = 0;
        while (count < 50 && hasPartialPutTempFiles(tempDir, pathDerivedName)) {
            Thread.sleep(100);
            count++;
        }
        Assert.assertFalse("Temporary file named after the request path found",
                new File(tempDir, pathDerivedName).exists());
        String[] leftOver = tempDir.list();
        if (leftOver != null) {
            for (String name : leftOver) {
                Assert.assertFalse("Partial PUT temporary file [" + name + "] not deleted",
                        name.startsWith(TEMP_FILE_PREFIX));
            }
        }
    }


    private static boolean hasPartialPutTempFiles(File tempDir, String pathDerivedName) {
        if (new File(tempDir, pathDerivedName).exists()) {
            return true;
        }
        String[] names = tempDir.list();
        if (names != null) {
            for (String name : names) {
                if (name.startsWith(TEMP_FILE_PREFIX)) {
                    return true;
                }
            }
        }
        return false;
    }


    /*
     * Same format as StandardSession.writeObjectData()
     */
    private static byte[] serializedSession(String id, String attributeName, String attributeValue)
            throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            long now = System.currentTimeMillis();
            oos.writeObject(Long.valueOf(now));        // creationTime
            oos.writeObject(Long.valueOf(now));        // lastAccessedTime
            oos.writeObject(Integer.valueOf(1800));    // maxInactiveInterval
            oos.writeObject(Boolean.FALSE);            // isNew
            oos.writeObject(Boolean.TRUE);             // isValid
            oos.writeObject(Long.valueOf(now));        // thisAccessedTime
            oos.writeObject(id);                       // id
            oos.writeObject(Integer.valueOf(1));       // attribute count
            oos.writeObject(attributeName);
            oos.writeObject(attributeValue);
        }
        return baos.toByteArray();
    }
}
