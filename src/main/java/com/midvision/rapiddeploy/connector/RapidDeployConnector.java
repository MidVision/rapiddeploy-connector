package com.midvision.rapiddeploy.connector;

import java.io.InputStream;
import java.security.Key;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.DefaultHttpClient;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class RapidDeployConnector {

    // FIXME: this values are in fact properties in the RapidDeploy framework.
    public static final String PREFIX_ENC = "{_MV@ENC#_}";
    public static final String ENCRYPTION_KEY = "lUzX7J0LkoUigR763Fnbuaq7e3TYPGe3";

    private static String encryptValue(final String key, final String value) throws Exception {
        final byte[] bytes24 = JCEHelper.createHashValue(key.getBytes(), JCEHelper.SHA_256);
        final Key key3DES = JCEHelper.create3DESKey(bytes24);
        final byte[] encryptedData = JCEHelper.encrypt(value.getBytes(), JCEHelper.DES_EDE, key3DES);
        try {
            return new String(Base64.encodeBase64(encryptedData));
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public static String invokeRapidDeployDeploymentPollOutput(String username, String password, String serverUrl, String projectName,
            String targetEnvironment, String packageName, boolean logEnabled) throws Exception {
        return invokeRapidDeployDeploymentPollOutput(username, password, serverUrl, projectName, targetEnvironment, packageName, logEnabled, null, null, null,
                null, null);
    }

    public static String invokeRapidDeployDeploymentPollOutput(String username, String password, String serverUrl, String projectName,
            String targetEnvironment, String packageName, boolean logEnabled, String userName, String passwordEncrypted, String keyFilePath,
            String keyPassPhraseEncrypted, String encryptionKey) throws Exception {

        final String encryptPass = PREFIX_ENC + encryptValue(ENCRYPTION_KEY + username, password);
        final String authenticationToken = new String(Base64.encodeBase64((username + ":" + encryptPass).getBytes("UTF-8")));

        boolean success = true;

        String[] envObjects = targetEnvironment.split("\\.");
        String output;
        if ((targetEnvironment.contains(".")) && (envObjects.length == 4)) {
            output = invokeRapidDeployDeployment(authenticationToken, serverUrl, projectName, envObjects[0], envObjects[1], envObjects[2], envObjects[3],
                    packageName, userName, passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey);
        } else {
            if ((targetEnvironment.contains(".")) && (envObjects.length == 3)) {
                output = invokeRapidDeployDeployment(authenticationToken, serverUrl, projectName, envObjects[0], envObjects[1], null, envObjects[2],
                        packageName, userName, passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey);
            } else {
                if (logEnabled) {
                    System.out.println("Exception: Invalid environment settings found! " + targetEnvironment);
                }
                throw new Exception("Invalid environment settings found!");
            }
        }
        if (logEnabled) {
            System.out.println("RapidDeploy job has successfully started!");
        }

        String jobId = extractJobId(output);
        if (jobId != null) {
            if (logEnabled) {
                System.out.println("Checking job status in every 30 seconds...");
            }
            boolean runningJob = true;

            long milisToSleep = 30000L;
            while (runningJob) {
                Thread.sleep(milisToSleep);
                String jobDetails = pollRapidDeployJobDetails(authenticationToken, serverUrl, jobId);
                String jobStatus = extractJobStatus(jobDetails);

                if (logEnabled) {
                    System.out.println("Job status is " + jobStatus);
                }
                if ((jobStatus.equals("DEPLOYING")) || (jobStatus.equals("QUEUED")) || (jobStatus.equals("STARTING")) || (jobStatus.equals("EXECUTING"))) {
                    if (logEnabled) {
                        System.out.println("Job is running, next check in 30 seconds..");
                    }
                    milisToSleep = 30000L;
                } else if ((jobStatus.equals("REQUESTED")) || (jobStatus.equals("REQUESTED_SCHEDULED"))) {
                    if (logEnabled) {
                        System.out
                                .println("Job is in a REQUESTED state. Approval may be required in RapidDeploy to continue with execution, next check in 30 seconds..");
                    }
                } else if (jobStatus.equals("SCHEDULED")) {
                    if (logEnabled) {
                        System.out.println("Job is in a SCHEDULED state, execution will start in a future date, next check in 5 minutes..");
                        System.out.println("Printing out job details");
                        System.out.println(jobDetails);
                    }
                    milisToSleep = 300000L;
                } else {
                    runningJob = false;
                    if (logEnabled) {
                        System.out.println("Job is finished with status " + jobStatus);
                    }
                    if ((jobStatus.equals("FAILED")) || (jobStatus.equals("REJECTED")) || (jobStatus.equals("CANCELLED")) || (jobStatus.equals("UNEXECUTABLE"))
                            || (jobStatus.equals("TIMEDOUT")) || (jobStatus.equals("UNKNOWN"))) {

                        success = false;
                    }
                }
            }
        } else {
            throw new Exception("Could not retrieve job id, running asynchronously!");
        }
        if (logEnabled) {
            System.out.println("");
        }
        String logs = pollRapidDeployJobLog(authenticationToken, serverUrl, jobId);
        if (logEnabled) {
            System.out.println(logs);
        }
        if (!success) {
            throw new RuntimeException("Failed to run RapidDeploy job. Please check the output.");
        }

        if (logEnabled) {
            System.out.println("Successfully ran RapidDeploy job. Please check the output.");
        }
        return "Successfully ran RapidDeploy job. Please check the output.";
    }

    public static String invokeRapidDeployDeployment(String authenticationToken, String serverUrl, String projectName, String server, String environment,
            String instance, String application, String packageName, String userName, String passwordEncrypted, String keyFilePath,
            String keyPassPhraseEncrypted, String encryptionKey) throws Exception {
        String deploymentUrl = buildDeploymentUrl(serverUrl, projectName, server, environment, instance, application, packageName, userName, passwordEncrypted,
                keyFilePath, keyPassPhraseEncrypted, encryptionKey);
        String output = callRDServerPutReq(deploymentUrl, authenticationToken);
        return output;
    }

    public static String invokeRapidDeployBuildPackage(String username, String password, String serverUrl, String projectName, String packageName,
            String archiveExension, boolean logEnabled) throws Exception {
        String deploymentUrl = buildPackageBuildUrl(serverUrl, projectName, packageName, archiveExension);

        final String encryptPass = PREFIX_ENC + encryptValue(ENCRYPTION_KEY + username, password);
        final String authenticationToken = new String(Base64.encodeBase64((username + ":" + encryptPass).getBytes("UTF-8")));

        String output = callRDServerPutReq(deploymentUrl, authenticationToken);
        if (logEnabled)
            System.out.println("Successfully invoked RapidDeploy build package with the following output: " + output);
        return output;
    }

    public static String pollRapidDeployJobDetails(String authenticationToken, String serverUrl, String jobId) throws Exception {
        String deploymentUrl = buildJobStatusUrl(serverUrl, jobId);
        String output = callRDServerGetReq(deploymentUrl, authenticationToken);
        return output;
    }

    public static String pollRapidDeployJobLog(String authenticationToken, String serverUrl, String jobId) throws Exception {
        String deploymentUrl = buildJobLogUrl(serverUrl, jobId);
        String output = callRDServerGetReq(deploymentUrl, authenticationToken);
        return output;
    }

    public static List<String> invokeRapidDeployListProjects(String authenticationToken, String serverUrl) throws Exception {
        String projectListUrl = buildProjectListQueryUrl(serverUrl, authenticationToken);
        String output = callRDServerGetReq(projectListUrl, authenticationToken);
        return extractTagValueFromXml(output, "name");
    }

    public static List<String> invokeRapidDeployListEnvironments(String authenticationToken, String serverUrl, String projectName) throws Exception {
        String environmentListUrl = buildEnvironmentListQueryUrl(serverUrl, authenticationToken, projectName);
        String output = callRDServerGetReq(environmentListUrl, authenticationToken);
        return extractTagValueFromXml(output, "span");
    }

    public static List<String> invokeRapidDeployListPackages(String authenticationToken, String serverUrl, String projectName, String server,
            String environment, String instance) throws Exception {
        String packageListUrl = buildPackageListQueryUrl(serverUrl, authenticationToken, projectName, server, environment, instance);
        String output = callRDServerGetReq(packageListUrl, authenticationToken);
        return extractTagValueFromXml(output, "span");
    }

    public static List<String> invokeRapidDeployListPackages(String authenticationToken, String serverUrl, String projectName) throws Exception {
        String packageListUrl = buildPackageListQueryUrl(serverUrl, authenticationToken, projectName);
        String output = callRDServerGetReq(packageListUrl, authenticationToken);
        return extractTagValueFromXml(output, "span");
    }

    public static List<String> invokeRapidDeployListServers(String authenticationToken, String serverUrl) throws Exception {
        String serverListUrl = buildServerListQueryUrl(serverUrl, authenticationToken);
        String output = callRDServerGetReq(serverListUrl, authenticationToken);
        return extractTagValueFromXml(output, "span");
    }

    public static String invokeRapidDeployGetSingleServer(String authenticationToken, String serverUrl, String serverName) throws Exception {
        String url = buildGetSingleServerQueryUrl(serverUrl, serverName);
        String output = callRDServerGetReq(url, authenticationToken);
        return extractHostname(output);
    }

    private static String buildDeploymentUrl(String serverUrl, String projectName, String server, String environment, String instance, String application,
            String packageName, String userName, String passwordEncrypted, String keyFilePath, String keyPassPhraseEncrypted, String encryptionKey) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/deployment/");
        url.append(projectName).append("/runjob/deploy/");
        url.append(server).append("/");
        url.append(environment).append("/");
        if (instance != null && !"".equals(instance)) {
            url.append(instance).append("/");
        }
        url.append(application);
        url.append("?returnLogFile=true");
        if ((packageName != null) && (!"".equals(packageName)) && (!"latest".equals(packageName.toLowerCase()))) {
            url.append("&packageName=").append(packageName);
        }
        if ((userName != null) && (!"".equals(userName))) {
            url.append("&userName=").append(userName);
            if ((passwordEncrypted != null) && (!"".equals(passwordEncrypted)))
                url.append("&passwordEncrypted=").append(passwordEncrypted);
            if ((keyFilePath != null) && (!"".equals(keyFilePath)))
                url.append("&keyFilePath=").append(keyFilePath);
            if ((keyPassPhraseEncrypted != null) && (!"".equals(keyPassPhraseEncrypted)))
                url.append("&keyPassPhraseEncrypted=").append(keyPassPhraseEncrypted);
            if ((encryptionKey != null) && (!"".equals(encryptionKey))) {
                url.append("&encryptionKey=").append(encryptionKey);
            }
        }
        return url.toString();
    }

    private static String buildPackageBuildUrl(String serverUrl, String projectName, String packageName, String archiveExension) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/deployment/");
        url.append(projectName).append("/package/create?packageName=");
        url.append(packageName == null ? "" : packageName).append("&archiveExension=").append(archiveExension == null ? "jar" : archiveExension);

        return url.toString();
    }

    private static String buildJobStatusUrl(String serverUrl, String jobId) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/deployment/display/job/" + jobId);
        return url.toString();
    }

    private static String buildJobLogUrl(String serverUrl, String jobId) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/deployment/showlog/job/" + jobId);
        return url.toString();
    }

    private static String buildProjectListQueryUrl(String serverUrl, String authenticationToken) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/project/list");

        return url.toString();
    }

    private static String buildEnvironmentListQueryUrl(String serverUrl, String authenticationToken, String projectName) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/project/" + projectName + "/list");

        return url.toString();
    }

    private static String buildPackageListQueryUrl(String serverUrl, String authenticationToken, String projectName, String server, String environment,
            String instance) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/deployment/" + projectName + "/package/list/" + server + "/" + environment + "/" + instance);
        return url.toString();
    }

    private static String buildPackageListQueryUrl(String serverUrl, String authenticationToken, String projectName) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/deployment/" + projectName + "/package/list");
        return url.toString();
    }

    private static String buildServerListQueryUrl(String serverUrl, String authenticationToken) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/server/list");
        return url.toString();
    }

    private static String buildGetSingleServerQueryUrl(String serverUrl, String serverName) {
        StringBuilder url = new StringBuilder("");
        if (!serverUrl.startsWith("http://")) {
            url.append("http://");
        }
        url.append(serverUrl).append("/ws/server/" + serverName);
        return url.toString();
    }

    private static String callRDServerPutReq(String url, String authenticationToken) throws Exception {
        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpPut putRequest = new HttpPut(url);
        putRequest.addHeader("Authorization", authenticationToken);
        HttpResponse response = httpClient.execute(putRequest);
        InputStream responseOutput = response.getEntity().getContent();
        int status = response.getStatusLine().getStatusCode();

        if ((status >= 400) && (status < 500)) {
            String exceptionContents = response.getStatusLine().toString() + "\nError calling RapidDeploy server on url:" + url + "\nCause: "
                    + getInputstreamContent(responseOutput);
            throw new Exception(exceptionContents);
        }
        return getInputstreamContent(responseOutput);
    }

    private static String callRDServerGetReq(String url, String authenticationToken) throws Exception {
        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpGet getRequest = new HttpGet(url);
        getRequest.addHeader("Authorization", authenticationToken);
        HttpResponse response = httpClient.execute(getRequest);
        InputStream responseOutput = response.getEntity().getContent();
        int status = response.getStatusLine().getStatusCode();

        if ((status >= 400) && (status < 500)) {
            throw new Exception(response.getStatusLine().toString() + "\nError calling RapidDeploy server on url:" + url + "\nCause: "
                    + getInputstreamContent(responseOutput));
        }
        return getInputstreamContent(responseOutput);
    }

    private static String getInputstreamContent(InputStream inputstream) throws java.io.IOException {
        String output = "";

        byte[] buf = new byte['?'];
        int nread;
        while ((nread = inputstream.read(buf)) > 0) {
            String line = new String(buf, 0, nread);
            output = output + line;
        }
        return output;
    }

    public static List<String> extractTagValueFromXml(String xmlContent, String tagName) throws Exception {
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xmlContent)));
        org.w3c.dom.Element rootElement = document.getDocumentElement();

        List<String> outputValues = new java.util.ArrayList<String>();
        NodeList list = rootElement.getElementsByTagName(tagName);
        if ((list != null) && (list.getLength() > 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                NodeList subList = list.item(i).getChildNodes();

                if ((subList != null) && (subList.getLength() > 0)) {
                    for (int j = 0; j < subList.getLength(); j++) {
                        outputValues.add(subList.item(j).getNodeValue());
                    }
                }
            }
        }
        return outputValues;
    }

    public static String extractXPathExpressionFromXml(String xmlContent, String xpathExpr) throws Exception {
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xmlContent)));
        XPathFactory xPathfactory = XPathFactory.newInstance();
        XPath xpath = xPathfactory.newXPath();
        XPathExpression expr = xpath.compile(xpathExpr);
        return expr.evaluate(document);
    }

    public static String extractJobStatus(String responseOutput) throws Exception {
        String jobStatus = null;
        List<String> responseData = extractTagValueFromXml(responseOutput, "span");
        for (int i = 0; i < responseData.size(); i++) {
            if ((((String) responseData.get(i)).equals("Display Details Job Status")) && (responseData.size() >= i + 1)) {
                jobStatus = (String) responseData.get(i + 1);
            }
        }
        return jobStatus;
    }

    public void test() {
    }

    public static String extractJobId(String responseOutput) throws Exception {
        String jobId = null;
        List<String> responseData = extractTagValueFromXml(responseOutput, "span");
        for (int i = 0; i < responseData.size(); i++) {
            if ((((String) responseData.get(i)).equals("Deployment Job ID")) && (responseData.size() >= i + 1)) {
                jobId = (String) responseData.get(i + 1);
            }
        }
        return jobId;
    }

    public static String extractHostname(String responseOutput) throws Exception {
        String hostname = null;
        hostname = extractXPathExpressionFromXml(responseOutput, "/Server/hostname/text()");
        return hostname;
    }
}
