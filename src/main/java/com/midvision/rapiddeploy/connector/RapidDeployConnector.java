package com.midvision.rapiddeploy.connector;

import java.io.InputStream;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.DefaultHttpClient;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class RapidDeployConnector {

	/**
	 * Runs a Job in RapidDeploy with basic information.
	 * 
	 * @param authenticationToken
	 * @param serverUrl
	 * @param projectName
	 * @param targetEnvironment
	 * @param packageName
	 * @param logEnabled
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(String authenticationToken, String serverUrl, String projectName, String targetEnvironment,
			String packageName, boolean logEnabled) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, null, null, null,
				null, null, false);
	}

	/**
	 * Runs a Job in RapidDeploy with specific transport credentials.
	 * 
	 * @param authenticationToken
	 * @param serverUrl
	 * @param projectName
	 * @param targetEnvironment
	 * @param packageName
	 * @param logEnabled
	 * @param userName
	 * @param passwordEncrypted
	 * @param keyFilePath
	 * @param keyPassPhraseEncrypted
	 * @param encryptionKey
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(String authenticationToken, String serverUrl, String projectName, String targetEnvironment,
			String packageName, boolean logEnabled, String userName, String passwordEncrypted, String keyFilePath, String keyPassPhraseEncrypted,
			String encryptionKey) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, userName,
				passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, false);
	}

	/**
	 * Runs a Job in RapidDeploy providing the option to run it asynchronously.
	 * 
	 * @param authenticationToken
	 * @param serverUrl
	 * @param projectName
	 * @param targetEnvironment
	 * @param packageName
	 * @param logEnabled
	 * @param asynchronousJob
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(String authenticationToken, String serverUrl, String projectName, String targetEnvironment,
			String packageName, boolean logEnabled, boolean asynchronousJob) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, null, null, null,
				null, null, asynchronousJob);
	}

	/**
	 * Runs a Job in RapidDeploy providing the options to run it asynchronously
	 * and selecting if running or not previously failed packages.
	 * 
	 * @param authenticationToken
	 * @param serverUrl
	 * @param projectName
	 * @param targetEnvironment
	 * @param packageName
	 * @param logEnabled
	 * @param asynchronousJob
	 * @param allowFailedPkg
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(String authenticationToken, String serverUrl, String projectName, String targetEnvironment,
			String packageName, boolean logEnabled, boolean asynchronousJob, boolean allowFailedPkg) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, null, null, null,
				null, null, asynchronousJob, allowFailedPkg);
	}

	/**
	 * Runs a Job in RapidDeploy with specific transport credentials and
	 * providing the option to run it asynchronously as well.
	 * 
	 * @param authenticationToken
	 * @param serverUrl
	 * @param projectName
	 * @param targetEnvironment
	 * @param packageName
	 * @param logEnabled
	 * @param userName
	 * @param passwordEncrypted
	 * @param keyFilePath
	 * @param keyPassPhraseEncrypted
	 * @param encryptionKey
	 * @param asynchronousJob
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(String authenticationToken, String serverUrl, String projectName, String targetEnvironment,
			String packageName, boolean logEnabled, String userName, String passwordEncrypted, String keyFilePath, String keyPassPhraseEncrypted,
			String encryptionKey, boolean asynchronousJob) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, userName,
				passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, asynchronousJob, false);
	}

	/**
	 * Runs a Job in RapidDeploy with all possible options (Main method).
	 * 
	 * @param authenticationToken
	 * @param serverUrl
	 * @param projectName
	 * @param targetEnvironment
	 * @param packageName
	 * @param logEnabled
	 * @param userName
	 * @param passwordEncrypted
	 * @param keyFilePath
	 * @param keyPassPhraseEncrypted
	 * @param encryptionKey
	 * @param asynchronousJob
	 * @param allowFailedPkg
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(String authenticationToken, String serverUrl, String projectName, String targetEnvironment,
			String packageName, boolean logEnabled, String userName, String passwordEncrypted, String keyFilePath, String keyPassPhraseEncrypted,
			String encryptionKey, boolean asynchronousJob, boolean allowFailedPkg) throws Exception {

		boolean success = true;
		StringBuilder response = new StringBuilder();

		String[] envObjects = targetEnvironment.split("\\.");
		String output;
		if ((targetEnvironment.contains(".")) && (envObjects.length == 4)) {
			output = invokeRapidDeployDeployment(authenticationToken, serverUrl, projectName, envObjects[0], envObjects[1], envObjects[2], envObjects[3],
					packageName, userName, passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, allowFailedPkg);
		} else if ((targetEnvironment.contains(".")) && (envObjects.length == 3)) {
			output = invokeRapidDeployDeployment(authenticationToken, serverUrl, projectName, envObjects[0], envObjects[1], null, envObjects[2], packageName,
					userName, passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, allowFailedPkg);
		} else {
			throw new RuntimeException("Invalid environment settings found! Environment: " + targetEnvironment);
		}

		response.append("RapidDeploy job successfully started!");
		response.append(System.getProperty("line.separator"));

		if (!asynchronousJob) {
			String jobId = RapidDeployConnector.extractJobId(output);
			if (jobId != null) {
				response.append("Checking job status every 30 seconds...");
				response.append(System.getProperty("line.separator"));
				boolean runningJob = true;
				long milisToSleep = 30000L;
				while (runningJob) {
					Thread.sleep(milisToSleep);
					String jobDetails = RapidDeployConnector.pollRapidDeployJobDetails(authenticationToken, serverUrl, jobId);
					String jobStatus = RapidDeployConnector.extractJobStatus(jobDetails);
					response.append("Job status: " + jobStatus);
					response.append(System.getProperty("line.separator"));
					if ((jobStatus.equals("DEPLOYING")) || (jobStatus.equals("QUEUED")) || (jobStatus.equals("STARTING")) || (jobStatus.equals("EXECUTING"))) {
						response.append("Job running, next check in 30 seconds...");
						response.append(System.getProperty("line.separator"));
						milisToSleep = 30000L;
					} else if ((jobStatus.equals("REQUESTED")) || (jobStatus.equals("REQUESTED_SCHEDULED"))) {
						response.append("Job in a REQUESTED state. Approval may be required in RapidDeploy to continue with the execution, next check in 30 seconds...");
						response.append(System.getProperty("line.separator"));
					} else if (jobStatus.equals("SCHEDULED")) {
						response.append("Job in a SCHEDULED state, the execution will start in a future date, next check in 5 minutes...");
						response.append(System.getProperty("line.separator"));
						response.append("Printing out job details: ");
						response.append(System.getProperty("line.separator"));
						response.append(jobDetails);
						response.append(System.getProperty("line.separator"));
						milisToSleep = 300000L;
					} else {
						runningJob = false;
						response.append("Job finished with status: " + jobStatus);
						response.append(System.getProperty("line.separator"));
						if ((jobStatus.equals("FAILED")) || (jobStatus.equals("REJECTED")) || (jobStatus.equals("CANCELLED"))
								|| (jobStatus.equals("UNEXECUTABLE")) || (jobStatus.equals("TIMEDOUT")) || (jobStatus.equals("UNKNOWN"))) {
							success = false;
						}
					}
				}
			} else {
				throw new RuntimeException("Could not retrieve job id, running asynchronously!");
			}
			response.append(System.getProperty("line.separator"));
			String logs = pollRapidDeployJobLog(authenticationToken, serverUrl, jobId);
			if (!success) {
				throw new RuntimeException("RapidDeploy job failed. Please check the output." + System.getProperty("line.separator") + logs);
			}
			response.append("RapidDeploy job successfully run. Please check the output.");
			response.append(System.getProperty("line.separator"));
			response.append(logs);
			response.append(System.getProperty("line.separator"));
		}
		return logEnabled ? response.toString() : output;
	}

	private static String invokeRapidDeployDeployment(String authenticationToken, String serverUrl, String projectName, String server, String environment,
			String instance, String application, String packageName, String userName, String passwordEncrypted, String keyFilePath,
			String keyPassPhraseEncrypted, String encryptionKey, boolean allowFailedPkg) throws Exception {
		String deploymentUrl = buildDeploymentUrl(serverUrl, projectName, server, environment, instance, application, packageName, userName, passwordEncrypted,
				keyFilePath, keyPassPhraseEncrypted, encryptionKey, String.valueOf(allowFailedPkg));
		String output = callRDServerPutReq(deploymentUrl, authenticationToken);
		return output;
	}

	public static String invokeRapidDeployBuildPackage(String authenticationToken, String serverUrl, String projectName, String packageName,
			String archiveExtension, boolean logEnabled) throws Exception {
		String deploymentUrl = buildPackageBuildUrl(serverUrl, projectName, packageName, archiveExtension);
		String output = callRDServerPutReq(deploymentUrl, authenticationToken);
		StringBuilder response = new StringBuilder();
		response.append("Successfully invoked RapidDeploy build package with the following output: ");
		response.append(System.getProperty("line.separator"));
		response.append(output);
		response.append(System.getProperty("line.separator"));
		return logEnabled ? response.toString() : output;
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
			String packageName, String userName, String passwordEncrypted, String keyFilePath, String keyPassPhraseEncrypted, String encryptionKey,
			String allowFailedPkg) {
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
		url.append("?returnLogFile=false");
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
		url.append("&allowFailedPkg=").append(allowFailedPkg);
		return url.toString();
	}

	private static String buildPackageBuildUrl(String serverUrl, String projectName, String packageName, String archiveExtension) {
		StringBuilder url = new StringBuilder("");
		if (!serverUrl.startsWith("http://")) {
			url.append("http://");
		}
		url.append(serverUrl).append("/ws/deployment/");
		url.append(projectName).append("/package/create?packageName=");
		url.append(packageName == null ? "" : packageName).append("&archiveExtension=").append(archiveExtension == null ? "jar" : archiveExtension);

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
		if (instance != null && !"".equals(instance)) {
			url.append(serverUrl).append("/ws/deployment/" + projectName + "/package/list/" + server + "/" + environment + "/" + instance);
		} else {
			url.append(serverUrl).append("/ws/deployment/" + projectName + "/package/list/" + server + "/" + environment);
		}
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
			if ((((String) responseData.get(i)).contains("Job Status")) && (responseData.size() >= i + 1)) {
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
			if ((((String) responseData.get(i)).contains("Job ID")) && (responseData.size() >= i + 1)) {
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
