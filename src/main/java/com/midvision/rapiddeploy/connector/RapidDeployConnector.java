package com.midvision.rapiddeploy.connector;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.SSLContext;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class RapidDeployConnector {

	private static final Log logger = LogFactory.getLog(RapidDeployConnector.class);

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
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled) throws Exception {
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
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled, final String userName, final String passwordEncrypted,
			final String keyFilePath, final String keyPassPhraseEncrypted, final String encryptionKey) throws Exception {
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
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled, final boolean asynchronousJob) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, null, null, null,
				null, null, asynchronousJob);
	}

	/**
	 * Runs a Job in RapidDeploy providing the option to run it asynchronously and a list of data dictionary items.
	 * 
	 * @param authenticationToken
	 * @param serverUrl
	 * @param projectName
	 * @param targetEnvironment
	 * @param packageName
	 * @param logEnabled
	 * @param asynchronousJob
	 * @param dataDictionary
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled, final boolean asynchronousJob,
			final Map<String, String> dataDictionary) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, null, null, null,
				null, null, asynchronousJob, false, dataDictionary);
	}

	/**
	 * Runs a Job in RapidDeploy providing the options to run it asynchronously and selecting if running or not previously failed packages.
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
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled, final boolean asynchronousJob, final boolean allowFailedPkg)
			throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, null, null, null,
				null, null, asynchronousJob, allowFailedPkg);
	}

	/**
	 * Runs a Job in RapidDeploy with specific transport credentials and providing the option to run it asynchronously as well.
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
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled, final String userName, final String passwordEncrypted,
			final String keyFilePath, final String keyPassPhraseEncrypted, final String encryptionKey, final boolean asynchronousJob) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, userName,
				passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, asynchronousJob, false);
	}

	/**
	 * Runs a Job in RapidDeploy with all possible options except the data dictionary list.
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
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled, final String userName, final String passwordEncrypted,
			final String keyFilePath, final String keyPassPhraseEncrypted, final String encryptionKey, final boolean asynchronousJob,
			final boolean allowFailedPkg) throws Exception {
		return invokeRapidDeployDeploymentPollOutput(authenticationToken, serverUrl, projectName, targetEnvironment, packageName, logEnabled, userName,
				passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, asynchronousJob, allowFailedPkg, new HashMap<String, String>());
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
	 * @param dataDictionary
	 * @return
	 * @throws Exception
	 */
	public static String invokeRapidDeployDeploymentPollOutput(final String authenticationToken, final String serverUrl, final String projectName,
			final String targetEnvironment, final String packageName, final boolean logEnabled, final String userName, final String passwordEncrypted,
			final String keyFilePath, final String keyPassPhraseEncrypted, final String encryptionKey, final boolean asynchronousJob,
			final boolean allowFailedPkg, final Map<String, String> dataDictionary) throws Exception {

		final String[] envObjects = targetEnvironment.split("\\.");
		String output;
		if ((targetEnvironment.contains(".")) && (envObjects.length == 4)) {
			output = invokeRapidDeployDeployment(authenticationToken, serverUrl, projectName, envObjects[0], envObjects[1], envObjects[2], envObjects[3],
					packageName, userName, passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, allowFailedPkg, dataDictionary);
		} else if ((targetEnvironment.contains(".")) && (envObjects.length == 3)) {
			output = invokeRapidDeployDeployment(authenticationToken, serverUrl, projectName, envObjects[0], envObjects[1], null, envObjects[2], packageName,
					userName, passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, allowFailedPkg, dataDictionary);
		} else {
			throw new RuntimeException("Invalid target environment found! Target: " + targetEnvironment);
		}

		final StringBuilder response = new StringBuilder();
		response.append("RapidDeploy job successfully started!");
		response.append(System.getProperty("line.separator"));

		if (!asynchronousJob) {
			checkJobStatus(authenticationToken, serverUrl, output, response);
		}
		return logEnabled ? response.toString() : output;
	}

	public static String invokeRapidDeployJobPlanPollOutput(final String authenticationToken, final String serverUrl, final String jobPlanId,
			final boolean asynchronousJob) throws Exception {
		String output;
		output = invokeRapiDeployJobPlan(authenticationToken, serverUrl, jobPlanId);
		final StringBuilder response = new StringBuilder();
		response.append("RapidDeploy jobPlan successfully started");
		response.append(System.getProperty("line.separator"));
		if (!asynchronousJob) {
			checkJobStatus(authenticationToken, serverUrl, output, response);
		}
		return output;
	}

	public static String invokeRapidDeployBuildPackage(final String authenticationToken, final String serverUrl, final String projectName,
			final String packageName, final String archiveExtension, final boolean logEnabled) throws Exception {
		return invokeRapidDeployBuildPackage(authenticationToken, serverUrl, projectName, packageName, archiveExtension, logEnabled, true);
	}

	public static String invokeRapidDeployBuildPackage(final String authenticationToken, final String serverUrl, final String projectName,
			final String packageName, final String archiveExtension, final boolean logEnabled, final boolean asynchronousJob) throws Exception {

		final String deploymentUrl = buildPackageBuildUrl(serverUrl, projectName, packageName, archiveExtension);
		final String output = callRDServerPutReq(deploymentUrl, authenticationToken);

		final StringBuilder response = new StringBuilder();
		response.append("RapidDeploy package build succesfully requested!");
		response.append(System.getProperty("line.separator"));

		if (!asynchronousJob) {
			checkJobStatus(authenticationToken, serverUrl, output, response);
		}
		return logEnabled ? response.toString() : output;
	}

	public static String pollRapidDeployJobDetails(final String authenticationToken, final String serverUrl, final String jobId) throws Exception {
		final String deploymentUrl = buildRequestUrl(serverUrl, "/ws/deployment/display/job/" + jobId);
		final String output = callRDServerGetReq(deploymentUrl, authenticationToken);
		return output;
	}

	public static String pollRapidDeployJobLog(final String authenticationToken, final String serverUrl, final String jobId) throws Exception {
		final String deploymentUrl = buildRequestUrl(serverUrl, "/ws/deployment/showlog/job/" + jobId);
		final String output = callRDServerGetReq(deploymentUrl, authenticationToken);
		return output;
	}

	public static List<String> invokeRapidDeployListProjects(final String authenticationToken, final String serverUrl) throws Exception {
		final String projectListUrl = buildRequestUrl(serverUrl, "/ws/project/list");
		final String output = callRDServerGetReq(projectListUrl, authenticationToken);
		return extractTagValueFromXml(output, "name");
	}

	public static List<String> invokeRapidDeployListTargets(final String authenticationToken, final String serverUrl, final String projectName)
			throws Exception {
		final String environmentListUrl = buildRequestUrl(serverUrl, "/ws/project/" + projectName + "/list");
		final String output = callRDServerGetReq(environmentListUrl, authenticationToken);
		final List<String> targetNames = extractTagValueFromXml(output, "span");
		final List<String> targets = new ArrayList<String>();
		for (final String target : targetNames) {
			if (!"null".equals(target) && !target.startsWith("Project")) {
				targets.add(target);
			}
		}
		return targets;
	}

	public static List<String> invokeRapidDeployListPackages(final String authenticationToken, final String serverUrl, final String projectName)
			throws Exception {
		return invokeRapidDeployListPackages(authenticationToken, serverUrl, projectName, null, null, null);
	}

	public static List<String> invokeRapidDeployListPackages(final String authenticationToken, final String serverUrl, final String projectName,
			final String server, final String environment, final String instance) throws Exception {
		String packageListUrl;
		if (server != null && !"".equals(server)) {
			if (instance != null && !"".equals(instance)) {
				packageListUrl = buildRequestUrl(serverUrl, "/ws/deployment/" + projectName + "/package/list/" + server + "/" + environment + "/" + instance);
			} else {
				packageListUrl = buildRequestUrl(serverUrl, "/ws/deployment/" + projectName + "/package/list/" + server + "/" + environment);
			}
		} else {
			packageListUrl = buildRequestUrl(serverUrl, "/ws/deployment/" + projectName + "/package/list");
		}
		final String output = callRDServerGetReq(packageListUrl, authenticationToken);
		final List<String> packageNames = extractTagValueFromXml(output, "span");
		final List<String> packages = new ArrayList<String>();
		for (final String pack : packageNames) {
			if (!"null".equals(pack) && !pack.contains("Package name for project")) {
				packages.add(pack);
			}
		}
		return packages;
	}

	public static List<String> invokeRapidDeployListServers(final String authenticationToken, final String serverUrl) throws Exception {
		final String serverListUrl = buildRequestUrl(serverUrl, "/ws/server/list");
		final String output = callRDServerGetReq(serverListUrl, authenticationToken);
		return extractXPathExpressionListFromXml(output, "/servers/Server/hostname/text()");
	}

	private static String invokeRapidDeployDeployment(final String authenticationToken, final String serverUrl, final String projectName, final String server,
			final String environment, final String instance, final String application, final String packageName, final String userName,
			final String passwordEncrypted, final String keyFilePath, final String keyPassPhraseEncrypted, final String encryptionKey,
			final boolean allowFailedPkg, final Map<String, String> dataDictionary) throws Exception {
		final String deploymentUrl = buildDeploymentUrl(serverUrl, projectName, server, environment, instance, application, packageName, userName,
				passwordEncrypted, keyFilePath, keyPassPhraseEncrypted, encryptionKey, String.valueOf(allowFailedPkg), dataDictionary);
		return callRDServerPutReq(deploymentUrl, authenticationToken);
	}

	private static String invokeRapiDeployJobPlan(final String authenticationToken, final String serverUrl, final String jobPlanId) throws Exception {
		final String runJobPlanUrl = buildRunJobPlanUrl(serverUrl, jobPlanId);
		return callRDServerPutReq(runJobPlanUrl, authenticationToken);
	}

	public static String invokeRapidDeployJobPlans(final String authenticationToken, final String serverUrl) throws Exception {
		final String jobPlanListUrl = buildRequestUrl(serverUrl, "/ws/deployment/jobPlan/list");
		final String output = callRDServerGetReq(jobPlanListUrl, authenticationToken);
		return output;
	}

	/** URL GENERATION METHODS **/

	private static String buildRequestUrl(String serverUrl, final String context) {
		if (serverUrl != null && serverUrl.endsWith("/")) {
			serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
		}
		final StringBuilder url = new StringBuilder();
		if (!serverUrl.startsWith("http://") && !serverUrl.startsWith("https://")) {
			url.append("http://");
		}
		url.append(serverUrl).append(context);
		return url.toString();
	}

	private static String buildPackageBuildUrl(String serverUrl, final String projectName, final String packageName, final String archiveExtension) {
		if (serverUrl != null && serverUrl.endsWith("/")) {
			serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
		}
		final StringBuilder url = new StringBuilder();
		if (!serverUrl.startsWith("http://") && !serverUrl.startsWith("https://")) {
			url.append("http://");
		}
		url.append(serverUrl).append("/ws/deployment/");
		url.append(projectName).append("/package/create?packageName=");
		url.append(packageName == null ? "" : packageName).append("&archiveExtension=")
				.append(archiveExtension == null || "".equals(archiveExtension) ? "jar" : archiveExtension);

		return url.toString();
	}

	private static String buildRunJobPlanUrl(String serverUrl, final String jobPlanId) {
		if (serverUrl != null && serverUrl.endsWith("/")) {
			serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
		}
		final StringBuilder url = new StringBuilder();
		if (!serverUrl.startsWith("http://") && !serverUrl.startsWith("https://")) {
			url.append("http://");
		}
		url.append(serverUrl).append("/ws/deployment/");
		url.append("jobPlan/run/");
		url.append(jobPlanId);
		return url.toString();
	}

	private static String buildDeploymentUrl(String serverUrl, final String projectName, final String server, final String environment, final String instance,
			final String application, final String packageName, final String userName, final String passwordEncrypted, final String keyFilePath,
			final String keyPassPhraseEncrypted, final String encryptionKey, final String allowFailedPkg, final Map<String, String> dataDictionary)
			throws UnsupportedEncodingException {
		if (serverUrl != null && serverUrl.endsWith("/")) {
			serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
		}
		final StringBuilder url = new StringBuilder();
		if (!serverUrl.startsWith("http://") && !serverUrl.startsWith("https://")) {
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
		for (final Entry<String, String> dataItem : dataDictionary.entrySet()) {
			url.append("&dictionaryItem=").append(URLEncoder.encode(dataItem.getKey(), "UTF-8")).append(URLEncoder.encode("=", "UTF-8"))
					.append(URLEncoder.encode(dataItem.getValue(), "UTF-8"));
		}
		return url.toString();
	}

	/** WEB SERVICE CALL METHODS **/

	private static String callRDServerPutReq(final String url, final String authenticationToken) throws Exception {
		final SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
		final SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
		final HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslSocketFactory).build();
		final HttpPut putRequest = new HttpPut(url);
		putRequest.addHeader("Authorization", authenticationToken);
		final HttpResponse response = httpClient.execute(putRequest);
		final InputStream responseOutput = response.getEntity().getContent();
		final int status = response.getStatusLine().getStatusCode();

		if ((status >= 400) && (status < 500)) {
			final String exceptionContents = response.getStatusLine().toString() + "\nError calling RapidDeploy server on url:" + url + "\nCause: "
					+ getInputstreamContent(responseOutput);
			throw new Exception(exceptionContents);
		}
		return getInputstreamContent(responseOutput);
	}

	private static String callRDServerGetReq(final String url, final String authenticationToken) throws Exception {
		final SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
		final SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
		final HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslSocketFactory).build();
		final HttpGet getRequest = new HttpGet(url);
		getRequest.addHeader("Authorization", authenticationToken);
		final HttpResponse response = httpClient.execute(getRequest);
		final InputStream responseOutput = response.getEntity().getContent();
		final int status = response.getStatusLine().getStatusCode();

		if ((status >= 400) && (status < 500)) {
			throw new Exception(response.getStatusLine().toString() + "\nError calling RapidDeploy server on url:" + url + "\nCause: "
					+ getInputstreamContent(responseOutput));
		}
		return getInputstreamContent(responseOutput);
	}

	private static String getInputstreamContent(final InputStream inputstream) throws java.io.IOException {
		final StringBuilder inputStringBuilder = new StringBuilder();
		final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputstream, "UTF-8"));
		String line = bufferedReader.readLine();
		while (line != null) {
			inputStringBuilder.append(line);
			inputStringBuilder.append('\n');
			line = bufferedReader.readLine();
		}
		return inputStringBuilder.toString();
	}

	private static void checkJobStatus(final String authenticationToken, final String serverUrl, final String output, final StringBuilder response)
			throws Exception, InterruptedException {
		boolean success = true;
		final String jobId = extractJobId(output);
		if (jobId != null) {
			response.append("Checking job status every 30 seconds...");
			response.append(System.getProperty("line.separator"));
			boolean runningJob = true;
			long milisToSleep = 30000L;
			while (runningJob) {
				Thread.sleep(milisToSleep);
				final String jobDetails = RapidDeployConnector.pollRapidDeployJobDetails(authenticationToken, serverUrl, jobId);
				final String jobStatus = RapidDeployConnector.extractJobStatus(jobDetails);
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
					if ((jobStatus.equals("FAILED")) || (jobStatus.equals("REJECTED")) || (jobStatus.equals("CANCELLED")) || (jobStatus.equals("UNEXECUTABLE"))
							|| (jobStatus.equals("TIMEDOUT")) || (jobStatus.equals("UNKNOWN"))) {
						success = false;
					}
				}
			}
		} else {
			throw new RuntimeException("Could not retrieve job id, running asynchronously!");
		}
		response.append(System.getProperty("line.separator"));
		final String logs = pollRapidDeployJobLog(authenticationToken, serverUrl, jobId);
		if (!success) {
			throw new RuntimeException("RapidDeploy job failed. Please check the output." + System.getProperty("line.separator") + logs);
		}
		response.append("RapidDeploy job successfully run. Please check the output.");
		response.append(System.getProperty("line.separator"));
		response.append(logs);
		response.append(System.getProperty("line.separator"));
	}

	public static Map<String, String> extractJobPlansFromXml(final String xmlContent) throws Exception {
		final DocumentBuilder builder = getSecureDocumentBuilderFactory().newDocumentBuilder();
		final Document document = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xmlContent)));
		final org.w3c.dom.Element rootElement = document.getDocumentElement();

		final NodeList list = rootElement.getElementsByTagName("JobPlan");
		final Map<String, String> result = new HashMap<String, String>();
		if ((list != null) && (list.getLength() > 0)) {
			for (int i = 0; i < list.getLength(); i++) {
				final NodeList subList = list.item(i).getChildNodes();
				if ((subList != null) && (subList.getLength() > 0)) {
					String id = null;
					String name = null;
					String securityName = "all";
					for (int j = 0; j < subList.getLength(); j++) {
						final Node node = subList.item(j);
						if (node.getChildNodes() == null) {
							continue;
						}
						if (node.getNodeName().equals("id")) {
							for (int k = 0; k < node.getChildNodes().getLength(); k++) {
								id = node.getChildNodes().item(k).getNodeValue();
							}
						}
						if (node.getNodeName().equals("name")) {
							for (int k = 0; k < node.getChildNodes().getLength(); k++) {
								name = node.getChildNodes().item(k).getNodeValue();
							}
						}
						if (node.getNodeName().equals("securityName")) {
							for (int k = 0; k < node.getChildNodes().getLength(); k++) {
								securityName = node.getChildNodes().item(k).getNodeValue();
							}
						}
					}
					if (id != null) {
						result.put(id, "[" + id + "] " + name + " (" + securityName + ")");
					}
				}
			}
		}
		return result;
	}

	public static List<String> extractTagValueFromXml(final String xmlContent, final String tagName) throws Exception {
		final DocumentBuilder builder = getSecureDocumentBuilderFactory().newDocumentBuilder();
		final Document document = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xmlContent)));
		final org.w3c.dom.Element rootElement = document.getDocumentElement();

		final List<String> outputValues = new ArrayList<String>();
		final NodeList list = rootElement.getElementsByTagName(tagName);
		if ((list != null) && (list.getLength() > 0)) {
			for (int i = 0; i < list.getLength(); i++) {
				final NodeList subList = list.item(i).getChildNodes();

				if ((subList != null) && (subList.getLength() > 0)) {
					for (int j = 0; j < subList.getLength(); j++) {
						outputValues.add(subList.item(j).getNodeValue());
					}
				}
			}
		}
		return outputValues;
	}

	@SuppressWarnings("unused")
	private static String extractXPathExpressionFromXml(final String xmlContent, final String xpathExpr) throws Exception {
		final DocumentBuilder builder = getSecureDocumentBuilderFactory().newDocumentBuilder();
		final Document document = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xmlContent)));
		final XPathFactory xPathfactory = XPathFactory.newInstance();
		final XPath xpath = xPathfactory.newXPath();
		final XPathExpression expr = xpath.compile(xpathExpr);
		return expr.evaluate(document);
	}

	private static List<String> extractXPathExpressionListFromXml(final String xmlContent, final String xpathExpr) throws Exception {
		final List<String> resList = new ArrayList<String>();
		final DocumentBuilder builder = getSecureDocumentBuilderFactory().newDocumentBuilder();
		final Document document = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xmlContent)));
		final XPathFactory xPathfactory = XPathFactory.newInstance();
		final XPath xpath = xPathfactory.newXPath();
		final XPathExpression expr = xpath.compile(xpathExpr);
		final NodeList list = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
		for (int i = 0; i < list.getLength(); i++) {
			final Node node = list.item(i);
			resList.add(node.getNodeValue());
		}
		return resList;
	}

	public static String extractJobStatus(final String responseOutput) throws Exception {
		String jobStatus = null;
		final List<String> responseData = extractTagValueFromXml(responseOutput, "span");
		for (int i = 0; i < responseData.size(); i++) {
			if ((((String) responseData.get(i)).contains("Job Status")) && (responseData.size() >= i + 1)) {
				jobStatus = (String) responseData.get(i + 1);
			}
		}
		return jobStatus;
	}

	public static List<String> extractIncludedJobIdsUnderPipelineJob(final String responseOutput) throws Exception {
		final List<String> includedJobIds = new ArrayList<String>();
		final List<String> responseData = extractTagValueFromXml(responseOutput, "span");
		for (int i = 0; i < responseData.size(); i++) {
			if ((((String) responseData.get(i)).contains("Internal Job ID")) && (responseData.size() >= i + 1)) {
				includedJobIds.add((String) responseData.get(i + 1));
			}
		}
		Collections.sort(includedJobIds);
		return includedJobIds;
	}

	public static String extractJobId(final String responseOutput) throws Exception {
		String jobId = null;
		final List<String> responseData = extractTagValueFromXml(responseOutput, "span");
		for (int i = 0; i < responseData.size(); i++) {
			final String tmpStr = (String) responseData.get(i);
			if ((tmpStr.contains("Job ID")) && (responseData.size() >= i + 1)) {
				jobId = (String) responseData.get(i + 1);
			}
			if ((tmpStr.contains("Job Id")) && (responseData.size() >= i + 1)) {
				if (jobId == null || "".equals(jobId)) {
					jobId = tmpStr.substring(tmpStr.indexOf("Job Id [") + 8, tmpStr.indexOf("]"));
				}
			}
		}
		return jobId;
	}

	/**
	 * Returns a secured to XXE attacks DocumentBuildFactory.
	 * 
	 * https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
	 */
	private static DocumentBuilderFactory getSecureDocumentBuilderFactory() throws ParserConfigurationException {
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		String feature = null;
		try {
			// This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all
			// XML entity attacks are prevented
			// Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
			feature = "http://apache.org/xml/features/disallow-doctype-decl";
			dbf.setFeature(feature, true);

			// If you can't completely disable DTDs, then at least do the following:
			// Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
			// Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
			// JDK7+ - http://xml.org/sax/features/external-general-entities
			feature = "http://xml.org/sax/features/external-general-entities";
			dbf.setFeature(feature, false);

			// Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
			// Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
			// JDK7+ - http://xml.org/sax/features/external-parameter-entities
			feature = "http://xml.org/sax/features/external-parameter-entities";
			dbf.setFeature(feature, false);

			// Disable external DTDs as well
			feature = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
			dbf.setFeature(feature, false);

			// and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
			dbf.setXIncludeAware(false);
			dbf.setExpandEntityReferences(false);

			try {
				dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
				dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
			} catch (final IllegalArgumentException iae) {
				logger.warn(iae.getMessage());
			}

			return dbf;
		} catch (final ParserConfigurationException pce) {
			// This should catch a failed setFeature feature
			logger.info("ParserConfigurationException was thrown. The feature '" + feature + "' is probably not supported by your XML processor.");
			throw pce;
		}
	}
}
