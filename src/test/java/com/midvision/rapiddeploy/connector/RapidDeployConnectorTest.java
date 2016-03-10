package com.midvision.rapiddeploy.connector;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class RapidDeployConnectorTest {

	private final String RD_URL = "http://localhost:8080/MidVision";
	private final String RD_AUTH_TOKEN = "bXZhZG1pbjp7X01WQEVOQyNffVdHLzFmNVMreVpRPQ=="; // mvadmin/mvadmin
	private final String RD_PROJECT = "CI_Test";
	private final String RD_PACK_NAME = "";
	private final String RD_PACK_EXT = "";
	private final String RD_TARGET = "localhost.test.LocalTest";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testInvokeRapidDeployBuildPackage() {
		try {
			System.out.println("Invoking a RapidDeploy package build...");
			final String output = RapidDeployConnector.invokeRapidDeployBuildPackage(RD_AUTH_TOKEN, RD_URL, RD_PROJECT, RD_PACK_NAME, RD_PACK_EXT, true, false);
			assertTrue("ERROR during the package build!", output.contains("File created successfully"));
			System.out.println("---> File created successfully!");
			System.out.println();
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testInvokeRapidDeployDeploymentPollOutput() {
		try {
			System.out.println("Invoking a RapidDeploy deployment of the previous package...");
			final String output = RapidDeployConnector.invokeRapidDeployDeploymentPollOutput(RD_AUTH_TOKEN, RD_URL, RD_PROJECT, RD_TARGET, RD_PACK_NAME, true, false);
			assertTrue("ERROR during the deployment!", output.contains("Completed RapidDeploy Deployment Request"));
			System.out.println("---> Completed RapidDeploy Deployment Request!");
			System.out.println();
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testInvokeRapidDeployListProjects() {
		try {
			final List<String> list = RapidDeployConnector.invokeRapidDeployListProjects(RD_AUTH_TOKEN, RD_URL);
			System.out.println("PROJECTS");
			System.out.println("---------------------");
			for (final String item : list) {
				System.out.println("* Project: " + item);
			}
			System.out.println();
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testInvokeRapidDeployListEnvironments() {
		try {
			final List<String> list = RapidDeployConnector.invokeRapidDeployListTargets(RD_AUTH_TOKEN, RD_URL, RD_PROJECT);
			System.out.println("TARGETS");
			System.out.println("---------------------");
			for (final String item : list) {
				System.out.println("* Target: " + item);
			}
			System.out.println();
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testInvokeRapidDeployListPackages() {
		try {
			final List<String> list = RapidDeployConnector.invokeRapidDeployListPackages(RD_AUTH_TOKEN, RD_URL, RD_PROJECT);
			System.out.println("PACKAGES");
			System.out.println("---------------------");
			for (final String item : list) {
				System.out.println("* Package: " + item);
			}
			System.out.println();
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testInvokeRapidDeployListServers() {
		try {
			final List<String> list = RapidDeployConnector.invokeRapidDeployListServers(RD_AUTH_TOKEN, RD_URL);
			System.out.println("SERVERS");
			System.out.println("---------------------");
			for (final String item : list) {
				System.out.println("* Server: " + item);
			}
			System.out.println();
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}
}
