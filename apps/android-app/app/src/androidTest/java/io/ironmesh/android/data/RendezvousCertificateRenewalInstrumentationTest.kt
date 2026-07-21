package io.ironmesh.android.data

import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ironmesh.android.ui.MainViewModel
import io.ironmesh.android.ui.enrollmentVerificationSuccessDetail
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RendezvousCertificateRenewalInstrumentationTest {
    private val application by lazy { ApplicationProvider.getApplicationContext<android.app.Application>() }
    private val appContext by lazy { ApplicationProvider.getApplicationContext<android.content.Context>() }

    @Before
    fun setUp() {
        RustPreferencesBridge.initialize(appContext)
        IronmeshPreferences.clearDeviceAuthState(appContext)
        RustClientTestBridge.stopRendezvousRenewalScenario()
    }

    @After
    fun tearDown() {
        RustClientTestBridge.stopRendezvousRenewalScenario()
        IronmeshPreferences.clearDeviceAuthState(appContext)
    }

    @Test
    fun storeIndex_renewsExpiredRendezvousCertificate_andPersistsUpdatedIdentity() {
        val scenario = JSONObject(RustClientTestBridge.startRendezvousRenewalScenario())
        val bootstrapJson = scenario.getString("connectionBootstrapJson")
        val expiredClientIdentityJson = scenario.getString("expiredClientIdentityJson")
        val expectedRenewedPem = scenario.getString("renewedRendezvousClientIdentityPem").trim()

        val seededState = deviceAuthState(
            connectionBootstrapJson = bootstrapJson,
            clientIdentityJson = expiredClientIdentityJson,
        )
        IronmeshPreferences.setDeviceAuthState(appContext, seededState)

        val authBeforeRequest = IronmeshPreferences.getDeviceAuthState(appContext)
        val responseJson = RustClientBridge.storeIndex(
            authBeforeRequest.preferredConnectionInput(),
            null,
            1,
            null,
            authBeforeRequest.serverCaPem,
            authBeforeRequest.toClientIdentityJson(),
        )

        val responseEntries = JSONObject(responseJson).getJSONArray("entries")
        assertTrue(responseEntries.length() >= 1)
        assertTrue(jsonArrayPaths(responseEntries).contains("docs/readme.txt"))

        val persisted = IronmeshPreferences.getDeviceAuthState(appContext)
        assertNotEquals(
            seededState.rendezvousClientIdentityPem,
            persisted.rendezvousClientIdentityPem,
        )
        assertEquals(expectedRenewedPem, persisted.rendezvousClientIdentityPem)
        assertEquals(seededState.clusterId, persisted.clusterId)
        assertEquals(seededState.deviceId, persisted.deviceId)
        assertEquals(seededState.publicKeyPem, persisted.publicKeyPem)
        assertEquals(seededState.privateKeyPem, persisted.privateKeyPem)
        assertEquals(seededState.credentialPem, persisted.credentialPem)

        val capturedPaths = jsonArrayStrings(RustClientTestBridge.getCapturedRequestPaths())
        assertTrue(
            "expected renewal request, got $capturedPaths",
            capturedPaths.contains("/api/v1/auth/device/renew-rendezvous-identity"),
        )
        assertTrue(
            "expected store index request, got $capturedPaths",
            capturedPaths.contains("/api/v1/store/index?depth=1"),
        )
    }

    @Test
    fun verifyEnrollmentAccess_reportsTheCompletedSignedRequestTimingAndRoute() = runBlocking {
        val scenario = JSONObject(RustClientTestBridge.startRendezvousRenewalScenario())
        val bootstrapJson = scenario.getString("connectionBootstrapJson")
        val expiredClientIdentityJson = scenario.getString("expiredClientIdentityJson")
        val authState = deviceAuthState(
            connectionBootstrapJson = bootstrapJson,
            clientIdentityJson = expiredClientIdentityJson,
        )

        val verification = IronmeshRepository().verifyEnrollmentAccess(authState)
        val detail = enrollmentVerificationSuccessDetail(verification)

        Log.i("EnrollmentDiagnosticsTest", detail)
        assertTrue("expected a non-negative verification duration", verification.elapsedMs >= 0L)
        assertNotNull("expected a route snapshot after signed access", verification.connectionRoutes)
        assertTrue(
            "expected completed store-index timing in '$detail'",
            detail.contains("request completed in"),
        )
    }

    @Test
    fun mainViewModel_reloadsPersistedIdentityBeforeBuildingClientRequests() {
        val scenario = JSONObject(RustClientTestBridge.startRendezvousRenewalScenario())
        val bootstrapJson = scenario.getString("connectionBootstrapJson")
        val expiredClientIdentityJson = scenario.getString("expiredClientIdentityJson")
        val expectedRenewedPem = scenario.getString("renewedRendezvousClientIdentityPem").trim()

        val expiredState = deviceAuthState(
            connectionBootstrapJson = bootstrapJson,
            clientIdentityJson = expiredClientIdentityJson,
        )
        IronmeshPreferences.setDeviceAuthState(appContext, expiredState)
        val viewModel = MainViewModel(application)

        val renewedState = expiredState.copy(rendezvousClientIdentityPem = expectedRenewedPem)
        IronmeshPreferences.setDeviceAuthState(appContext, renewedState)

        val method = MainViewModel::class.java.getDeclaredMethod("currentClientIdentityJson")
        method.isAccessible = true
        val reloadedIdentityJson = method.invoke(viewModel) as String
        val reloadedPem = JSONObject(reloadedIdentityJson)
            .getString("rendezvous_client_identity_pem")
            .trim()

        assertEquals(expectedRenewedPem, reloadedPem)
        assertEquals(
            expectedRenewedPem,
            viewModel.uiState.value.deviceAuthState.rendezvousClientIdentityPem,
        )
    }

    private fun deviceAuthState(
        connectionBootstrapJson: String,
        clientIdentityJson: String,
    ): DeviceAuthState {
        val json = JSONObject(clientIdentityJson)
        return DeviceAuthState(
            clusterId = json.requiredTrimmedString("cluster_id"),
            deviceId = json.requiredTrimmedString("device_id"),
            label = json.optionalTrimmedString("label"),
            connectionBootstrapJson = connectionBootstrapJson.trim(),
            directServerBaseUrl = "",
            serverCaPem = null,
            publicKeyPem = json.requiredTrimmedString("public_key_pem"),
            privateKeyPem = json.requiredTrimmedString("private_key_pem"),
            credentialPem = json.optionalTrimmedString("credential_pem"),
            rendezvousClientIdentityPem =
                json.optionalTrimmedString("rendezvous_client_identity_pem"),
        )
    }

    private fun jsonArrayStrings(raw: String): Set<String> {
        val array = JSONArray(raw)
        return jsonArrayPaths(array)
    }

    private fun jsonArrayPaths(array: JSONArray): Set<String> {
        val result = linkedSetOf<String>()
        for (index in 0 until array.length()) {
            val value = array.get(index)
            result += when (value) {
                is JSONObject -> value.getString("path")
                else -> value.toString()
            }
        }
        return result
    }

    private fun JSONObject.optionalTrimmedString(name: String): String? {
        if (!has(name) || isNull(name)) {
            return null
        }
        return getString(name).trim().takeIf { it.isNotEmpty() }
    }

    private fun JSONObject.requiredTrimmedString(name: String): String =
        optionalTrimmedString(name) ?: error("missing $name in client identity JSON")
}
