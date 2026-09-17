package ai.openclaw.app.gateway

import ai.openclaw.app.SecurePrefs
import android.content.Context
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.util.Base64
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DeviceIdentityStoreTest {
  private val app get() = RuntimeEnvironment.getApplication()
  private val legacyFile get() = File(app.filesDir, "openclaw/identity/device.json")

  @Before
  fun setUp() {
    legacyFile.delete()
  }

  @After
  fun tearDown() {
    legacyFile.delete()
  }

  @Test
  fun migratesLegacyIdentityAndKeepsItStableAcrossReopen() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)
    val seed = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()
    backing.edit().clear().commit()
    legacyFile.parentFile?.mkdirs()
    legacyFile.writeText(Json.encodeToString(seed), Charsets.UTF_8)

    val migrated = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()

    assertEquals(seed, migrated)
    assertFalse(legacyFile.exists())
    assertEquals(migrated, DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate())
  }

  @Test
  fun freshInstallPersistsIdentityOnlyInSecurePrefs() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)

    val created = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()

    assertFalse(legacyFile.exists())
    assertEquals(DeviceIdentityStore.ALGORITHM_ML_DSA_65, created.algorithm)
    val signature = DeviceIdentityStore.withPrefs(app, prefs).signPayload("gateway-proof", created)
    assertTrue(signature != null)
    assertTrue(
      DeviceIdentityStore.withPrefs(app, prefs)
        .verifySelfSignature("gateway-proof", signature!!, created),
    )
    assertEquals(created, DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate())
  }

  @Test
  fun corruptedLegacyFileIsDeletedAndReplacedWithStableIdentity() {
    val backing = newBackingPrefs()
    val prefs = SecurePrefs(app, securePrefsOverride = backing)
    legacyFile.parentFile?.mkdirs()
    legacyFile.writeText("{not-json", Charsets.UTF_8)

    val regenerated = DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate()

    assertFalse(legacyFile.exists())
    assertEquals(regenerated, DeviceIdentityStore.withPrefs(app, prefs).loadOrCreate())
  }

  @Test
  fun sharedFips204VectorVerifiesWithBouncyCastle() {
    val fixture = findRepositoryFixture("test/fixtures/pqc/ml-dsa-65-fips204.json")
    val vector = Json.parseToJsonElement(fixture.readText()).jsonObject
    val decode = Base64.getUrlDecoder()::decode
    val publicKey = decode(vector.getValue("publicKeyBase64Url").jsonPrimitive.content)
    val signature = decode(vector.getValue("deterministicSignatureBase64Url").jsonPrimitive.content)
    val message = vector.getValue("messageUtf8").jsonPrimitive.content.toByteArray(Charsets.UTF_8)
    val verifier = org.bouncycastle.crypto.signers.MLDSASigner()
    verifier.init(
      false,
      org.bouncycastle.crypto.params.MLDSAPublicKeyParameters(
        org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65,
        publicKey,
      ),
    )
    verifier.update(message, 0, message.size)

    assertTrue(verifier.verifySignature(signature))
  }

  private fun findRepositoryFixture(path: String): File {
    var current = File(System.getProperty("user.dir")).canonicalFile
    repeat(8) {
      val candidate = File(current, path)
      if (candidate.isFile) return candidate
      current = current.parentFile ?: return@repeat
    }
    error("Could not locate repository fixture: $path")
  }

  private fun newBackingPrefs() =
    app.getSharedPreferences(
      "device-identity-test-${UUID.randomUUID()}",
      Context.MODE_PRIVATE,
    )
}
