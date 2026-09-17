package ai.openclaw.app.gateway

import ai.openclaw.app.SecurePrefs
import android.content.Context
import android.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest

/** Persistent device identity used to register this Android node with gateways. */
@Serializable
data class DeviceIdentity(
  val deviceId: String,
  val publicKeyRawBase64: String,
  val privateKeyPkcs8Base64: String,
  val createdAtMs: Long,
  val algorithm: String = DeviceIdentityStore.ALGORITHM_ED25519,
)

/** Owns device identity generation, persistence, and auth payload signatures. */
class DeviceIdentityStore private constructor(
  context: Context,
  private val prefs: SecurePrefs,
) {
  constructor(context: Context) : this(context, SecurePrefs(context))

  private val json = Json { ignoreUnknownKeys = true }
  private val legacyIdentityFile = File(context.filesDir, "openclaw/identity/device.json")

  @Volatile private var cachedIdentity: DeviceIdentity? = null

  /** Loads the persisted identity or creates one, repairing old device-id drift. */
  @Synchronized
  fun loadOrCreate(): DeviceIdentity {
    cachedIdentity?.let { return it }
    migrateLegacyIdentity()
    val existing = load()
    if (existing != null) {
      val derived = deriveDeviceId(existing.publicKeyRawBase64)
      if (derived != null && derived != existing.deviceId) {
        val updated = existing.copy(deviceId = derived)
        save(updated)
        cachedIdentity = updated
        return updated
      }
      cachedIdentity = existing
      return existing
    }
    val fresh = generate()
    save(fresh)
    cachedIdentity = fresh
    return fresh
  }

  /** Signs gateway connect payload text with the persisted device private key. */
  fun signPayload(
    payload: String,
    identity: DeviceIdentity,
  ): String? =
    try {
      // Use BC lightweight API directly; R8 can break JCA provider registration.
      val privateKeyBytes = Base64.decode(identity.privateKeyPkcs8Base64, Base64.DEFAULT)
      val privateKey = org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(privateKeyBytes)
      val signer =
        when (identity.algorithm) {
          ALGORITHM_ML_DSA_65 -> org.bouncycastle.crypto.signers.MLDSASigner()
          ALGORITHM_ED25519 -> org.bouncycastle.crypto.signers.Ed25519Signer()
          else -> error("Unsupported device identity algorithm: ${identity.algorithm}")
        }
      signer.init(true, privateKey)
      val payloadBytes = payload.toByteArray(Charsets.UTF_8)
      signer.update(payloadBytes, 0, payloadBytes.size)
      base64UrlEncode(signer.generateSignature())
    } catch (e: Throwable) {
      android.util.Log.e("DeviceAuth", "signPayload FAILED: ${e.javaClass.simpleName}: ${e.message}", e)
      null
    }

  /** Verifies a signature against the persisted public key for debug diagnostics. */
  fun verifySelfSignature(
    payload: String,
    signatureBase64Url: String,
    identity: DeviceIdentity,
  ): Boolean =
    try {
      val rawPublicKey = Base64.decode(identity.publicKeyRawBase64, Base64.DEFAULT)
      val pubKey =
        when (identity.algorithm) {
          ALGORITHM_ML_DSA_65 ->
            org.bouncycastle.crypto.params.MLDSAPublicKeyParameters(
              org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65,
              rawPublicKey,
            )
          ALGORITHM_ED25519 ->
            org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(rawPublicKey, 0)
          else -> error("Unsupported device identity algorithm: ${identity.algorithm}")
        }
      val sigBytes = base64UrlDecode(signatureBase64Url)
      val verifier =
        when (identity.algorithm) {
          ALGORITHM_ML_DSA_65 -> org.bouncycastle.crypto.signers.MLDSASigner()
          ALGORITHM_ED25519 -> org.bouncycastle.crypto.signers.Ed25519Signer()
          else -> error("Unsupported device identity algorithm: ${identity.algorithm}")
        }
      verifier.init(false, pubKey)
      val payloadBytes = payload.toByteArray(Charsets.UTF_8)
      verifier.update(payloadBytes, 0, payloadBytes.size)
      verifier.verifySignature(sigBytes)
    } catch (e: Throwable) {
      android.util.Log.e("DeviceAuth", "self-verify exception: ${e.message}", e)
      false
    }

  /** Decodes gateway URL-safe base64 signatures, accepting unpadded input. */
  private fun base64UrlDecode(input: String): ByteArray {
    val normalized = input.replace('-', '+').replace('_', '/')
    // Android Base64 expects padded input; gateway signatures are URL-safe
    // unpadded strings.
    val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
    return Base64.decode(padded, Base64.DEFAULT)
  }

  /** Returns the public key in the gateway's unpadded URL-safe base64 format. */
  fun publicKeyBase64Url(identity: DeviceIdentity): String? =
    try {
      val raw = Base64.decode(identity.publicKeyRawBase64, Base64.DEFAULT)
      base64UrlEncode(raw)
    } catch (_: Throwable) {
      null
    }

  private fun load(): DeviceIdentity? = readIdentity(prefs.getString(identityKey))

  private fun readIdentity(raw: String?): DeviceIdentity? {
    return try {
      if (raw == null) return null
      val decoded = json.decodeFromString(DeviceIdentity.serializer(), raw)
      if (decoded.deviceId.isBlank() ||
        decoded.publicKeyRawBase64.isBlank() ||
        decoded.privateKeyPkcs8Base64.isBlank()
      ) {
        null
      } else {
        decoded
      }
    } catch (_: Throwable) {
      null
    }
  }

  private fun migrateLegacyIdentity() {
    if (!legacyIdentityFile.exists()) return
    val legacy =
      runCatching { legacyIdentityFile.readText(Charsets.UTF_8) }
        .getOrNull()
        ?.let(::readIdentity)
    if (legacy == null) {
      legacyIdentityFile.delete()
      return
    }

    save(legacy)
    check(load() == legacy) { "Failed to migrate device identity to secure storage" }
    // Delete plaintext after verified import so secure prefs remain the only identity owner.
    // A fallback would expose the key again and can restore stale identity, breaking gateway pairing.
    check(legacyIdentityFile.delete() || !legacyIdentityFile.exists()) {
      "Failed to delete legacy device identity"
    }
  }

  private fun save(identity: DeviceIdentity) {
    val encoded = json.encodeToString(DeviceIdentity.serializer(), identity)
    check(prefs.putStringSynchronously(identityKey, encoded)) {
      "Failed to persist device identity"
    }
  }

  private fun generate(): DeviceIdentity {
    // Use BC's FIPS 204 lightweight API directly; provider registration is unreliable after R8.
    val kpGen =
      org.bouncycastle.crypto.generators
        .MLDSAKeyPairGenerator()
    kpGen.init(
      org.bouncycastle.crypto.params
        .MLDSAKeyGenerationParameters(
          java.security.SecureRandom(),
          org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65,
        ),
    )
    val kp = kpGen.generateKeyPair()
    val pubKey = kp.public as org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
    val privKey = kp.private as org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
    val rawPublic = pubKey.encoded
    val deviceId = sha256Hex(rawPublic)
    // Store private key as PKCS8 so signPayload can parse the same persisted
    // shape after app restarts and upgrades.
    val privKeyInfo =
      org.bouncycastle.crypto.util.PrivateKeyInfoFactory
        .createPrivateKeyInfo(privKey)
    val pkcs8Bytes = privKeyInfo.encoded
    return DeviceIdentity(
      deviceId = deviceId,
      publicKeyRawBase64 = Base64.encodeToString(rawPublic, Base64.NO_WRAP),
      privateKeyPkcs8Base64 = Base64.encodeToString(pkcs8Bytes, Base64.NO_WRAP),
      createdAtMs = System.currentTimeMillis(),
      algorithm = ALGORITHM_ML_DSA_65,
    )
  }

  /** Re-derives the stable device id from the raw Ed25519 public key bytes. */
  private fun deriveDeviceId(publicKeyRawBase64: String): String? =
    try {
      val raw = Base64.decode(publicKeyRawBase64, Base64.DEFAULT)
      sha256Hex(raw)
    } catch (_: Throwable) {
      null
    }

  private fun sha256Hex(data: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(data)
    val out = CharArray(digest.size * 2)
    var i = 0
    for (byte in digest) {
      val v = byte.toInt() and 0xff
      out[i++] = HEX[v ushr 4]
      out[i++] = HEX[v and 0x0f]
    }
    return String(out)
  }

  private fun base64UrlEncode(data: ByteArray): String =
    Base64.encodeToString(
      data,
      Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
    )

  companion object {
    const val ALGORITHM_ED25519 = "ed25519"
    const val ALGORITHM_ML_DSA_65 = "ml-dsa-65"
    private const val identityKey = "device.identity"
    private val HEX = "0123456789abcdef".toCharArray()

    internal fun withPrefs(
      context: Context,
      prefs: SecurePrefs,
    ): DeviceIdentityStore = DeviceIdentityStore(context, prefs)
  }
}
