package expo.modules.updates.loader

import android.annotation.SuppressLint
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import expo.modules.structuredheaders.BooleanItem
import expo.modules.structuredheaders.Dictionary
import okhttp3.*
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import expo.modules.structuredheaders.Parser
import expo.modules.structuredheaders.StringItem
import expo.modules.updates.manifest.UpdateManifest

object Crypto {
  private val TAG = Crypto::class.java.simpleName

  const val CODE_SIGNING_METADATA_ALGORITHM_KEY = "alg"
  const val CODE_SIGNING_METADATA_KEY_ID_KEY = "keyid"

  const val CODE_SIGNING_METADATA_DEFAULT_KEY_ID = "root"
  const val CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_SIGNATURE = "sig"
  const val CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_KEY_ID = "keyid"
  const val CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_ALGORITHM = "alg"

  private const val EXPO_PUBLIC_KEY_URL = "https://exp.host/--/manifest-public-key"

  // ASN.1 path to the extended key usage info within a CERT
  private const val CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"

  fun verifyExpoPublicRSASignature(
    fileDownloader: FileDownloader,
    data: String,
    signature: String,
    listener: RSASignatureListener
  ) {
    fetchExpoPublicKeyAndVerifyPublicRSASignature(true, data, signature, fileDownloader, listener)
  }

  // On first attempt use cache. If verification fails try a second attempt without
  // cache in case the keys were actually rotated.
  // On second attempt reject promise if it fails.
  private fun fetchExpoPublicKeyAndVerifyPublicRSASignature(
    isFirstAttempt: Boolean,
    plainText: String,
    cipherText: String,
    fileDownloader: FileDownloader,
    listener: RSASignatureListener
  ) {
    val cacheControl = if (isFirstAttempt) CacheControl.FORCE_CACHE else CacheControl.FORCE_NETWORK
    val request = Request.Builder()
      .url(EXPO_PUBLIC_KEY_URL)
      .cacheControl(cacheControl)
      .build()
    fileDownloader.downloadData(
      request,
      object : Callback {
        override fun onFailure(call: Call, e: IOException) {
          listener.onError(e, true)
        }

        @Throws(IOException::class)
        override fun onResponse(call: Call, response: Response) {
          val exception: Exception = try {
            val isValid = verifyPublicRSASignature(response.body()!!.string(), plainText, cipherText)
            listener.onCompleted(isValid)
            return
          } catch (e: Exception) {
            e
          }
          if (isFirstAttempt) {
            fetchExpoPublicKeyAndVerifyPublicRSASignature(
              false,
              plainText,
              cipherText,
              fileDownloader,
              listener
            )
          } else {
            listener.onError(exception, false)
          }
        }
      }
    )
  }

  @Throws(
    NoSuchAlgorithmException::class,
    InvalidKeySpecException::class,
    InvalidKeyException::class,
    SignatureException::class
  )
  private fun verifyPublicRSASignature(
    publicKey: String,
    plainText: String,
    cipherText: String
  ): Boolean {
    // remove comments from public key
    val publicKeySplit = publicKey.split("\\r?\\n".toRegex()).toTypedArray()
    var publicKeyNoComments = ""
    for (line in publicKeySplit) {
      if (!line.contains("PUBLIC KEY-----")) {
        publicKeyNoComments += line + "\n"
      }
    }

    val signature = Signature.getInstance("SHA256withRSA")
    val decodedPublicKey = Base64.decode(publicKeyNoComments, Base64.DEFAULT)
    val publicKeySpec = X509EncodedKeySpec(decodedPublicKey)
    @SuppressLint("InlinedApi") val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
    val key = keyFactory.generatePublic(publicKeySpec)
    signature.initVerify(key)
    signature.update(plainText.toByteArray())
    return signature.verify(Base64.decode(cipherText, Base64.DEFAULT))
  }

  interface RSASignatureListener {
    fun onError(exception: Exception, isNetworkError: Boolean)
    fun onCompleted(isValid: Boolean)
  }

  enum class CodeSigningAlgorithm(val algorithmName: String) {
    RSA_SHA256("rsa-v1_5-sha256");

    companion object {
      fun parseFromString(str: String?): CodeSigningAlgorithm {
        return when (str) {
          RSA_SHA256.algorithmName -> RSA_SHA256
          null -> RSA_SHA256
          else -> throw Exception("Invalid code signing algorithm name: $str")
        }
      }
    }
  }

  interface ValidateSignatureCallback {
    fun onFailure(e: Exception)
    fun onSuccess()
  }

  data class CodeSigningConfiguration(
    private val embeddedCertificateChainAndMetadata: CertificateChainAndMetadata,
    private val requiresIntermediateCertificateAtUrl: String?
  ) {
    fun validateSignature(info: SignatureHeaderInfo, bodyBytes: ByteArray, callback: ValidateSignatureCallback) {
      val isSignatureValid = isSignatureValid(
        embeddedCertificateChainAndMetadata,
        info,
        bodyBytes
      )
      if (!isSignatureValid) {
        callback.onFailure(IOException("Manifest download was successful, but signature was incorrect"))
      } else {
        callback.onSuccess()
      }
    }
  }

  data class CertificateChain(val certificateChainCertificates: List<String>)

  data class CertificateChainAndMetadata(
    private val embeddedRootCertificateString: String,
    private val certificateChain: List<String>?,
    private val metadata: Map<String, String>?,
  ) {
    val codeSigningCertificate: X509Certificate by lazy {
      val embeddedRootCertificate = constructCertificate(embeddedRootCertificateString)
      if (embeddedRootCertificate.isCodeSigningCertificate()) {
        embeddedRootCertificate
      } else {
        if (certificateChain == null) {
          throw CertificateException("No code signing certificate found. Must have X509v3 Key Usage: Digital Signature and X509v3 Extended Key Usage: Code Signing")
        }
        val chainCertificates = certificateChain.map { constructCertificate(it) }
        val fullChain = chainCertificates.toMutableList().apply {
          add(embeddedRootCertificate)
          validateChain()
        }
        val leafCertificate = fullChain[0]
        if (!leafCertificate.isCodeSigningCertificate()) {
          throw CertificateException("Leaf certificate in chain is not a code signing certificate. Must have X509v3 Key Usage: Digital Signature and X509v3 Extended Key Usage: Code Signing")
        }
        leafCertificate
      }
    }

    val algorithm: CodeSigningAlgorithm by lazy {
      CodeSigningAlgorithm.parseFromString(metadata?.get(CODE_SIGNING_METADATA_ALGORITHM_KEY))
    }

    val keyId: String by lazy {
      metadata?.get(CODE_SIGNING_METADATA_KEY_ID_KEY) ?: CODE_SIGNING_METADATA_DEFAULT_KEY_ID
    }

    companion object {
      private fun constructCertificate(certificateString: String): X509Certificate {
        return (CertificateFactory.getInstance("X.509").generateCertificate(certificateString.byteInputStream()) as X509Certificate).apply {
          checkValidity()
        }
      }

      private fun X509Certificate.isCodeSigningCertificate(): Boolean {
        return keyUsage != null && keyUsage.isNotEmpty() && keyUsage[0] && extendedKeyUsage.contains(CODE_SIGNING_OID)
      }

      private fun List<X509Certificate>.validateChain() {
        for (i in 0 until size - 1) {
          val cert = get(i)
          val issuer = get(i + 1)
          if (cert.issuerX500Principal !== issuer.subjectX500Principal) {
            throw CertificateException("Certificates do not chain")
          }
          cert.verify(issuer.publicKey)
        }
        // last (root) must be self-signed, verify the final cert
        if (last().issuerX500Principal == last().subjectX500Principal) {
          last().verify(last().publicKey)
        }
      }
    }
  }

  fun createAcceptSignatureHeader(certificateChainAndMetadata: CertificateChainAndMetadata): String {
    return Dictionary.valueOf(
      mapOf(
        CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_SIGNATURE to BooleanItem.valueOf(true),
        CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_KEY_ID to StringItem.valueOf(certificateChainAndMetadata.keyId),
        CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_ALGORITHM to StringItem.valueOf(certificateChainAndMetadata.algorithm.algorithmName)
      )
    ).serialize()
  }

  data class SignatureHeaderInfo(val signature: String, val keyId: String, val algorithm: CodeSigningAlgorithm)

  fun parseSignatureHeader(signatureHeader: String?): SignatureHeaderInfo {
    if (signatureHeader == null) {
      throw Exception("No expo-signature header specified")
    }

    val signatureMap = Parser(signatureHeader).parseDictionary().get()

    val sigFieldValue = signatureMap[CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_SIGNATURE]
    val keyIdFieldValue = signatureMap[CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_KEY_ID]
    val algFieldValue = signatureMap[CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_ALGORITHM]

    val signature = if (sigFieldValue is StringItem) {
      sigFieldValue.get()
    } else throw Exception("Structured field $CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_SIGNATURE not found in expo-signature header")
    val keyId = if (keyIdFieldValue is StringItem) {
      keyIdFieldValue.get()
    } else CODE_SIGNING_METADATA_DEFAULT_KEY_ID
    val alg = if (algFieldValue is StringItem) {
      algFieldValue.get()
    } else null

    return SignatureHeaderInfo(signature, keyId, CodeSigningAlgorithm.parseFromString(alg))
  }

  fun isSignatureValid(certificateChainAndMetadata: CertificateChainAndMetadata, info: SignatureHeaderInfo, bytes: ByteArray): Boolean {
    val certificate = certificateChainAndMetadata.codeSigningCertificate

    // check that the key used to sign the response is the same as the key in the code signing certificate
    if (info.keyId != certificateChainAndMetadata.keyId) {
      throw Exception("Key with keyid=${info.keyId} from signature not found in client configuration")
    }

    // note that a mismatched algorithm doesn't fail early. it still tries to verify the signature with the
    // algorithm specified in the configuration
    if (info.algorithm != certificateChainAndMetadata.algorithm) {
      Log.i(TAG, "Key with alg=${info.algorithm} from signature does not match client configuration algorithm, continuing")
    }

    return Signature.getInstance(
      when (certificateChainAndMetadata.algorithm) {
        CodeSigningAlgorithm.RSA_SHA256 -> "SHA256withRSA"
      }
    ).apply {
      initVerify(certificate.publicKey)
      update(bytes)
    }.verify(Base64.decode(info.signature, Base64.DEFAULT))
  }
}
