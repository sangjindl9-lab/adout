package kr.eumsoft.securitypro.data.updater

import java.security.MessageDigest
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

/**
 * Ed25519 서명 검증(순수 자바 구현, Android 10+ 호환).
 *
 * 플랫폼 JCA 의 Ed25519 는 Android 13(API 33)부터 제공되므로, minSdk 29 를 지원하기 위해
 * 검증된 서드파티 구현(net.i2p.crypto.eddsa, CC0)을 사용한다.
 */
object Ed25519 {

    private val CURVE by lazy { EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519) }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        return try {
            val key = EdDSAPublicKey(EdDSAPublicKeySpec(publicKey, CURVE))
            val engine = EdDSAEngine(MessageDigest.getInstance(CURVE.hashAlgorithm))
            engine.initVerify(key)
            engine.update(message)
            engine.verify(signature)
        } catch (_: Exception) {
            false
        }
    }

    fun isValidPublicKey(hex: String): Boolean =
        hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length % 2 == 0) { "hex 길이가 홀수입니다." }
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(clean[i * 2], 16) shl 4) or Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
        return out
    }
}
