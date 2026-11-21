package kr.eumsoft.securitypro.data.updater

import java.security.MessageDigest
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec

/** 테스트용 Ed25519 키/서명 도구(앱에는 포함되지 않는다). */
object Ed25519TestKeys {

    private val curve by lazy {
        EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
    }

    data class KeyPair(val publicKeyHex: String, val privateKey: EdDSAPrivateKey)

    fun generate(seed: ByteArray = ByteArray(32) { (it * 7 + 3).toByte() }): KeyPair {
        val privateKey = EdDSAPrivateKey(EdDSAPrivateKeySpec(seed, curve))
        val publicKeyHex = privateKey.abyte.joinToString("") { "%02x".format(it) }
        return KeyPair(publicKeyHex, privateKey)
    }

    fun sign(keyPair: KeyPair, message: ByteArray): ByteArray {
        val engine = EdDSAEngine(MessageDigest.getInstance(curve.hashAlgorithm))
        engine.initSign(keyPair.privateKey)
        engine.update(message)
        return engine.sign()
    }

    fun base64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)
}
