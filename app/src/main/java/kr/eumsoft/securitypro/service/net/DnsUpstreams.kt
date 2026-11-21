package kr.eumsoft.securitypro.service.net

import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kr.eumsoft.securitypro.core.dns.DnsWire
import kr.eumsoft.securitypro.core.net.DnsUpstream
import kr.eumsoft.securitypro.data.prefs.DnsMode

/** VpnService.protect() 를 감싼 소켓 팩토리. 터널 재진입을 막는다. */
interface SocketProtector {
    fun protect(socket: Socket): Boolean
    fun protect(socket: DatagramSocket): Boolean
}

/**
 * 시스템 DNS 로 전달(가장 호환성이 높다).
 *
 * 현재 네트워크의 DNS 서버를 사용하며, 없으면 공용 리졸버로 대체한다.
 */
class SystemDnsUpstream(
    private val protector: SocketProtector,
    private val connectivity: ConnectivityManager?,
    override val description: String = "시스템 DNS",
) : DnsUpstream {

    override suspend fun resolve(query: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        val servers = currentServers()
        for (server in servers) {
            val response = udpExchange(server, query)
            if (response != null) return@withContext response
        }
        null
    }

    private fun currentServers(): List<InetAddress> {
        val result = ArrayList<InetAddress>()
        try {
            val network: Network? = connectivity?.activeNetwork
            if (network != null) {
                val props = connectivity.getLinkProperties(network)
                props?.dnsServers?.forEach { result += it }
            }
        } catch (_: Exception) {
            // 권한/상태 문제 시 공용 리졸버로 대체
        }
        if (result.isEmpty()) {
            FALLBACK.forEach { result += InetAddress.getByName(it) }
        }
        return result.take(3)
    }

    private fun udpExchange(server: InetAddress, query: ByteArray): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            protector.protect(socket)
            socket.soTimeout = 4000
            val packet = DatagramPacket(query, query.size, server, 53)
            socket.send(packet)
            val buffer = ByteArray(4096)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            val data = response.data.copyOfRange(response.offset, response.offset + response.length)
            if (DnsWire.rcodeOf(data) < 0) null else data
        } catch (_: Exception) {
            null
        } finally {
            socket?.close()
        }
    }

    companion object {
        private val FALLBACK = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")
    }
}

/**
 * DNS-over-HTTPS(RFC 8484). POST application/dns-message.
 * TLS 소켓을 직접 보호(protect)한 뒤 HTTP/1.1 로 요청한다.
 */
class DohUpstream(
    private val protector: SocketProtector,
    private val host: String,
    private val path: String,
    override val description: String,
) : DnsUpstream {

    override suspend fun resolve(query: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        var raw: Socket? = null
        var tls: SSLSocket? = null
        try {
            raw = Socket()
            protector.protect(raw)
            raw.connect(InetSocketAddress(host, 443), 5000)
            raw.soTimeout = 6000
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            tls = factory.createSocket(raw, host, 443, true) as SSLSocket
            tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            tls.startHandshake()
            val request = buildString {
                append("POST $path HTTP/1.1\r\n")
                append("Host: $host\r\n")
                append("User-Agent: EUM-SECURITY-PRO/1.0\r\n")
                append("Accept: application/dns-message\r\n")
                append("Content-Type: application/dns-message\r\n")
                append("Content-Length: ${query.size}\r\n")
                append("Connection: close\r\n\r\n")
            }.toByteArray(Charsets.ISO_8859_1)
            val out = tls.outputStream
            out.write(request)
            out.write(query)
            out.flush()
            val response = readHttpResponse(tls.inputStream)
            response
        } catch (_: Exception) {
            null
        } finally {
            runCatching { tls?.close() }
            runCatching { raw?.close() }
        }
    }

    private fun readHttpResponse(input: java.io.InputStream): ByteArray? {
        val data = DataInputStream(input)
        val statusLine = readLine(data) ?: return null
        if (!statusLine.contains(" 200")) return null
        var contentLength = -1
        while (true) {
            val line = readLine(data) ?: break
            if (line.isEmpty()) break
            if (line.startsWith("Content-Length:", true)) {
                contentLength = line.substringAfter(':').trim().toIntOrNull() ?: -1
            }
        }
        if (contentLength <= 0 || contentLength > 65535) return null
        val body = ByteArray(contentLength)
        DataInputStream(input).readFully(body)
        return body
    }

    private fun readLine(input: DataInputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return null
            if (b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
            if (sb.length > 2048) return null
        }
        return sb.toString()
    }
}

/** DNS-over-TLS(RFC 7858). 2바이트 길이 프리픽스로 질의/응답을 주고받는다. */
class DotUpstream(
    private val protector: SocketProtector,
    private val host: String,
    override val description: String,
) : DnsUpstream {

    override suspend fun resolve(query: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        var raw: Socket? = null
        var tls: SSLSocket? = null
        try {
            raw = Socket()
            protector.protect(raw)
            raw.connect(InetSocketAddress(host, 853), 5000)
            raw.soTimeout = 6000
            tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(raw, host, 853, true) as SSLSocket
            tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            tls.startHandshake()
            val out = DataOutputStream(tls.outputStream)
            out.writeShort(query.size)
            out.write(query)
            out.flush()
            val input = DataInputStream(tls.inputStream)
            val length = input.readUnsignedShort()
            if (length <= 0 || length > 65535) return@withContext null
            val response = ByteArray(length)
            input.readFully(response)
            response
        } catch (_: Exception) {
            null
        } finally {
            runCatching { tls?.close() }
            runCatching { raw?.close() }
        }
    }
}

/** 사용자가 설정한 DNS 모드에 맞는 업스트림을 만든다. */
object UpstreamFactory {

    data class Provider(val host: String, val path: String, val label: String)

    private val DOH_PROVIDERS = mapOf(
        "cloudflare" to Provider("cloudflare-dns.com", "/dns-query", "Cloudflare DoH"),
        "google" to Provider("dns.google", "/dns-query", "Google DoH"),
        "adguard" to Provider("dns.adguard-dns.com", "/dns-query", "AdGuard DoH"),
    )

    private val DOT_PROVIDERS = mapOf(
        "cloudflare" to Provider("one.one.one.one", "", "Cloudflare DoT"),
        "google" to Provider("dns.google", "", "Google DoT"),
        "adguard" to Provider("dns.adguard-dns.com", "", "AdGuard DoT"),
    )

    fun create(
        mode: DnsMode,
        provider: String,
        customHost: String,
        protector: SocketProtector,
        connectivity: ConnectivityManager?,
    ): DnsUpstream = when (mode) {
        DnsMode.SYSTEM -> SystemDnsUpstream(protector, connectivity)
        DnsMode.DOH -> {
            val config = if (provider == "custom" && customHost.isNotBlank()) {
                Provider(customHost, "/dns-query", "사용자 DoH")
            } else {
                DOH_PROVIDERS[provider] ?: DOH_PROVIDERS.getValue("cloudflare")
            }
            DohUpstream(protector, config.host, config.path, config.label)
        }
        DnsMode.DOT -> {
            val config = if (provider == "custom" && customHost.isNotBlank()) {
                Provider(customHost, "", "사용자 DoT")
            } else {
                DOT_PROVIDERS[provider] ?: DOT_PROVIDERS.getValue("cloudflare")
            }
            DotUpstream(protector, config.host, config.label)
        }
    }

    fun randomId(): Int = SecureRandom().nextInt(0xFFFF)
}
