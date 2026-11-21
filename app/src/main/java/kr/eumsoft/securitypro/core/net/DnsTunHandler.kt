package kr.eumsoft.securitypro.core.net

import kr.eumsoft.securitypro.core.dns.BlockResponseMode
import kr.eumsoft.securitypro.core.dns.DecisionReason
import kr.eumsoft.securitypro.core.dns.DnsFilterEngine
import kr.eumsoft.securitypro.core.dns.DnsRcode
import kr.eumsoft.securitypro.core.dns.DnsWire

/** DNS 요청 1건의 처리 결과(통계/로그용). */
data class DnsEvent(
    val domain: String,
    val type: Int,
    val blocked: Boolean,
    val allowedByUser: Boolean,
    val category: String?,
    val sourceId: Long?,
    val matchedRule: String?,
    val cached: Boolean,
    val upstreamFailed: Boolean,
    val at: Long,
)

/**
 * TUN 에서 읽은 패킷 1개를 처리해 앱으로 돌려줄 패킷을 만든다.
 *
 * - DNS(UDP/53)가 아니면 null(폐기) — 이 VPN 은 DNS 전용이며 나머지 트래픽은 라우팅하지 않는다.
 * - 차단 규칙에 걸리면 NXDOMAIN/0.0.0.0 응답을 직접 만든다.
 * - 허용이면 업스트림(시스템 DNS/DoH/DoT)으로 전달하고 응답을 재포장한다.
 *
 * Android API 에 의존하지 않으므로 실제 패킷 바이트로 단위 테스트한다.
 */
class DnsTunHandler(
    private val engineProvider: () -> DnsFilterEngine?,
    private val blockingEnabled: () -> Boolean = { true },
    private val responseMode: () -> BlockResponseMode = { BlockResponseMode.NXDOMAIN },
    private val upstream: DnsUpstream?,
    private val cache: DnsResponseCache = DnsResponseCache(),
    private val onEvent: (DnsEvent) -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis,
) {

    suspend fun handle(packet: ByteArray, length: Int = packet.size): ByteArray? {
        val info = IpPackets.parseUdp(packet, length) ?: return null
        if (!info.isDnsQuery) return null
        val query = DnsWire.parseQuery(info.payload, info.payload.size) ?: return null
        val question = query.firstQuestion ?: return null
        val domain = question.name
        val type = question.type
        val now = clock()

        val decision = if (blockingEnabled()) {
            engineProvider()?.evaluate(domain, type)
        } else {
            null
        }

        if (decision != null && decision.blocked) {
            val response = DnsWire.buildBlockResponse(query, responseMode())
            onEvent(
                DnsEvent(
                    domain = domain,
                    type = type,
                    blocked = true,
                    allowedByUser = false,
                    category = decision.category,
                    sourceId = decision.sourceId,
                    matchedRule = decision.matchedRule,
                    cached = false,
                    upstreamFailed = false,
                    at = now,
                )
            )
            return wrap(info, response)
        }

        // 허용: 캐시 → 업스트림
        val cached = cache.get(domain, type, now)
        if (cached != null) {
            onEvent(
                DnsEvent(
                    domain = domain,
                    type = type,
                    blocked = false,
                    allowedByUser = decision?.reason == DecisionReason.USER_ALLOW,
                    category = decision?.category,
                    sourceId = null,
                    matchedRule = null,
                    cached = true,
                    upstreamFailed = false,
                    at = now,
                )
            )
            return wrap(info, DnsWire.rewriteId(cached, query.id))
        }

        val upstreamResponse = try {
            upstream?.resolve(query.withOriginalId())
        } catch (_: Exception) {
            null
        }
        if (upstreamResponse == null || upstreamResponse.size < 12) {
            val response = DnsWire.buildErrorResponse(query, DnsRcode.SERVFAIL)
            onEvent(
                DnsEvent(
                    domain = domain,
                    type = type,
                    blocked = false,
                    allowedByUser = decision?.reason == DecisionReason.USER_ALLOW,
                    category = decision?.category,
                    sourceId = null,
                    matchedRule = null,
                    cached = false,
                    upstreamFailed = true,
                    at = now,
                )
            )
            return wrap(info, response)
        }
        cache.put(domain, type, upstreamResponse, now)
        onEvent(
            DnsEvent(
                domain = domain,
                type = type,
                blocked = false,
                allowedByUser = decision?.reason == DecisionReason.USER_ALLOW,
                category = decision?.category,
                sourceId = null,
                matchedRule = null,
                cached = false,
                upstreamFailed = false,
                at = now,
            )
        )
        return wrap(info, DnsWire.rewriteId(upstreamResponse, query.id))
    }

    /** 응답 바이트를 원래 질의의 출발지로 돌려보내는 IP/UDP 패킷으로 감싼다. */
    private fun wrap(info: UdpPacketInfo, dnsResponse: ByteArray): ByteArray =
        if (info.ipv6) {
            IpPackets.buildIpv6Udp(
                sourceAddress = info.destinationAddress,
                destinationAddress = info.sourceAddress,
                sourcePort = 53,
                destinationPort = info.sourcePort,
                payload = dnsResponse,
            )
        } else {
            IpPackets.buildIpv4Udp(
                sourceAddress = info.destinationAddress,
                destinationAddress = info.sourceAddress,
                sourcePort = 53,
                destinationPort = info.sourcePort,
                payload = dnsResponse,
            )
        }

    private fun kr.eumsoft.securitypro.core.dns.DnsQuery.withOriginalId(): ByteArray {
        // 업스트림에는 원본 질의 바이트를 그대로 보낸다(트랜잭션 ID 유지).
        val out = java.io.ByteArrayOutputStream(questionSection.size + 12)
        out.write((id shr 8) and 0xFF)
        out.write(id and 0xFF)
        out.write((flags shr 8) and 0xFF)
        out.write(flags and 0xFF)
        out.write(0)
        out.write(questions.size)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(questionSection)
        return out.toByteArray()
    }
}
