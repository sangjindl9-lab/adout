package kr.eumsoft.securitypro.core.dns

/**
 * DNS 와이어 포맷(RFC 1035) 파서/생성기.
 *
 * 이 파일은 Android API 에 의존하지 않는 순수 Kotlin 이므로 단위 테스트에서
 * 실제 바이트 패킷으로 검증할 수 있다.
 */

object DnsType {
    const val A = 1
    const val NS = 2
    const val CNAME = 5
    const val SOA = 6
    const val PTR = 12
    const val MX = 15
    const val TXT = 16
    const val AAAA = 28
    const val SRV = 33
    const val OPT = 41
    const val HTTPS = 65
    const val ANY = 255

    fun nameOf(code: Int): String = when (code) {
        A -> "A"
        NS -> "NS"
        CNAME -> "CNAME"
        SOA -> "SOA"
        PTR -> "PTR"
        MX -> "MX"
        TXT -> "TXT"
        AAAA -> "AAAA"
        SRV -> "SRV"
        OPT -> "OPT"
        HTTPS -> "HTTPS"
        ANY -> "ANY"
        else -> "TYPE$code"
    }
}

const val DNS_CLASS_IN = 1
const val DNS_HEADER_SIZE = 12
const val DNS_MAX_NAME_LENGTH = 253
const val DNS_MAX_UDP_PAYLOAD = 4096

/** DNS 응답 코드. */
object DnsRcode {
    const val NO_ERROR = 0
    const val FORMERR = 1
    const val SERVFAIL = 2
    const val NXDOMAIN = 3
    const val NOTIMP = 4
    const val REFUSED = 5
}

data class DnsQuestion(
    val name: String,
    val type: Int,
    val qclass: Int,
)

/** 파싱된 DNS 질의(헤더 + 질의 섹션). */
class DnsQuery(
    val id: Int,
    val flags: Int,
    val questions: List<DnsQuestion>,
    /** 원본 질의 섹션 바이트(응답에 그대로 되돌려 준다). */
    val questionSection: ByteArray,
) {
    val isRecursionDesired: Boolean get() = (flags and 0x0100) != 0
    val firstQuestion: DnsQuestion? get() = questions.firstOrNull()
    val firstDomain: String? get() = questions.firstOrNull()?.name
}

internal fun ByteArray.u8(index: Int): Int = this[index].toInt() and 0xFF

internal fun ByteArray.u16(index: Int): Int = (u8(index) shl 8) or u8(index + 1)

internal fun ByteArray.u32(index: Int): Long =
    (u8(index).toLong() shl 24) or
        (u8(index + 1).toLong() shl 16) or
        (u8(index + 2).toLong() shl 8) or
        u8(index + 3).toLong()

object DnsWire {

    /** 도메인 정규화: 소문자, 후행 점 제거, 공백 제거. */
    fun normalizeDomain(raw: String): String =
        raw.trim().trimEnd('.').lowercase()

    /**
     * DNS 질의 파싱. 질의(QR=0)가 아니거나 형식이 잘못되면 null.
     */
    fun parseQuery(data: ByteArray, length: Int = data.size): DnsQuery? {
        if (length < DNS_HEADER_SIZE || length > data.size) return null
        val id = data.u16(0)
        val flags = data.u16(2)
        val isResponse = (flags and 0x8000) != 0
        if (isResponse) return null
        val qdCount = data.u16(4)
        if (qdCount <= 0 || qdCount > 8) return null

        val questions = ArrayList<DnsQuestion>(qdCount)
        var offset = DNS_HEADER_SIZE
        val questionStart = offset
        repeat(qdCount) {
            val decoded = readName(data, offset, length) ?: return null
            offset = decoded.second
            if (offset + 4 > length) return null
            val type = data.u16(offset)
            val qclass = data.u16(offset + 2)
            offset += 4
            questions += DnsQuestion(decoded.first, type, qclass)
        }
        val questionSection = data.copyOfRange(questionStart, offset)
        return DnsQuery(id, flags, questions, questionSection)
    }

    /**
     * 압축 포인터를 안전하게 따라가며 이름을 읽는다.
     * 반환값: (이름, 이름 뒤 첫 오프셋)
     */
    fun readName(data: ByteArray, start: Int, limit: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var offset = start
        var afterName = -1
        var jumps = 0
        var bytesConsumed = 0
        while (true) {
            if (offset >= limit) return null
            val len = data.u8(offset)
            when {
                len == 0 -> {
                    offset += 1
                    if (afterName < 0) afterName = offset
                    break
                }
                len and 0xC0 == 0xC0 -> {
                    // 압축 포인터
                    if (offset + 1 >= limit) return null
                    val pointer = ((len and 0x3F) shl 8) or data.u8(offset + 1)
                    if (afterName < 0) afterName = offset + 2
                    if (pointer >= offset) return null // 앞으로만 이동(루프 방지)
                    offset = pointer
                    jumps++
                    if (jumps > 16) return null
                }
                len and 0xC0 != 0 -> return null
                else -> {
                    if (len > 63 || offset + 1 + len > limit) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    sb.append(String(data, offset + 1, len, Charsets.US_ASCII))
                    bytesConsumed += len + 1
                    if (bytesConsumed > DNS_MAX_NAME_LENGTH + 64) return null
                    offset += len + 1
                }
            }
        }
        val name = normalizeDomain(sb.toString())
        if (name.length > DNS_MAX_NAME_LENGTH) return null
        return name to (afterName.coerceAtLeast(offset))
    }

    /** RFC 1035 이름 인코딩(포인터 없음). */
    fun encodeName(name: String): ByteArray {
        val normalized = normalizeDomain(name)
        if (normalized.isEmpty()) return byteArrayOf(0)
        val out = java.io.ByteArrayOutputStream(normalized.length + 2)
        normalized.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "라벨 길이 오류: $label" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    /**
     * 질의에 대한 응답 생성.
     *
     * @param answers 추가할 응답 레코드(없으면 빈 응답)
     */
    fun buildResponse(
        query: DnsQuery,
        rcode: Int,
        answers: List<DnsAnswer> = emptyList(),
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream(512)
        writeU16(out, query.id)
        // QR=1, opcode 유지, AA=1, RD 유지, RA=1
        var flags = 0x8000 or 0x0400
        if (query.isRecursionDesired) flags = flags or 0x0100
        flags = flags or 0x0080
        flags = flags or (rcode and 0x000F)
        writeU16(out, flags)
        writeU16(out, query.questions.size)
        writeU16(out, answers.size)
        writeU16(out, 0)
        writeU16(out, 0)
        out.write(query.questionSection)
        answers.forEach { answer ->
            writeU16(out, 0xC000 or DNS_HEADER_SIZE) // 첫 질의 이름을 가리키는 포인터
            writeU16(out, answer.type)
            writeU16(out, DNS_CLASS_IN)
            writeU32(out, answer.ttl)
            writeU16(out, answer.rdata.size)
            out.write(answer.rdata)
        }
        return out.toByteArray()
    }

    /** FORMERR/SERVFAIL 처럼 질의만 되돌려 주는 최소 응답. */
    fun buildErrorResponse(query: DnsQuery, rcode: Int): ByteArray = buildResponse(query, rcode)

    /** 차단 응답: NXDOMAIN 또는 0.0.0.0 / :: . */
    fun buildBlockResponse(query: DnsQuery, mode: BlockResponseMode): ByteArray =
        when (mode) {
            BlockResponseMode.NXDOMAIN -> buildResponse(query, DnsRcode.NXDOMAIN)
            BlockResponseMode.NULL_IP -> {
                val answers = query.questions.mapNotNull { question ->
                    when (question.type) {
                        DnsType.A -> DnsAnswer(DnsType.A, 60, ByteArray(4))
                        DnsType.AAAA -> DnsAnswer(DnsType.AAAA, 60, ByteArray(16))
                        else -> null
                    }
                }
                buildResponse(query, if (answers.isEmpty()) DnsRcode.NO_ERROR else DnsRcode.NO_ERROR, answers)
            }
        }

    /**
     * 응답의 최소 TTL(초). 캐시 수명 계산에 사용한다.
     * 실패 응답은 캐시하지 않도록 0 을 돌려준다.
     */
    fun minTtl(data: ByteArray, length: Int = data.size): Int {
        if (length < DNS_HEADER_SIZE) return 0
        val flags = data.u16(2)
        if ((flags and 0x8000) == 0) return 0
        val rcode = flags and 0x000F
        if (rcode != DnsRcode.NO_ERROR) return 0
        val qd = data.u16(4)
        val an = data.u16(6)
        if (an <= 0) return 0
        var offset = DNS_HEADER_SIZE
        repeat(qd) {
            val decoded = readName(data, offset, length) ?: return 0
            offset = decoded.second + 4
        }
        var min = Int.MAX_VALUE
        repeat(an) {
            val decoded = readName(data, offset, length) ?: return 0
            offset = decoded.second
            if (offset + 10 > length) return 0
            val ttl = data.u32(offset + 4).toInt()
            val rdLength = data.u16(offset + 8)
            offset += 10 + rdLength
            if (ttl in 1..min) min = ttl
        }
        return if (min == Int.MAX_VALUE) 0 else min
    }

    /** 응답의 응답 코드(실패 시 -1). */
    fun rcodeOf(data: ByteArray, length: Int = data.size): Int {
        if (length < DNS_HEADER_SIZE) return -1
        return data.u16(2) and 0x000F
    }

    /** 응답의 트랜잭션 ID 를 질의 ID 로 맞춘다. */
    fun rewriteId(data: ByteArray, newId: Int): ByteArray {
        if (data.size < 2) return data
        val copy = data.copyOf()
        copy[0] = ((newId shr 8) and 0xFF).toByte()
        copy[1] = (newId and 0xFF).toByte()
        return copy
    }

    private fun writeU16(out: java.io.ByteArrayOutputStream, value: Int) {
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU32(out: java.io.ByteArrayOutputStream, value: Long) {
        out.write(((value shr 24) and 0xFF).toInt())
        out.write(((value shr 16) and 0xFF).toInt())
        out.write(((value shr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }
}

data class DnsAnswer(
    val type: Int,
    val ttl: Long,
    val rdata: ByteArray,
)

enum class BlockResponseMode {
    /** NXDOMAIN(도메인 없음) — 앱이 즉시 실패를 인지한다. */
    NXDOMAIN,

    /** 0.0.0.0 / :: 응답 — 일부 앱이 더 빨리 포기한다. */
    NULL_IP,
}
