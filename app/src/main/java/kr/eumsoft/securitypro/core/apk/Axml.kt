package kr.eumsoft.securitypro.core.apk

/**
 * Android Binary XML(AXML) 파서.
 *
 * APK 안의 AndroidManifest.xml 은 텍스트가 아니라 리소스 청크 형식이다. 이 파서는
 * 외부 라이브러리 없이 문자열 풀/리소스 맵/엘리먼트 청크를 직접 해석한다.
 * 손상된 입력에 대비해 모든 길이 값을 경계 검사하고, 중첩 깊이와 엘리먼트 수를 제한한다.
 */
object Axml {

    private const val RES_XML_TYPE = 0x0003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
    private const val RES_XML_START_ELEMENT = 0x0102
    private const val RES_XML_END_ELEMENT = 0x0103
    private const val RES_XML_CDATA = 0x0104
    private const val RES_XML_START_NAMESPACE = 0x0100
    private const val RES_XML_END_NAMESPACE = 0x0101

    private const val TYPE_REFERENCE = 0x01
    private const val TYPE_STRING = 0x03
    private const val TYPE_FLOAT = 0x04
    private const val TYPE_DIMENSION = 0x05
    private const val TYPE_FRACTION = 0x06
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12

    private const val MAX_ELEMENTS = 20_000
    private const val MAX_DEPTH = 64

    data class Attr(
        val namespace: String?,
        val name: String,
        val rawValue: String?,
        val type: Int,
        val data: Int,
    ) {
        val stringValue: String?
            get() = rawValue

        val intValue: Int?
            get() = when (type) {
                TYPE_INT_DEC, TYPE_INT_HEX -> data
                TYPE_INT_BOOLEAN -> if (data != 0) 1 else 0
                else -> rawValue?.toIntOrNull()
            }

        val boolValue: Boolean?
            get() = when (type) {
                TYPE_INT_BOOLEAN -> data != 0
                TYPE_INT_DEC, TYPE_INT_HEX -> data != 0
                else -> when (rawValue?.lowercase()) {
                    "true" -> true
                    "false" -> false
                    else -> null
                }
            }
    }

    data class Element(
        val name: String,
        val attributes: List<Attr>,
        val children: List<Element>,
    ) {
        fun attr(name: String): Attr? =
            attributes.firstOrNull { it.name == name && (it.namespace == null || it.namespace == ANDROID_NS) }
                ?: attributes.firstOrNull { it.name == name }

        fun child(name: String): Element? = children.firstOrNull { it.name == name }

        fun childrenNamed(name: String): List<Element> = children.filter { it.name == name }
    }

    const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

    /** 파싱 결과. 형식이 아니면 null. */
    fun parse(bytes: ByteArray): Element? {
        if (bytes.size < 8) return null
        val rootType = u16(bytes, 0)
        if (rootType != RES_XML_TYPE) return null
        val rootHeaderSize = u16(bytes, 2)
        val rootSize = u32(bytes, 4).toInt()
        val end = if (rootSize in 8..bytes.size) rootSize else bytes.size

        var stringPool: List<String>? = null
        var resourceIds: IntArray? = null
        val stack = ArrayList<MutableElement>()
        var root: MutableElement? = null
        var offset = rootHeaderSize
        var elementCount = 0

        while (offset + 8 <= end) {
            val type = u16(bytes, offset)
            val headerSize = u16(bytes, offset + 2)
            val chunkSize = u32(bytes, offset + 4).toInt()
            if (headerSize < 8 || chunkSize < headerSize || offset + chunkSize > end) break

            when (type) {
                RES_STRING_POOL_TYPE -> {
                    stringPool = readStringPool(bytes, offset, headerSize, chunkSize)
                }
                RES_XML_RESOURCE_MAP_TYPE -> {
                    val count = (chunkSize - headerSize) / 4
                    val ids = IntArray(count)
                    for (i in 0 until count) {
                        ids[i] = u32(bytes, offset + headerSize + i * 4).toInt()
                    }
                    resourceIds = ids
                }
                RES_XML_START_ELEMENT -> {
                    val pool = stringPool ?: return null
                    elementCount++
                    if (elementCount > MAX_ELEMENTS) return null
                    val element = readStartElement(bytes, offset, headerSize, chunkSize, pool, resourceIds)
                        ?: return null
                    val parent = stack.lastOrNull()
                    if (parent == null) {
                        if (root == null) root = element else return null
                    } else {
                        if (stack.size >= MAX_DEPTH) return null
                        parent.children += element
                    }
                    stack += element
                }
                RES_XML_END_ELEMENT -> {
                    if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
                }
                RES_XML_CDATA, RES_XML_START_NAMESPACE, RES_XML_END_NAMESPACE -> Unit
            }
            offset += chunkSize
        }
        return root?.toImmutable()
    }

    private class MutableElement(
        val name: String,
        val attributes: List<Attr>,
    ) {
        val children = ArrayList<MutableElement>()

        fun toImmutable(): Element = Element(name, attributes, children.map { it.toImmutable() })
    }

    private fun readStartElement(
        bytes: ByteArray,
        chunkOffset: Int,
        headerSize: Int,
        chunkSize: Int,
        pool: List<String>,
        resourceIds: IntArray?,
    ): MutableElement? {
        // ResXMLTree_node: header(8) + lineNumber(4) + comment(4) = 16
        val extOffset = chunkOffset + 16
        if (extOffset + 20 > chunkOffset + chunkSize) return null
        val nameIndex = i32(bytes, extOffset + 4)
        val attributeStart = u16(bytes, extOffset + 8)
        val attributeSize = u16(bytes, extOffset + 10)
        val attributeCount = u16(bytes, extOffset + 12)
        if (attributeCount > 512) return null
        if (attributeSize < 20) return null
        val name = stringAt(pool, nameIndex) ?: return null
        val attributes = ArrayList<Attr>(attributeCount)
        var attrOffset = extOffset + attributeStart
        for (i in 0 until attributeCount) {
            if (attrOffset + 20 > chunkOffset + chunkSize) return null
            val nsIndex = i32(bytes, attrOffset)
            val attrNameIndex = i32(bytes, attrOffset + 4)
            val rawValueIndex = i32(bytes, attrOffset + 8)
            val valueSize = u16(bytes, attrOffset + 12)
            val dataType = bytes[attrOffset + 15].toInt() and 0xFF
            val data = i32(bytes, attrOffset + 16)

            var attrName = stringAt(pool, attrNameIndex)
            if (attrName.isNullOrEmpty() && resourceIds != null &&
                attrNameIndex in resourceIds.indices
            ) {
                attrName = androidAttrName(resourceIds[attrNameIndex])
            }
            val rawValue = stringAt(pool, rawValueIndex)
            val namespace = stringAt(pool, nsIndex)
            if (attrName != null) {
                val resolvedRaw = rawValue ?: when (dataType) {
                    TYPE_STRING -> stringAt(pool, data)
                    TYPE_INT_DEC, TYPE_INT_HEX -> data.toString()
                    TYPE_INT_BOOLEAN -> if (data != 0) "true" else "false"
                    TYPE_REFERENCE -> "@0x" + Integer.toHexString(data)
                    TYPE_FLOAT -> Float.fromBits(data).toString()
                    else -> null
                }
                attributes += Attr(
                    namespace = namespace?.ifEmpty { null },
                    name = attrName,
                    rawValue = resolvedRaw,
                    type = dataType,
                    data = data,
                )
            }
            val step = if (valueSize >= 20) valueSize else attributeSize
            attrOffset += step
        }
        return MutableElement(name, attributes)
    }

    private fun readStringPool(
        bytes: ByteArray,
        chunkOffset: Int,
        headerSize: Int,
        chunkSize: Int,
    ): List<String>? {
        if (headerSize < 28) return null
        val stringCount = u32(bytes, chunkOffset + 8).toInt()
        val flags = u32(bytes, chunkOffset + 16).toInt()
        val stringsStart = u32(bytes, chunkOffset + 20).toInt()
        if (stringCount < 0 || stringCount > 500_000) return null
        val offsetsStart = chunkOffset + headerSize
        if (offsetsStart + stringCount * 4 > chunkOffset + chunkSize) return null
        val utf8 = (flags and 0x100) != 0
        val base = chunkOffset + stringsStart
        val chunkEnd = chunkOffset + chunkSize
        val result = ArrayList<String>(stringCount)
        for (i in 0 until stringCount) {
            val relative = u32(bytes, offsetsStart + i * 4).toInt()
            if (relative < 0 || base + relative >= chunkEnd) {
                result += ""
                continue
            }
            result += if (utf8) {
                decodeUtf8(bytes, base + relative, chunkEnd)
            } else {
                decodeUtf16(bytes, base + relative, chunkEnd)
            }
        }
        return result
    }

    private fun decodeUtf8(bytes: ByteArray, start: Int, end: Int): String {
        var offset = start
        // UTF-16 길이(사용하지 않음)
        if (offset >= end) return ""
        val first = bytes[offset].toInt() and 0xFF
        offset += if (first and 0x80 != 0) 2 else 1
        if (offset >= end) return ""
        val b0 = bytes[offset].toInt() and 0xFF
        val byteLength: Int
        if (b0 and 0x80 != 0) {
            if (offset + 1 >= end) return ""
            byteLength = ((b0 and 0x7F) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
            offset += 2
        } else {
            byteLength = b0
            offset += 1
        }
        if (byteLength < 0 || offset + byteLength > end) return ""
        return String(bytes, offset, byteLength, Charsets.UTF_8)
    }

    private fun decodeUtf16(bytes: ByteArray, start: Int, end: Int): String {
        var offset = start
        if (offset + 2 > end) return ""
        var length = u16(bytes, offset)
        offset += 2
        if (length and 0x8000 != 0) {
            if (offset + 2 > end) return ""
            length = ((length and 0x7FFF) shl 16) or u16(bytes, offset)
            offset += 2
        }
        if (length < 0 || offset + length * 2 > end) return ""
        return String(bytes, offset, length * 2, Charsets.UTF_16LE)
    }

    private fun stringAt(pool: List<String>, index: Int): String? =
        if (index >= 0 && index < pool.size) pool[index] else null

    /** android.R.attr 리소스 id → 속성 이름(문자열 풀에 이름이 없을 때 사용). */
    private fun androidAttrName(resourceId: Int): String? = ANDROID_ATTRS[resourceId]

    private val ANDROID_ATTRS: Map<Int, String> = mapOf(
        0x01010000 to "theme",
        0x01010001 to "label",
        0x01010002 to "icon",
        0x01010003 to "name",
        0x01010006 to "permission",
        0x0101000e to "enabled",
        0x0101000f to "debuggable",
        0x01010010 to "exported",
        0x01010011 to "process",
        0x01010018 to "authorities",
        0x0101001d to "allowTaskReparenting",
        0x0101020c to "minSdkVersion",
        0x0101021b to "versionCode",
        0x0101021c to "versionName",
        0x01010270 to "targetSdkVersion",
        0x01010271 to "maxSdkVersion",
        0x01010280 to "allowBackup",
        0x010104ec to "usesCleartextTraffic",
        0x01010572 to "requestLegacyExternalStorage",
        0x01010527 to "extractNativeLibs",
        0x01010573 to "networkSecurityConfig",
    )

    private fun u16(bytes: ByteArray, offset: Int): Int {
        if (offset + 1 >= bytes.size) return 0
        return (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
    }

    private fun u32(bytes: ByteArray, offset: Int): Long {
        if (offset + 3 >= bytes.size) return 0
        return (bytes[offset].toLong() and 0xFF) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 8) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 3].toLong() and 0xFF) shl 24)
    }

    private fun i32(bytes: ByteArray, offset: Int): Int = u32(bytes, offset).toInt()
}
