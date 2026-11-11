package network.conet.chat.localread

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** Result of the body parser (spec r2 section 21.2). */
data class ParsedBody(
    val kind: LocalMediaKind,
    /** Media that cannot be shown: the placeholder height applies (88 x fs). */
    val failed: Boolean,
    val text: String? = null,
    val mime: String? = null,
    val size: Long? = null,
    val name: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val blob: String? = null,
    /** Error code only (`parse_error`, `manifest_invalid`, `media_parser_missing`). Never content. */
    val error: String? = null,
)

/**
 * Body parser (spec r2 section 21.2). The stored bytes are the basis; nothing is re-serialized.
 * Text is plain UTF-8, not JSON. A body that starts with `{` and carries `v` or `kind` is a
 * manifest candidate: `v = 1` and a legal `kind` make a media item, anything else is `unknown` and failed.
 */
object MediaManifestParser {
    private val MEDIA_KINDS = mapOf(
        "image" to LocalMediaKind.IMAGE,
        "video" to LocalMediaKind.VIDEO,
        "file" to LocalMediaKind.FILE,
    )

    fun parse(bytes: ByteArray): ParsedBody {
        val text = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (e: CharacterCodingException) {
            return ParsedBody(LocalMediaKind.UNKNOWN, failed = true, error = "parse_error")
        }
        if (!text.startsWith("{")) return ParsedBody(LocalMediaKind.TEXT, failed = false, text = text)
        val obj = try {
            JSONObject(text)
        } catch (e: Exception) {
            return ParsedBody(LocalMediaKind.TEXT, failed = false, text = text)
        }
        if (!obj.has("v") && !obj.has("kind")) return ParsedBody(LocalMediaKind.TEXT, failed = false, text = text)
        return manifest(obj) ?: ParsedBody(LocalMediaKind.UNKNOWN, failed = true, error = "manifest_invalid")
    }

    /** Null when the object is not a valid v1 manifest. */
    private fun manifest(obj: JSONObject): ParsedBody? {
        if (!obj.has("v") || obj.opt("v") !is Int || obj.optInt("v") != 1) return null
        val kind = MEDIA_KINDS[obj.optString("kind", "")] ?: return null
        if (obj.opt("text") !is String) return null
        val m = obj.optJSONObject("media") ?: return null
        val mime = m.opt("mime") as? String ?: return null
        val size = m.opt("size") as? Number ?: return null
        if (size.toLong().toDouble() != size.toDouble()) return null
        val blob = m.opt("blob") as? String ?: return null
        val name = if (m.has("name")) (m.opt("name") as? String ?: return null) else null
        val width = optIntOrNull(m, "width") ?: if (m.has("width")) return null else null
        val height = optIntOrNull(m, "height") ?: if (m.has("height")) return null else null
        return ParsedBody(
            kind = kind,
            failed = false,
            text = obj.getString("text"),
            mime = mime,
            size = size.toLong(),
            name = name,
            width = width,
            height = height,
            blob = blob,
        )
    }

    private fun optIntOrNull(m: JSONObject, key: String): Int? {
        if (!m.has(key)) return null
        val v = m.opt(key) as? Int ?: return null
        return if (v > 0) v else null
    }
}
