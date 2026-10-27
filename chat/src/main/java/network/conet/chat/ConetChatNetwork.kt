package network.conet.chat

/**
 * Guardian / SI entry helpers shared by Conet Chat listen and host cipher POST.
 */
object ConetChatNetwork {
    fun normalizeIp(raw: String?): String? {
        var trimmed = raw?.trim().orEmpty()
        if (trimmed.isEmpty() || trimmed.contains("/") || trimmed.contains(" ")) return null
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length - 1)
        }
        if (trimmed.contains(":")) {
            if (trimmed.count { it == ':' } < 2 || trimmed.contains(".")) return null
            return trimmed
        }
        val parts = trimmed.split(".")
        if (parts.size != 4) return null
        for (part in parts) {
            if (part.isEmpty() || part.length > 3) return null
            if (part.length > 1 && part.startsWith("0")) return null
            val n = part.toIntOrNull() ?: return null
            if (n !in 0..255) return null
        }
        return trimmed
    }

    fun postUrl(ip: String): String? {
        val norm = normalizeIp(ip) ?: return null
        return if (norm.contains(":")) "http://[$norm]/post" else "http://$norm/post"
    }
}
