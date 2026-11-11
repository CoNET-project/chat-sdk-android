package network.conet.chat.localread

/** Message kinds the layout estimator knows (spec 6.1). */
enum class LocalMediaKind { TEXT, IMAGE, VIDEO, FILE, SYSTEM, UNKNOWN }

/** Container geometry from the UI (spec 6.1). Points, not pixels. The SDK never infers orientation. */
data class LocalViewport(
    val widthPt: Double,
    val heightPt: Double,
    val orientation: String,
    val fontScale: Double,
    val layoutVersion: Int,
) {
    init {
        require(widthPt > 0 && heightPt > 0) { "viewport size must be positive" }
        require(orientation == "portrait" || orientation == "landscape") { "bad orientation" }
        require(fontScale > 0) { "bad fontScale" }
    }
}

/** Layout size record bucket keys and estimates (spec 8.1 to 8.3). */
object LocalChatLayout {
    const val MEDIA_MIN_H_PT = 120.0
    const val MEDIA_MAX_SHARE = 0.9
    /** Re-measured values closer than this to the stored one are not written (8.2). */
    const val WRITE_TOLERANCE_PT = 2.0

    /** widthBucket = round(widthPt / 8) × 8. */
    fun widthBucket(widthPt: Double): Int = (Math.round(widthPt / 8.0) * 8L).toInt()

    /** fontBucket = clamp(round(fontScale × 10), 8, 20). */
    fun fontBucket(fontScale: Double): Int = Math.round(fontScale * 10.0).toInt().coerceIn(8, 20)

    /**
     * Estimated size in points (spec 8.3). Returns (wPt, hPt). Used only to decide how many
     * rows a page takes; estimates are never written to the store.
     */
    fun estimate(
        kind: LocalMediaKind,
        widthPx: Int?,
        heightPx: Int?,
        mediaFailed: Boolean,
        vp: LocalViewport,
    ): Pair<Double, Double> {
        val wB = widthBucket(vp.widthPt).toDouble()
        val f = vp.fontScale
        if (mediaFailed) return Pair(wB, 88.0 * f)
        return when (kind) {
            LocalMediaKind.TEXT -> Pair(wB, 56.0 * f)
            LocalMediaKind.IMAGE, LocalMediaKind.VIDEO -> {
                val wPt = wB - 24.0
                val ratio = if (widthPx != null && heightPx != null && widthPx > 0 && heightPx > 0) {
                    heightPx.toDouble() / widthPx.toDouble()
                } else if (kind == LocalMediaKind.IMAGE) {
                    3.0 / 4.0
                } else {
                    9.0 / 16.0
                }
                val upper = maxOf(MEDIA_MIN_H_PT, MEDIA_MAX_SHARE * vp.heightPt)
                Pair(wPt, (wPt * ratio).coerceIn(MEDIA_MIN_H_PT, upper))
            }
            LocalMediaKind.FILE, LocalMediaKind.SYSTEM, LocalMediaKind.UNKNOWN -> Pair(wB, 72.0 * f)
        }
    }
}

/**
 * Per width bucket EMA (alpha 0.2) of measured ÷ estimated height. Applied only to
 * unmeasured messages. In memory only, never written to the store (spec 8.3).
 */
class LocalChatLayoutCorrector(private val alpha: Double = 0.2) {
    private val ratio = HashMap<Int, Double>()

    fun observe(widthBucket: Int, estimatedH: Double, measuredH: Double) {
        if (estimatedH <= 0.0 || measuredH <= 0.0) return
        val r = measuredH / estimatedH
        val prev = ratio[widthBucket]
        ratio[widthBucket] = if (prev == null) r else prev + alpha * (r - prev)
    }

    fun correct(widthBucket: Int, estimatedH: Double): Double = estimatedH * (ratio[widthBucket] ?: 1.0)
}
