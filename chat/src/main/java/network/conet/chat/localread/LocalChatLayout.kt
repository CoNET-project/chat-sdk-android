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

/** Layout size record bucket keys and estimates (spec v0.2 section 8). Matches chat-layout-oracle.mjs. */
object LocalChatLayout {
    const val MEDIA_MIN_H_PT = 120.0
    const val MEDIA_MAX_SHARE = 0.9
    /** Image and video bubbles are at most this wide (oracle: min(widthPt - 24, 280)). */
    const val MEDIA_MAX_W_PT = 280.0
    /** Re-measured values closer than this to the stored one are not written (8.2). */
    const val WRITE_TOLERANCE_PT = 2.0

    /** widthBucket = round(widthPt / 8) × 8. */
    fun widthBucket(widthPt: Double): Int = (Math.round(widthPt / 8.0) * 8L).toInt()

    /** fontBucket = clamp(round(fontScale × 10), 8, 20). */
    fun fontBucket(fontScale: Double): Int = Math.round(fontScale * 10.0).toInt().coerceIn(8, 20)

    /** Same clamp as the oracle: min(hi, max(lo, x)). Never throws for small viewports. */
    private fun clampOracle(x: Double, lo: Double, hi: Double): Double = Math.min(hi, Math.max(lo, x))

    /**
     * Estimated size in points (spec 8.3, oracle `estimateHeight`). Returns (wPt, hPt).
     * Estimates decide only how many rows a page takes; they are never stored.
     */
    fun estimate(
        kind: LocalMediaKind,
        widthPx: Int?,
        heightPx: Int?,
        mediaFailed: Boolean,
        vp: LocalViewport,
    ): Pair<Double, Double> {
        val f = vp.fontScale
        if (mediaFailed) return Pair(widthBucket(vp.widthPt).toDouble(), 88.0 * f)
        return when (kind) {
            LocalMediaKind.TEXT -> Pair(widthBucket(vp.widthPt).toDouble(), 56.0 * f)
            LocalMediaKind.IMAGE, LocalMediaKind.VIDEO -> {
                val wPt = Math.min(vp.widthPt - 24.0, MEDIA_MAX_W_PT)
                val upper = MEDIA_MAX_SHARE * vp.heightPt
                val hasDims = widthPx != null && heightPx != null && widthPx > 0 && heightPx > 0
                val h = if (hasDims) {
                    clampOracle(wPt * heightPx!!.toDouble() / widthPx!!.toDouble(), MEDIA_MIN_H_PT, upper)
                } else {
                    // No dimensions: 4:3 for both image and video (oracle).
                    clampOracle(wPt * 3.0 / 4.0, MEDIA_MIN_H_PT, upper)
                }
                Pair(wPt, h)
            }
            LocalMediaKind.FILE, LocalMediaKind.SYSTEM, LocalMediaKind.UNKNOWN ->
                Pair(widthBucket(vp.widthPt).toDouble(), 72.0 * f)
        }
    }
}

/**
 * Per width bucket EMA (alpha 0.2) of measured ÷ estimated height (spec 8.3, last paragraph).
 * NOT applied by the store: chat-layout-oracle.mjs, the normative reference, does not apply it,
 * and the scenario vectors depend on that. Kept for the decision in receipt section 8 (D-A8).
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
