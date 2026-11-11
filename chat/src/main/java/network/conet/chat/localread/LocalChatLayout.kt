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

    /** Oracle clamp: min(hi, max(lo, x)). Never throws for small viewports. */
    private fun clampOracle(x: Double, lo: Double, hi: Double): Double = Math.min(hi, Math.max(lo, x))

    /** Oracle r1: round to 0.1 pt (JS Math.round semantics for positive values). */
    fun r1(x: Double): Double = Math.round(x * 10.0) / 10.0

    private const val EM_LATIN = 0.52
    private const val EM_DIGIT = 0.55
    private const val EM_SPACE = 0.28
    private const val EM_PUNCT = 0.38
    private const val EM_CJK = 1.0
    private const val LINE_EM = 1.4
    private const val PAD_V_EM = 16.0
    private const val CAPTION_EM = 24.0

    private fun emFor(cp: Int): Double = when {
        cp == 0x20 -> EM_SPACE
        cp in 0x30..0x39 -> EM_DIGIT
        cp in 0x41..0x5a || cp in 0x61..0x7a -> EM_LATIN
        cp < 0x80 -> EM_PUNCT
        else -> EM_CJK
    }

    /**
     * Estimated text lines (spec v1.1 8.3, oracle `textLinesEstimate`): per-character em widths,
     * a forced break at each newline, a break before a character that would overflow the width.
     */
    fun textLinesEstimate(body: String, wPt: Double, fs: Double): Int {
        val fontPt = 16.0 * fs
        val w = Math.max(1.0, wPt - 24.0)
        var lines = 0
        for (logical in body.split('\n')) {
            lines++
            var cur = 0.0
            var i = 0
            while (i < logical.length) {
                val cp = logical.codePointAt(i)
                i += Character.charCount(cp)
                val a = emFor(cp) * fontPt
                if (cur + a > w && cur > 0.0) {
                    lines++
                    cur = a
                } else {
                    cur += a
                }
            }
        }
        return lines
    }

    /**
     * Estimated size in points (spec v1.1 8.3, oracle `estimateHeight`). Returns (wPt, hPt).
     * Estimates decide only how many rows a page takes; they are never stored.
     */
    fun estimate(
        kind: LocalMediaKind,
        widthPx: Int?,
        heightPx: Int?,
        mediaFailed: Boolean,
        body: String?,
        vp: LocalViewport,
    ): Pair<Double, Double> {
        val fs = vp.fontScale
        val wB = widthBucket(vp.widthPt).toDouble()
        if (kind == LocalMediaKind.TEXT && !mediaFailed) {
            val lines = textLinesEstimate(body.orEmpty(), vp.widthPt, fs)
            return Pair(wB, r1(PAD_V_EM * fs + lines * LINE_EM * 16.0 * fs))
        }
        if (mediaFailed) return Pair(wB, r1(88.0 * fs))
        return when (kind) {
            LocalMediaKind.IMAGE, LocalMediaKind.VIDEO -> {
                val wPt = Math.min(vp.widthPt - 24.0, MEDIA_MAX_W_PT)
                val upper = MEDIA_MAX_SHARE * vp.heightPt
                val lo = Math.min(MEDIA_MIN_H_PT, upper)
                val hasDims = widthPx != null && heightPx != null && widthPx > 0 && heightPx > 0
                val h = if (hasDims) {
                    clampOracle(wPt * heightPx!!.toDouble() / widthPx!!.toDouble(), lo, upper)
                } else if (kind == LocalMediaKind.VIDEO) {
                    clampOracle(wPt * 9.0 / 16.0, lo, upper)
                } else {
                    clampOracle(wPt * 3.0 / 4.0, lo, upper)
                }
                Pair(wPt, r1(h + CAPTION_EM * fs))
            }
            LocalMediaKind.TEXT -> Pair(wB, r1(PAD_V_EM * fs))
            LocalMediaKind.FILE, LocalMediaKind.SYSTEM, LocalMediaKind.UNKNOWN -> Pair(wB, r1(72.0 * fs))
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
