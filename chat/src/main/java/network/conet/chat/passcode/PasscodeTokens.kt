package network.conet.chat.passcode

/**
 * Passcode overlay design tokens (spec r3b 25.17.10). Values come from `spec/passcode-tokens.v1.json`
 * (sha256 9f1644c9…); `PasscodeTokensTest` checks every constant against that file.
 *
 * Colors are ARGB as Long. The JSON uses #RRGGBB or #RRGGBBAA; [parseHexColor] converts it.
 * Lengths are in dp (equal to iOS pt at @1x). No UI code lives here: the overlay itself, FLAG_SECURE
 * and the device behaviour are verified on a device, not in JVM tests.
 */
object PasscodeTokens {
    // color
    const val COLOR_BG: Long = 0xFF071126L
    const val COLOR_FG: Long = 0xFFFFFFFFL
    const val COLOR_FG_MUTED: Long = 0xBFFFFFFFL
    const val COLOR_ACCENT: Long = 0xFFFFFFFFL
    const val COLOR_ON_ACCENT: Long = 0xFF071126L
    const val COLOR_DANGER: Long = 0xFFEF4444L
    const val COLOR_WARN: Long = 0xFFFDE68AL
    const val COLOR_SURFACE: Long = 0x1AFFFFFFL
    const val COLOR_BORDER: Long = 0x26FFFFFFL

    // font (size in dp, weight as CSS numeric weight)
    const val FONT_TITLE_SIZE = 20
    const val FONT_TITLE_WEIGHT = 600
    const val FONT_BODY_SIZE = 14
    const val FONT_BODY_WEIGHT = 400
    const val FONT_CAPTION_SIZE = 12
    const val FONT_CAPTION_WEIGHT = 400

    // dots
    const val DOT_SIZE = 14
    const val DOT_GAP = 12

    // keypad
    const val KEY_WIDTH = 72
    const val KEY_HEIGHT = 72
    const val KEY_RADIUS = 36
    const val GRID_COLS = 3
    const val GRID_ROWS = 4
    /** Row-major, 12 slots. The empty string is the blank slot; "delete" is the backspace key. */
    val GRID_LABELS: List<String> = listOf(
        "1", "2", "3",
        "4", "5", "6",
        "7", "8", "9",
        "", "0", "delete",
    )

    // radius, motion, touch
    const val RADIUS_CARD = 24
    const val SHAKE_DURATION_MS = 320
    const val SHAKE_AMPLITUDE = 8
    const val TOUCH_MIN_TARGET = 44

    /** WCAG contrast minimum. Every check in the JSON file must be at least this value. */
    const val CONTRAST_MIN = 4.5

    /**
     * Parses `#RRGGBB` (alpha FF) or `#RRGGBBAA` into ARGB. Any other form throws.
     */
    fun parseHexColor(hex: String): Long {
        require(hex.length == 7 || hex.length == 9) { "bad color length: $hex" }
        require(hex[0] == '#') { "color must start with #: $hex" }
        val body = hex.substring(1)
        require(body.all { it in '0'..'9' || it in 'A'..'F' || it in 'a'..'f' }) { "bad color digits: $hex" }
        val rgb = body.substring(0, 6).toLong(16)
        return if (body.length == 6) {
            0xFF000000L or rgb
        } else {
            val aa = body.substring(6, 8).toLong(16)
            (aa shl 24) or rgb
        }
    }
}
