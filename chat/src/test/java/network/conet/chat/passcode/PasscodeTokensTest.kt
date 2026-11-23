package network.conet.chat.passcode

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Checks [PasscodeTokens] against `spec/passcode-tokens.v1.json` (sha256 9f1644c9…, spec r3b 25.17.10).
 * The JSON file is the canonical copy from the PWA integration; the test does not rely on Android.
 */
class PasscodeTokensTest {
    private val bytes = File(System.getenv("PASSCODE_TOKENS") ?: "../spec/passcode-tokens.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))

    @Test
    fun tokenFileIsTheCanonicalOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("9f1644c9829fb233da552ab5ff4bfe6407e7438b4d6925d66eb11c25f370e7e0", sha)
    }

    @Test
    fun colorsMatchTheJson() {
        val c = v.getJSONObject("color")
        fun check(key: String, expected: Long) = assertEquals(key, PasscodeTokens.parseHexColor(c.getString(key)), expected)
        check("bg", PasscodeTokens.COLOR_BG)
        check("fg", PasscodeTokens.COLOR_FG)
        check("fgMuted", PasscodeTokens.COLOR_FG_MUTED)
        check("accent", PasscodeTokens.COLOR_ACCENT)
        check("onAccent", PasscodeTokens.COLOR_ON_ACCENT)
        check("danger", PasscodeTokens.COLOR_DANGER)
        check("warn", PasscodeTokens.COLOR_WARN)
        check("surface", PasscodeTokens.COLOR_SURFACE)
        check("border", PasscodeTokens.COLOR_BORDER)
    }

    @Test
    fun typeDotKeypadRadiusMotionAndTouchMatchTheJson() {
        val f = v.getJSONObject("font")
        assertEquals(f.getJSONObject("title").getInt("size"), PasscodeTokens.FONT_TITLE_SIZE)
        assertEquals(f.getJSONObject("title").getInt("weight"), PasscodeTokens.FONT_TITLE_WEIGHT)
        assertEquals(f.getJSONObject("body").getInt("size"), PasscodeTokens.FONT_BODY_SIZE)
        assertEquals(f.getJSONObject("body").getInt("weight"), PasscodeTokens.FONT_BODY_WEIGHT)
        assertEquals(f.getJSONObject("caption").getInt("size"), PasscodeTokens.FONT_CAPTION_SIZE)
        assertEquals(f.getJSONObject("caption").getInt("weight"), PasscodeTokens.FONT_CAPTION_WEIGHT)

        val dot = v.getJSONObject("dot")
        assertEquals(dot.getInt("size"), PasscodeTokens.DOT_SIZE)
        assertEquals(dot.getInt("gap"), PasscodeTokens.DOT_GAP)

        val key = v.getJSONObject("keypad").getJSONObject("key")
        assertEquals(key.getInt("width"), PasscodeTokens.KEY_WIDTH)
        assertEquals(key.getInt("height"), PasscodeTokens.KEY_HEIGHT)
        assertEquals(key.getInt("radius"), PasscodeTokens.KEY_RADIUS)

        assertEquals(v.getJSONObject("radius").getInt("card"), PasscodeTokens.RADIUS_CARD)
        val shake = v.getJSONObject("motion").getJSONObject("shake")
        assertEquals(shake.getInt("durationMs"), PasscodeTokens.SHAKE_DURATION_MS)
        assertEquals(shake.getInt("amplitude"), PasscodeTokens.SHAKE_AMPLITUDE)
        assertEquals(v.getJSONObject("touch").getInt("minTarget"), PasscodeTokens.TOUCH_MIN_TARGET)
    }

    @Test
    fun keypadGridShapeAndLabelsMatchTheJson() {
        val grid = v.getJSONObject("keypad").getJSONObject("grid")
        assertEquals(grid.getInt("cols"), PasscodeTokens.GRID_COLS)
        assertEquals(grid.getInt("rows"), PasscodeTokens.GRID_ROWS)
        val labels = grid.getJSONArray("labels")
        assertEquals(PasscodeTokens.GRID_COLS * PasscodeTokens.GRID_ROWS, PasscodeTokens.GRID_LABELS.size)
        assertEquals(labels.length(), PasscodeTokens.GRID_LABELS.size)
        for (i in 0 until labels.length()) {
            assertEquals("slot $i", labels.getString(i), PasscodeTokens.GRID_LABELS[i])
        }
    }

    @Test
    fun everyContrastCheckPassesTheMinimum() {
        val checks = v.getJSONObject("contrast").getJSONArray("checks")
        assertEquals(6, checks.length())
        for (i in 0 until checks.length()) {
            val c = checks.getJSONObject(i)
            val ratio = c.getDouble("ratio")
            val min = c.getDouble("min")
            assertTrue("${c.getString("name")}: ratio $ratio below min $min", ratio >= min)
            assertTrue("${c.getString("name")}: min $min below CONTRAST_MIN", min >= PasscodeTokens.CONTRAST_MIN)
        }
    }

    @Test
    fun parseHexColorHandlesRgbAndRgbaAndRejectsOtherForms() {
        assertEquals(0xFF071126L, PasscodeTokens.parseHexColor("#071126"))
        assertEquals(0x1AFFFFFFL, PasscodeTokens.parseHexColor("#FFFFFF1A"))
        assertEquals(0xBFFFFFFFL, PasscodeTokens.parseHexColor("#FFFFFFBF"))
        assertThrows(IllegalArgumentException::class.java) { PasscodeTokens.parseHexColor("071126") }
        assertThrows(IllegalArgumentException::class.java) { PasscodeTokens.parseHexColor("#07112") }
        assertThrows(IllegalArgumentException::class.java) { PasscodeTokens.parseHexColor("#GGGGGG") }
    }
}
