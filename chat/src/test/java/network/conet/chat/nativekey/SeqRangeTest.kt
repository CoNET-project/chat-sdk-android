package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Transaction sequence range (supplement, shellTxSeq): an integer in 0 .. 2^53 - 1, kept as Long. 1.0, 1e0, negatives, 2^53 and above, strings
 * and a missing value are bad_request. The check is [NativeSyncAck.seqOf], used by pwaWalletSync (formatError) and pwaEmptySignal.
 */
class SeqRangeTest {
    private fun seqOfJson(text: String): Long? = NativeSyncAck.seqOf(JSONObject(text))

    @Test
    fun theBoundsAreZeroAndTwoToTheFiftyThreeMinusOne() {
        assertEquals(9007199254740991L, NativeSyncAck.MAX_SEQ)
        assertEquals(0L, seqOfJson("""{"seq":0}"""))
        assertEquals(9007199254740991L, seqOfJson("""{"seq":9007199254740991}"""))
    }

    @Test
    fun aMillisecondTimestampSequenceIsAccepted() {
        // PWA shellTxSeq is persistent and monotonic, with the millisecond timestamp as its floor (about 1.8e12).
        assertEquals(1_800_000_000_000L, seqOfJson("""{"seq":1800000000000}"""))
    }

    @Test
    fun floatingForms() {
        assertNull("1.0 is a JSON double, not an integer", seqOfJson("""{"seq":1.0}"""))
        assertNull("1e0 is a JSON double, not an integer", seqOfJson("""{"seq":1e0}"""))
        assertNull("1.5", seqOfJson("""{"seq":1.5}"""))
    }

    @Test
    fun negativesAndTooLarge() {
        assertNull("-1", seqOfJson("""{"seq":-1}"""))
        assertNull("2^53 is out of range", seqOfJson("""{"seq":9007199254740992}"""))
        assertNull("Long.MAX_VALUE is out of range", seqOfJson("""{"seq":9223372036854775807}"""))
        assertNull("beyond Long", seqOfJson("""{"seq":99999999999999999999999}"""))
    }

    @Test
    fun stringsAndMissingValuesAreNotIntegers() {
        assertNull(seqOfJson("""{"seq":"5"}"""))
        assertNull(seqOfJson("""{"seq":null}"""))
        assertNull(seqOfJson("""{}"""))
    }

    /** The format check of pwaWalletSync uses the same range: an out-of-range sequence is bad_request before any read or write. */
    @Test
    fun theSyncFormatCheckRefusesOutOfRangeSequences() {
        assertEquals("bad_request", NativeSyncAck.formatError(JSONObject("""{"seq":9007199254740992}""").put("phrase", "x"), "x"))
        assertEquals("bad_request", NativeSyncAck.formatError(JSONObject("""{"seq":1.0}"""), "x"))
    }
}
