package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * 25.27.9 (r3ed, PM R727): the SDK-internal sign labels of the migration flow (PRECHECK, CHALLENGE) are byte-identical to
 * `spec/domain-tags-vectors.v1.json` (sha256 86d6ece8…d12). The tags are pairwise distinct (DT-T1), no tag is a byte prefix of another
 * (DT-T2), and the internal sign tags are not producible from a purposeId (DT-T3, the middle part holds a dot). The vector file is a byte
 * copy and is not edited. DT-T3 rests on the purposeId syntax of §25.27.3, which this test does not check.
 */
class PgpMigrationDomainTagsTest {
    private val bytes = File("../spec/domain-tags-vectors.v1.json").readBytes()
    private val labels = JSONObject(String(bytes, Charsets.UTF_8)).getJSONArray("labels")

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    private fun entry(id: String): JSONObject =
        (0 until labels.length()).map { labels.getJSONObject(it) }.single { it.getString("id") == id }

    @Test
    fun vectorFileIsTheRegisteredCopy() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("86d6ece8f3ff960b636fc1a8f0d757e3643f207ce0a3737d412d49caaaf67d12", sha)
    }

    @Test
    fun theVectorLabelHexesAreTheirLabels() {
        for (i in 0 until labels.length()) {
            val e = labels.getJSONObject(i)
            assertEquals(e.getString("id"), e.getString("labelHex"), hex(utf8(e.getString("label"))))
        }
    }

    @Test
    fun precheckAndChallengeLabelsAreByteIdenticalToTheVector() {
        assertEquals(entry("DT-04").getString("label"), PgpMigrationPolicy.PRECHECK_LABEL)
        assertEquals(entry("DT-04").getString("labelHex"), hex(utf8(PgpMigrationPolicy.PRECHECK_LABEL)))
        assertEquals(entry("DT-05").getString("label"), PgpMigrationPolicy.CHALLENGE_LABEL)
        assertEquals(entry("DT-05").getString("labelHex"), hex(utf8(PgpMigrationPolicy.CHALLENGE_LABEL)))
    }

    /** DT-T1 and DT-T2 over every label of the vector: the candidates, the sign labels and the AAD prefixes. */
    @Test
    fun dtT1AndDtT2TheLabelsArePairwiseDistinctAndNoneIsAPrefixOfAnother() {
        val all = (0 until labels.length()).map { labels.getJSONObject(it).getString("label") }
        for (i in all.indices) for (j in all.indices) if (i != j) {
            val a = utf8(all[i])
            val b = utf8(all[j])
            assertTrue("${all[i]} differs from ${all[j]}", !a.contentEquals(b))
            assertTrue("${all[i]} is not a byte prefix of ${all[j]}", !(b.size >= a.size && b.copyOf(a.size).contentEquals(a)))
        }
    }

    /** DT-T3: the middle part of an internal sign label holds a dot, so it is not a purposeId. The candidates are the registered purposes. */
    @Test
    fun dtT3TheInternalSignLabelsAreNotProducibleFromAPurposeId() {
        for (id in listOf("DT-04", "DT-05")) {
            val middle = entry(id).getString("label").removePrefix("beamio.pgp.").removeSuffix(".v1\n")
            assertTrue("$id middle part has a dot: $middle", middle.contains("."))
        }
        assertEquals(entry("DT-01").getString("label"), NativePgpVault.domainLabel("chatEnvelope"))
        assertEquals(entry("DT-02").getString("label"), NativePgpVault.domainLabel("groupMessage"))
        assertEquals(entry("DT-03").getString("label"), NativePgpVault.domainLabel("voiceSignal"))
    }
}
