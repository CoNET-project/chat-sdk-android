package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger

/**
 * E9.11.33 r2-amend6 G-LR-4 / G-LR-3 at the reader: the five states, a whitelist for any other stored value (READ_FAILED), a failed read is
 * READ_FAILED, and the reader writes nothing. Counting the reads at the file layer: only readReportIn reads the report.
 */
class LegacyReportReaderTest {
    private class Stored(private val value: String?, private val fail: Boolean = false) : VaultFiles {
        val reads = mutableListOf<String>()
        val writes = mutableListOf<String>()
        override fun read(name: String): ByteArray? {
            reads += name
            if (fail) throw IOException("report unreadable")
            return value?.toByteArray(Charsets.UTF_8)
        }
        override fun write(name: String, bytes: ByteArray) { writes += name }
        override fun delete(name: String) { writes += "delete:$name" }
    }

    @Test fun theFiveStatesAreMappedFromTheStoredValue() {
        assertEquals(LegacyReportState.ABSENT, LegacyStoreReport.readReportIn(Stored("absent")))
        assertEquals(LegacyReportState.FOUND, LegacyStoreReport.readReportIn(Stored("found")))
        assertEquals(LegacyReportState.UNREADABLE, LegacyStoreReport.readReportIn(Stored("unreadable")))
        assertEquals(LegacyReportState.NOT_REPORTED, LegacyStoreReport.readReportIn(Stored(null)))
    }

    @Test fun anyOtherStoredValueIsReadFailedNotAbsent() {
        for (v in listOf("", "ABSENT", "ok", "migrating", "Ready", "eoa", "0x" + "a".repeat(40))) {
            assertEquals("'$v'", LegacyReportState.READ_FAILED, LegacyStoreReport.readReportIn(Stored(v)))
        }
    }

    @Test fun aFailedReadIsReadFailedNotAbsent() {
        assertEquals(LegacyReportState.READ_FAILED, LegacyStoreReport.readReportIn(Stored("absent", fail = true)))
    }

    @Test fun theReaderWritesAndDeletesNothing() {
        val files = Stored("found")
        LegacyStoreReport.readReportIn(files)
        assertEquals(emptyList<String>(), files.writes)
        assertEquals(listOf(ClearFlagFiles.LEGACY_REPORT), files.reads)
    }

    /** The read counter at the file layer (E9.11.33 r2-amend6 §5.2, G-LR-1..5): only the reader reads the report name. */
    private class Counting(private val inner: VaultFiles) : VaultFiles {
        val reportReads = AtomicInteger(0)
        override fun read(name: String): ByteArray? {
            if (name == ClearFlagFiles.LEGACY_REPORT) reportReads.incrementAndGet()
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
    }

    @Test fun theReaderIsTheOnlyPathThatReadsTheReport() {
        val counted = Counting(Stored("absent"))
        // the flags, the account paths and the vault state without the reader: no read of the report name
        val flags = DeviceFlagFiles(counted)
        flags.accountPointer()
        flags.legacyUnreadable()
        flags.accountAddress()
        assertEquals("the flags alone do not read the report", 0, counted.reportReads.get())
        assertEquals(LegacyReportState.ABSENT, LegacyStoreReport.readReportIn(counted))
        assertEquals("one read per reader call", 1, counted.reportReads.get())
    }
}
