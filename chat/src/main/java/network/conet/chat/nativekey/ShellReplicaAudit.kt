package network.conet.chat.nativekey

/**
 * The one log line of a page-copy backfill (25.52Y.74 / ABSENT backfill review): it names the writer by the first six characters of the EOA
 * and the word created. No record content, no key material. Kept out of ShellRecord.kt, which must not contain a logging call (ShellRecordTest).
 */
internal object ShellReplicaAudit {
    fun created(eoa: String) {
        android.util.Log.i("ShellReplica", "page copy created eoa=${eoa.take(6)}")
    }
}
