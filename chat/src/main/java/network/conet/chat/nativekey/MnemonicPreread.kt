package network.conet.chat.nativekey

import java.util.concurrent.Executors

/**
 * Start-up pre-read of the saved recovery phrase (r2.4.3 to follow).
 *
 * The shell starts [start] once, asynchronously. The page gets one of three answers ([Answer]): a valid phrase, confirmed absent, or unknown.
 * Unknown covers a failed read and a pre-read that has not finished (never an empty answer).
 *
 * Sequence: every accepted sync carries a transaction sequence number ([accept]). The newest accepted sequence is the epoch. A pre-read
 * started under an older epoch is never published, and a cached answer is served only while its epoch is current, so a late old pre-read
 * cannot overwrite a newer write. A successful sync publishes a fresh independent read under its own sequence ([publishAfterSync]).
 * The phrase is held in memory only for the bridge answer and is never logged.
 */
internal object MnemonicPreread {
    sealed class Answer {
        class Valid(val eoa: String, val phrase: String) : Answer()
        object Absent : Answer()
        object Unknown : Answer()
    }

    /** The shell's legacy report state that alone allows an absent answer (E9.11.33 r2-amend6, §5.5). */
    internal val LEGACY_ABSENT: LegacyReportState = LegacyReportState.ABSENT

    private val lock = Any()
    private val worker = Executors.newSingleThreadExecutor()

    /** The newest accepted sync sequence. 0 until the first accepted sync. */
    private var acceptedSeq: Long = 0L
    private var cached: Pair<Long, Answer>? = null

    /** The vault's answer for the saved phrase, read once. Unknown on any failure or when not finished. */
    fun readAnswer(read: () -> Answer): Answer = try {
        read()
    } catch (_: Exception) {
        Answer.Unknown
    }

    /** True while a background pre-read is running (set by [startIfIdle], cleared when its result is published). */
    private var inFlight = false

    /** Diagnostic hook (the module sets it to its logger): receives a line per start and per result, never a phrase. */
    @Volatile var log: (String) -> Unit = {}

    /** Starts the pre-read in the background. A pre-read already running is superseded by this one (its result is then discarded). */
    fun start(read: () -> Answer) {
        val epoch = synchronized(lock) {
            cached = null
            inFlight = true
            acceptedSeq
        }
        launch(epoch, read, "start")
    }

    /**
     * Starts the pre-read only when none is running and no answer is cached (E9.11.x, pre-read not started: a first-foreground or start-from-store
     * entry used to skip the start-up pre-read, so the page got unknown for ever). Returns true when a read was started. A read fault is unknown and
     * is not cached: the next call starts again.
     */
    fun startIfIdle(source: String, read: () -> Answer): Boolean {
        val epoch = synchronized(lock) {
            if (inFlight || cached != null) return false
            inFlight = true
            acceptedSeq
        }
        launch(epoch, read, source)
        return true
    }

    private fun launch(epoch: Long, read: () -> Answer, source: String) {
        log("preread start source=$source")
        worker.execute {
            val answer = readAnswer(read)
            synchronized(lock) {
                // An unknown answer is not cached: the next page request starts a fresh read (retryable).
                if (acceptedSeq == epoch && answer !is Answer.Unknown) cached = epoch to answer
                inFlight = false
            }
            log("preread result source=$source ${answer.javaClass.simpleName.lowercase()}")
        }
    }

    /** Test hook: whether a read is running now. */
    internal fun isInFlight(): Boolean = synchronized(lock) { inFlight }

    /**
     * Accepts a sync request with [seq] when it is newer than the last accepted one. Accepting voids every cached pre-read.
     * A request that is not newer is refused (stale): nothing is written.
     */
    fun accept(seq: Long): Boolean = acceptTransaction(seq, sync = true)

    /**
     * The shared transaction ledger (r2.5.x): `pwaWalletSync` and `pwaEmptySignal` share one sequence. The newest sequence of either command
     * is the bar; an older or equal one is stale for both. A sync also moves the pre-read epoch ([accept]); a signal does not.
     */
    private var latestSeq: Long = 0L

    /**
     * Accepts a transaction of either command with [seq] when it is not older than the newest one (r2.5.6 56(1), SQ-07): an equal sequence is
     * current, so a PWA retry of the same transaction is accepted. A strictly older one is stale. [sync] moves the pre-read epoch.
     */
    fun acceptTransaction(seq: Long, sync: Boolean): Boolean = synchronized(lock) {
        if (seq < latestSeq) return false
        latestSeq = seq
        if (sync) {
            acceptedSeq = seq
            cached = null
        }
        true
    }

    /** The newest sequence of either command (read only). */
    fun latestAcceptedSeq(): Long = synchronized(lock) { latestSeq }

    /** Publishes [answer] for the sync [seq], only when [seq] is still the newest accepted sequence. */
    fun publishAfterSync(seq: Long, answer: Answer) = synchronized(lock) {
        // An unknown read is not cached (retryable): the next page request starts a fresh read.
        if (acceptedSeq == seq && answer !is Answer.Unknown) cached = seq to answer
    }

    /** The answer for the page: the cached answer while its epoch is current; otherwise unknown. */
    fun answer(): Answer = synchronized(lock) {
        val c = cached
        if (c != null && c.first == acceptedSeq) c.second else Answer.Unknown
    }

    /** The answer the vault gives now: the saved phrase, confirmed absent, or unknown (locked, unreadable). Reads the vault only. */
    fun vaultAnswer(vault: NativeWalletVault, legacyReport: () -> LegacyReportState): Answer = prereadAnswer(vault, legacyReport)

    /**
     * The pre-read (a half-written window is ignorable): every phrase item the vault can name is read, the fixed mnemonic file
     * and each isolated copy of it. A phrase that verifies (BIP-39, derived EOA equal to its own envelope EOA) is the answer `valid`. A read that
     * fails, or two different valid accounts, is `unknown`. With no valid phrase the answer is `absent` when the key record reads (or there is none)
     * and the state is settled or a pending marker (rollback_pending, the marker is not a lock for this answer); any other lock is `unknown`.
     * The pre-read writes nothing and removes nothing.
     */
    private fun prereadAnswer(vault: NativeWalletVault, legacyReport: () -> LegacyReportState): Answer {
        val answer = prereadAnswerRaw(vault, legacyReport)
        // Additive field overwrite (iii, i): an unsettled OVERWRITE (the marker has overwrite=true and lists an isolated copy of
        // REC or MNEM) is not answered valid: a failed overwrite is not a success, the answer stays unknown until a write settles it. A first-write
        // half window (no overwrite marker) keeps E9.1-1 (a valid phrase answers valid); a residual MARK of an import and a settled keep residue
        // (E9.1-4) are not overwrites and keep their answers.
        // E1: an unreadable or unparseable marker is not answered valid either (a read failure is unknown).
        // A read fault of the pending marker is unknown whatever the other positions say (global rule: a read failure is unknown). A marker that
        // reads but cannot be parsed keeps its answer, except that a valid answer becomes unknown.
        if (vault.pendingMarkerReadFault()) return Answer.Unknown
        return if (answer is Answer.Valid && (vault.overwriteIntentUnsettled() || vault.pendingMarkerUnreadable())) Answer.Unknown else answer
    }

    private fun prereadAnswerRaw(vault: NativeWalletVault, legacyReport: () -> LegacyReportState): Answer {
        // E9.1: only the mnemonic positions decide. REC and MARK are not read here (REC holds no phrase on Android), and a
        // marker that does not match its record is not a read failure. Entries the pending marker names as an unfinished write are read best-effort.
        val marked = vault.prereadMarkerNames()
        val current = readCurrentPhrase(vault, marked)
        if (current is Answer.Valid) return current        // E9.1 (source priority): the current record wins over every sealed copy
        if (current === Answer.Unknown) return Answer.Unknown  // a read failure of the current record is unknown; the copies are not used
        val valid = LinkedHashMap<String, Answer.Valid>()
        for (name in vault.storedNames().filter { it.startsWith(NativeWalletVault.MNEM + ".isolated.") }.sorted()) {
            // A read failure is transient (unknown) and is never ignored, listed or not (transient vs deterministic):
            // only a deterministic failure of a listed entry (Unreadable below) is ignored.
            val bytes = vault.storedBytes(name) ?: continue
            val first = vault.phraseItemOf(bytes)
            val item = if (name in marked) listedItem(vault, name, bytes, first) ?: return Answer.Unknown else first
            when (item) {
                is NativeWalletVault.PhraseItem.Valid -> valid[item.eoa] = Answer.Valid(item.eoa, item.phrase)
                NativeWalletVault.PhraseItem.Invalid -> Unit
                // An unlisted unreadable copy is unknown. A listed one is ignored (E9.1-1) EXCEPT under an unsettled overwrite (the marker carries the
                // additive field overwrite=true): then a listed copy that does not read is unknown, with or without another
                // valid copy. Markers without the field (2026-11-17 format) keep the E9.1-1 behaviour.
                NativeWalletVault.PhraseItem.Unreadable -> if (name !in marked || vault.overwriteMarkerNew()) return Answer.Unknown
            }
        }
        // Two different valid accounts among the copies: the timestamp rule (E9.2 / E9.2.1) is not implemented yet, so unknown.
        if (valid.size >= 2) return Answer.Unknown
        if (valid.size == 1) return valid.values.single()
        // Hotfix (S25 pre-read; K.2, K.3, K.5, PY.15, E9.11.29 r2): an empty native phrase is absent only when the shell reported the legacy store
        // absent. found, unreadable, a missing report, or a failed read of the report is unknown: never absent.
        val report = try {
            legacyReport()
        } catch (_: Exception) {
            null
        }
        return if (report == LEGACY_ABSENT) Answer.Absent else Answer.Unknown
    }

    /**
     * The current record's phrase item (the fixed mnemonic file). Absent: Absent-state (the caller goes on to the copies). A failed read or an
     * undecryptable item that is not an unfinished-write entry is Unknown. An invalid phrase is absent only when a second read is invalid too (N5).
     */
    private fun readCurrentPhrase(vault: NativeWalletVault, marked: Set<String>): Answer? {
        val name = NativeWalletVault.MNEM
        // A read failure propagates (transient: unknown), listed or not. The pre-read of the fixed position is never a silent absence.
        val bytes = vault.storedBytes(name) ?: return null
        val first = vault.phraseItemOf(bytes)
        val item = if (name in marked) listedItem(vault, name, bytes, first) ?: return Answer.Unknown else first
        return when (item) {
            is NativeWalletVault.PhraseItem.Valid -> Answer.Valid(item.eoa, item.phrase)
            NativeWalletVault.PhraseItem.Invalid -> {
                val again = vault.storedBytes(name)?.let { vault.phraseItemOf(it) }
                if (again == NativeWalletVault.PhraseItem.Invalid) null else Answer.Unknown
            }
            NativeWalletVault.PhraseItem.Unreadable -> if (name in marked) null else Answer.Unknown
        }
    }

    /**
     * E9.1.2-1 (a) (erratum 2026-11-17) with the second read. A listed entry that is unreadable on the first read is confirmed deterministic only
     * when the second read gives the same bytes and the same unreadable result (the two reads agree). Any other outcome (a readable second read,
     * a different failure, a missing second read) is not confirmed: unknown (null). The of 2026-11-17 adopts unknown for a first failure
     * followed by a valid read, so the second read's value is not used.
     */
    private fun listedItem(vault: NativeWalletVault, name: String, first: ByteArray, firstItem: NativeWalletVault.PhraseItem): NativeWalletVault.PhraseItem? {
        if (firstItem != NativeWalletVault.PhraseItem.Unreadable) return firstItem
        val second = vault.storedBytes(name) ?: return null
        val secondItem = vault.phraseItemOf(second)
        return if (second.contentEquals(first) && secondItem == NativeWalletVault.PhraseItem.Unreadable) {
            NativeWalletVault.PhraseItem.Unreadable
        } else {
            null
        }
    }

    /** The answer by the phrase verdict of the state (the previous rule, kept for the reference tests). */
    internal fun vaultAnswerByVerdict(vault: NativeWalletVault): Answer = when (val st = vault.state()) {
        is NativeWalletVault.State.NoKey -> Answer.Absent
        is NativeWalletVault.State.Ready -> when (vault.phraseVerdict()) {
            NativeWalletVault.PhraseVerdict.VALID -> when (val r = vault.mnemonicOf()) {
                is NativeWalletVault.MnemonicRead.Stored -> Answer.Valid(r.eoa, r.phrase)
                else -> Answer.Unknown
            }
            NativeWalletVault.PhraseVerdict.MISSING -> Answer.Absent
            NativeWalletVault.PhraseVerdict.UNKNOWN -> Answer.Unknown
            // E7-7 (N5): an invalid phrase item is absent only when a second read gives the same invalid result; otherwise unknown.
            NativeWalletVault.PhraseVerdict.INVALID ->
                if (vault.phraseVerdict() == NativeWalletVault.PhraseVerdict.INVALID) Answer.Absent else Answer.Unknown
        }
        // B1 (review): a readable phrase with no key record is a valid account; any other lock is unknown.
        is NativeWalletVault.State.Locked -> {
            if (st.reason == NativeWalletVault.PHRASE_ONLY) {
                vault.phraseOnly()?.let { Answer.Valid(it.first, it.second) } ?: Answer.Unknown
            } else {
                Answer.Unknown
            }
        }
    }

    /** [vaultAnswer], or unknown when the read itself throws (B3: the publish always happens; an unreadable state is still unknown). */
    fun vaultAnswerOrUnknown(vault: NativeWalletVault, legacyReport: () -> LegacyReportState): Answer = try {
        vaultAnswer(vault, legacyReport)
    } catch (_: Exception) {
        Answer.Unknown
    }

    /**
     * The native rules alone, with the legacy store assumed absent (the native-store cases of the vectors and the unit tests). Production passes the
     * shell's report with the two-argument form, so this overload never decides a device's answer.
     */
    fun vaultAnswerOrUnknown(vault: NativeWalletVault): Answer = vaultAnswerOrUnknown(vault) { LEGACY_ABSENT }

    /** Test hook: forget all state. */
    internal fun resetForTests() = synchronized(lock) {
        acceptedSeq = 0L
        latestSeq = 0L
        cached = null
        inFlight = false
    }
}
