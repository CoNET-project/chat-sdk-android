package network.conet.chat.nativekey

/**
 * Log-only timing of the vault's slow parts: how many Keystore operations and how many milliseconds, how many
 * derivations and how many milliseconds, how long a caller waited for the vault's monitor, and the security level of the wrapping key. Numbers and
 * enumerated words only: no name, address, phrase, key or error text is ever recorded. Nothing here changes behaviour.
 */
internal object VaultPerf {
    /** The counters of one thread since it started counting. Copied, never shared between threads. */
    class Acc(var ksOps: Int = 0, var ksNs: Long = 0L, var deriveOps: Int = 0, var deriveNs: Long = 0L) {
        fun copy() = Acc(ksOps, ksNs, deriveOps, deriveNs)
    }

    private val local = ThreadLocal.withInitial { Acc() }

    /** Where the lines go: (label, start in nanoseconds, code). Production writes ConetDiag; a test captures them. */
    @Volatile
    internal var sink: (String, Long, String) -> Unit = { label, start, code -> DiagTiming.log(label, start, code) }

    /** The kind of one Keystore operation, as an enumerated word in the per-operation line. */
    enum class Op { OPEN, SEAL, PRESENCE, OTHER }

    /** The class of the thread that runs an operation: an enumerated word, never the thread's name. */
    enum class ThreadClass { MAIN, SNAPSHOT, MODULE_IO, OTHER }

    /** The Keystore operations running now, in every thread. A new operation sees how many others were already in flight. */
    private val inFlight = java.util.concurrent.atomic.AtomicInteger(0)

    internal fun threadClassOf(name: String, isMain: Boolean): ThreadClass = when {
        isMain -> ThreadClass.MAIN
        name == "conet-vault-snapshot" -> ThreadClass.SNAPSHOT
        name == "conet-chat-module" -> ThreadClass.MODULE_IO
        else -> ThreadClass.OTHER
    }

    /** Overridable so a JVM test does not need Android's Looper. Production reads the main looper's thread. */
    @Volatile
    internal var isMainThread: () -> Boolean = {
        try {
            android.os.Looper.getMainLooper().thread === Thread.currentThread()
        } catch (_: Throwable) {
            false
        }
    }

    fun <T> keystore(block: () -> T): T = keystore(Op.OTHER, block)

    /**
     * One Keystore operation: counted in this thread's counters and logged as its own line, `ks.op kind=OPEN others=1 cls=MODULE_IO ok=1`.
     * `others` is how many Keystore operations were already running when this one started (the StrongBox queue); `ok` is 1 when it returned
     * without throwing. Enumerated words and digits only.
     */
    fun <T> keystore(kind: Op, block: () -> T): T {
        val t = System.nanoTime()
        val others = inFlight.getAndIncrement()
        var ok = false
        try {
            val r = block()
            ok = true
            return r
        } finally {
            inFlight.decrementAndGet()
            val a = local.get()
            a.ksOps++
            a.ksNs += System.nanoTime() - t
            val cls = threadClassOf(Thread.currentThread().name, isMainThread())
            sink("ks.op", t, "kind=${kind.name} others=$others cls=${cls.name} ok=${if (ok) 1 else 0}")
        }
    }

    fun <T> derive(block: () -> T): T {
        val t = System.nanoTime()
        try {
            return block()
        } finally {
            val a = local.get()
            a.deriveOps++
            a.deriveNs += System.nanoTime() - t
        }
    }

    /** The counters of this thread now, to be passed to [line] when the measured step ends. */
    fun mark(): Acc = local.get().copy()

    private fun ms(ns: Long) = ns / 1_000_000L

    /** `ksOps=3 ksMs=2100 deriveOps=1 deriveMs=310 lockWaitMs=0` plus an enumerated [outcome] when given: digits and upper-case words only. */
    fun line(since: Acc, lockWaitMs: Long, outcome: String? = null): String {
        val now = local.get()
        val base = "ksOps=${now.ksOps - since.ksOps} ksMs=${ms(now.ksNs - since.ksNs)} deriveOps=${now.deriveOps - since.deriveOps} " +
            "deriveMs=${ms(now.deriveNs - since.deriveNs)} lockWaitMs=$lockWaitMs"
        return if (outcome == null) base else "$base outcome=$outcome"
    }

    fun log(label: String, start: Long, since: Acc, lockWaitMs: Long, outcome: String? = null) {
        sink(label, start, line(since, lockWaitMs, outcome))
    }

    /** The wrapping key's security level, logged once per process: SOFTWARE, TEE, STRONGBOX, SECURE_HARDWARE or UNKNOWN. */
    private val levelLogged = java.util.concurrent.atomic.AtomicBoolean(false)

    fun logWrapKeyLevelOnce(level: () -> String) {
        if (!levelLogged.compareAndSet(false, true)) return
        val word = try {
            level()
        } catch (_: Throwable) {
            "UNKNOWN"
        }
        sink("wrapKey.level", System.nanoTime(), "level=${word.filter { it.isUpperCase() || it == '_' }.ifEmpty { "UNKNOWN" }}")
    }

    internal fun resetForTests() {
        inFlight.set(0)
        local.set(Acc())
        levelLogged.set(false)
    }
}
