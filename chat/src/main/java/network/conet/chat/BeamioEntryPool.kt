package network.conet.chat

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Warm entry pool for one-shot POSTs ([BeamioSiCipherPost.post]).
 *
 * Keeps several roster entries that answered a plain `GET /` recently, so a send
 * takes a checked entry at once instead of probing first. Each send takes a random
 * warm entry that differs from the last few sends; the set rotates one entry per
 * refresh. Same rules as the iOS SDK.
 *
 * Runs only while the SDK is active: an activity of the app is started, or the
 * shell holds it (ringing, dialing, in a call, push wake). Nothing runs in the
 * background otherwise. Probes are bare `GET /` on port 80: no wallet, no
 * signature, no identity, no call data.
 */
object BeamioEntryPool {
    private const val TAG = "BeamioEntryPool"
    private const val TARGET_READY = 8
    private const val TICK_MS = 15_000L
    private const val MAX_LATENCY_MS = 1_500
    private const val PROBE_TIMEOUT_MS = 2_000
    private const val ENTRY_MAX_AGE_MS = 90_000L
    private const val RECENT_AVOID = 3

    private data class Entry(val ip: String, val latencyMs: Int, val checkedAt: Long)

    /** Last ready set, saved after each refresh: a push wake uses it before the first probe ends. */
    private const val CACHE_FILE = "conet-entry-pool.txt"
    private const val CACHE_MAX_AGE_MS = 30 * 60_000L
    @Volatile private var cached: List<String> = emptyList()
    @Volatile private var cachedAt = 0L

    private val ready = ConcurrentHashMap<String, Entry>()
    private val recent = ArrayDeque<String>()
    private val holds = mutableSetOf<String>()
    private val lock = Any()

    @Volatile private var app: Context? = null
    @Volatile private var startedActivities = 0
    private val attached = AtomicBoolean(false)
    private val ticking = AtomicBoolean(false)

    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "conet-entry-pool").apply { isDaemon = true }
    }
    private val probes = Executors.newFixedThreadPool(6) { r ->
        Thread(r, "conet-entry-probe").apply { isDaemon = true }
    }
    private var future: ScheduledFuture<*>? = null

    /** Shell: once per process (Application, Activity or service context). */
    fun attach(context: Context) {
        val application = context.applicationContext as? Application ?: return
        app = application
        if (!attached.compareAndSet(false, true)) return
        loadCache(application)
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: Activity) {
                startedActivities++
                activityChanged()
            }

            override fun onActivityStopped(activity: Activity) {
                startedActivities = (startedActivities - 1).coerceAtLeast(0)
                activityChanged()
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
        // Attached from a started activity (e.g. MainActivity.onCreate → onStart follows).
        activityChanged()
    }

    /** Shell: true while a call rings, dials or is up (checked on every refresh). */
    @Volatile var holdWhile: (() -> Boolean)? = null

    val isActive: Boolean
        get() = startedActivities > 0 || synchronized(lock) { holds.isNotEmpty() } ||
            (try { holdWhile?.invoke() == true } catch (_: Exception) { false })

    /** Keep warming while [reason] holds (e.g. `"call"`, `"incomingCall"`). */
    fun hold(reason: String) {
        val added = synchronized(lock) { holds.add(reason) }
        if (added) activityChanged()
    }

    fun release(reason: String) {
        val removed = synchronized(lock) { holds.remove(reason) }
        if (removed) activityChanged()
    }

    /** Refresh now (push wake, node table change). No-op while inactive. */
    fun warmNow() {
        scheduler.execute { tick() }
    }

    private fun activityChanged() {
        scheduler.execute {
            if (isActive) {
                if (future == null) {
                    future = scheduler.scheduleWithFixedDelay({ tick() }, 0, TICK_MS, TimeUnit.MILLISECONDS)
                }
            } else {
                future?.cancel(false)
                future = null
            }
        }
    }

    /**
     * A random warm entry inside [allowed], outside [excluding], preferably not one of
     * the last few used. Before the first refresh of this process (push wake), the
     * entries saved by the last refresh are used, up to [CACHE_MAX_AGE_MS] old.
     */
    fun take(allowed: Set<String>, excluding: Set<String>): String? {
        val now = System.currentTimeMillis()
        var usable = ready.values.filter {
            it.ip in allowed && it.ip !in excluding && now - it.checkedAt < ENTRY_MAX_AGE_MS * 2
        }.map { it.ip }
        if (usable.isEmpty() && now - cachedAt < CACHE_MAX_AGE_MS) {
            usable = cached.filter { it in allowed && it !in excluding }
        }
        if (usable.isEmpty()) return null
        val ip = synchronized(lock) {
            val fresh = usable.filter { it !in recent }
            val picked = (fresh.ifEmpty { usable }).random()
            recent.addLast(picked)
            while (recent.size > RECENT_AVOID) recent.removeFirst()
            picked
        }
        return ip
    }

    /** A send through [ip] failed: drop it until a later probe brings it back. */
    fun reportFailure(ip: String) {
        ready.remove(ip)
        cached = cached - ip
    }

    /** IPs that answered a probe lately (e.g. to prefer a live voice relay). */
    fun warmIps(): Set<String> {
        val now = System.currentTimeMillis()
        return ready.values.filter { now - it.checkedAt < ENTRY_MAX_AGE_MS * 2 }.map { it.ip }.toSet()
    }

    private fun loadCache(ctx: Context) {
        runCatching {
            val f = java.io.File(ctx.filesDir, CACHE_FILE)
            if (!f.exists()) return
            val lines = f.readLines()
            val at = lines.firstOrNull()?.toLongOrNull() ?: return
            cached = lines.drop(1).mapNotNull { BeamioSiCipherPost.normalizeIp(it) }
            cachedAt = at
        }
    }

    private fun saveCache(ctx: Context) {
        val ips = ready.keys.toList()
        if (ips.isEmpty()) return
        runCatching {
            // IPs only (public node table entries): no wallet, no identity.
            java.io.File(ctx.filesDir, CACHE_FILE).writeText((listOf(System.currentTimeMillis().toString()) + ips).joinToString("\n"))
        }
        cached = ips
        cachedAt = System.currentTimeMillis()
    }

    /** Node table changed: removed IPs leave the pool now; new ones are probed first. */
    fun nodesChanged(removed: Set<String>) {
        removed.forEach { ready.remove(it) }
        warmNow()
    }

    val readyCount: Int get() = ready.size

    private fun rosterIps(ctx: Context): List<String> =
        BeamioChatPgpStore.loadSiNodes(ctx)
            .mapNotNull { BeamioSiCipherPost.normalizeIp(it.ip) }
            .filter { !BeamioSiCipherPost.isMarkedUnreachable(it) }
            .distinct()

    /** On the scheduler thread. */
    private fun tick() {
        val ctx = app ?: return
        if (!isActive) {
            activityChanged()  // stops the timer
            return
        }
        if (!ticking.compareAndSet(false, true)) return
        try {
            // The node table check rides on the same activity (no polling while inactive).
            BeamioGuardianNodeWatch.tick(ctx)
            val roster = rosterIps(ctx)
            val rosterSet = roster.toSet()
            val now = System.currentTimeMillis()
            ready.keys.filter { it !in rosterSet }.forEach { ready.remove(it) }
            val stale = ready.values.filter { now - it.checkedAt > ENTRY_MAX_AGE_MS }.map { it.ip }.toMutableList()
            // Rotate: once full, retire the oldest-checked entry so the set keeps changing.
            if (ready.size >= TARGET_READY) {
                ready.values.minByOrNull { it.checkedAt }?.let { oldest ->
                    ready.remove(oldest.ip)
                    stale.remove(oldest.ip)
                }
            }
            val have = ready.keys.toSet()
            val need = (TARGET_READY - have.size + stale.size).coerceAtLeast(0)
            val fresh = roster.filter { it !in have }.shuffled().take(need + 2)
            val jobs = (stale + fresh).map { ip ->
                ip to probes.submit<Int?> {
                    val r = BeamioSiCipherPost.probeIp(ip, PROBE_TIMEOUT_MS)
                    BeamioSiCipherPost.scoreEntry(ip, r.reachable, r.latencyMs)
                    if (r.reachable) r.latencyMs else null
                }
            }
            for ((ip, job) in jobs) {
                val latency = try {
                    job.get(PROBE_TIMEOUT_MS + 1_500L, TimeUnit.MILLISECONDS)
                } catch (_: Exception) {
                    null
                }
                if (latency != null && latency <= MAX_LATENCY_MS && ip in rosterSet) {
                    ready[ip] = Entry(ip, latency, System.currentTimeMillis())
                } else {
                    ready.remove(ip)
                }
            }
            if (ready.size > TARGET_READY) {
                val keep = ready.values.sortedBy { it.latencyMs }.take(TARGET_READY).map { it.ip }.toSet()
                ready.keys.filter { it !in keep }.forEach { ready.remove(it) }
            }
            saveCache(ctx)
        } catch (e: Exception) {
            Log.w(TAG, "refresh failed: ${e.message}")
        } finally {
            ticking.set(false)
        }
    }
}
