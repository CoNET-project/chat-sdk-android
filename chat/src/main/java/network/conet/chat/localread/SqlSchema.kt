package network.conet.chat.localread

/**
 * SQLite schema and key-range queries (spec r3a section 7.1, D-A1 replacement).
 * Pure constants, no Android types: the SQL text is unit-tested on the JVM; execution needs android.database.sqlite.
 *
 * Plaintext columns are limited to the blind indexes and the fields listed in 7.1 (sort_ts, revision, state,
 * pending_publish). Bodies and metadata are sealed (AES-256-GCM, 7.2). There is no send_id, preview,
 * conv_key, kind, dir or ts column in plaintext.
 */
object SqlSchema {
    const val SCHEMA_VERSION = 1

    /** Deleted rows: state 1 = tombstone, state 2 = superseded (folded); both mean deleted. */
    const val STATE_NORMAL = 0
    const val STATE_TOMBSTONE = 1
    const val STATE_SUPERSEDED = 2

    /** Page size bound for one key-range query (raw rows). The caller passes n + 1 to probe hasOlder. */
    const val MAX_PAGE_ROWS = 200

    val DDL: List<String> = listOf(
        """CREATE TABLE IF NOT EXISTS meta (
            k TEXT PRIMARY KEY,
            v_enc BLOB NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS conv (
            conv_blind TEXT PRIMARY KEY,
            meta_enc BLOB NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS msg (
            conv_blind TEXT NOT NULL,
            stable_id TEXT NOT NULL,
            sort_ts INTEGER NOT NULL,
            revision INTEGER NOT NULL DEFAULT 0,
            state INTEGER NOT NULL DEFAULT 0,
            pending_publish INTEGER NOT NULL DEFAULT 0,
            cid_blind TEXT,
            body_enc BLOB,
            meta_enc BLOB,
            PRIMARY KEY (conv_blind, sort_ts, stable_id)
        )""",
        "CREATE UNIQUE INDEX IF NOT EXISTS msg_id_uq ON msg (conv_blind, stable_id)",
        "CREATE INDEX IF NOT EXISTS msg_cid ON msg (conv_blind, cid_blind)",
        """CREATE TABLE IF NOT EXISTS alias (
            alias_blind TEXT PRIMARY KEY,
            target_enc BLOB NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS layout (
            conv_blind TEXT NOT NULL,
            stable_id TEXT NOT NULL,
            layout_key TEXT NOT NULL,
            val_enc BLOB NOT NULL,
            PRIMARY KEY (conv_blind, stable_id, layout_key)
        )""",
    )

    /**
     * Page query: rows of one conversation strictly before the cursor key (sort_ts, stable_id), newest first.
     * Without a cursor the bounds are omitted. Byte order of ASCII stable ids matches SQLite BINARY collation.
     */
    fun pageSql(hasCursor: Boolean): String {
        val bound = if (hasCursor) " AND (sort_ts < ? OR (sort_ts = ? AND stable_id < ?))" else ""
        return "SELECT stable_id, sort_ts, revision, state, pending_publish, cid_blind, body_enc, meta_enc " +
            "FROM msg WHERE conv_blind = ?$bound ORDER BY sort_ts DESC, stable_id DESC LIMIT ?"
    }

    /** Number of parameters [pageSql] expects, in order: conv_blind, [sort_ts, sort_ts, stable_id], limit. */
    fun pageArgCount(hasCursor: Boolean): Int = if (hasCursor) 5 else 2

    /** Full-history scan for the sync and for the M3 verification (ascending K). */
    const val ALL_ROWS_SQL: String =
        "SELECT conv_blind, stable_id, sort_ts, revision, state, body_enc, meta_enc FROM msg ORDER BY conv_blind, sort_ts, stable_id"

    /** Row lookup by stable id (the sync skip rule, 9.2 step 2). */
    const val BY_STABLE_SQL: String =
        "SELECT revision, state, body_enc FROM msg WHERE conv_blind = ? AND stable_id = ?"

    /** Row lookup by cid blind index (diagnostic and fast path only; correctness does not depend on it). */
    const val BY_CID_SQL: String =
        "SELECT stable_id, state, body_enc FROM msg WHERE conv_blind = ? AND cid_blind = ? LIMIT 1"

    /** Pending rows are kept by clearing (T-12). */
    const val CLEAR_CONV_SQL: String =
        "DELETE FROM msg WHERE conv_blind = ? AND pending_publish = 0"

    /** Newest row of a conversation, for the conversation list (6.7). */
    const val LAST_ROW_SQL: String =
        "SELECT sort_ts, stable_id FROM msg WHERE conv_blind = ? AND state = 0 ORDER BY sort_ts DESC, stable_id DESC LIMIT 1"
}
