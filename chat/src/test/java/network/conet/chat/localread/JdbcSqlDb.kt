package network.conet.chat.localread

import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Types

/** JVM test implementation of [SqlDb] on xerial sqlite-jdbc (testImplementation only). */
class JdbcSqlDb private constructor(private val conn: Connection) : SqlDb {

    override fun execute(sql: String, args: Array<Any?>) {
        conn.prepareStatement(sql).use { ps ->
            bind(ps, args)
            ps.executeUpdate()
        }
    }

    override fun query(sql: String, args: Array<Any?>): List<Array<Any?>> {
        val out = ArrayList<Array<Any?>>()
        conn.prepareStatement(sql).use { ps ->
            bind(ps, args)
            ps.executeQuery().use { rs ->
                val n = rs.metaData.columnCount
                while (rs.next()) out.add(Array(n) { i -> cell(rs, i + 1) })
            }
        }
        return out
    }

    override fun <T> transaction(block: () -> T): T {
        val prev = conn.autoCommit
        conn.autoCommit = false
        try {
            val r = block()
            conn.commit()
            return r
        } catch (e: Throwable) {
            conn.rollback()
            throw e
        } finally {
            conn.autoCommit = prev
        }
    }

    override fun close() {
        conn.close()
    }

    /** Bytes written to the file so far (WAL mode when a file is used). Used by the cost test. */
    fun walBytes(file: File): Long {
        val wal = File(file.path + "-wal")
        return if (wal.exists()) wal.length() else 0L
    }

    private fun bind(ps: PreparedStatement, args: Array<Any?>) {
        for ((i, a) in args.withIndex()) {
            when (a) {
                null -> ps.setNull(i + 1, Types.NULL)
                is Long -> ps.setLong(i + 1, a)
                is Int -> ps.setInt(i + 1, a)
                is String -> ps.setString(i + 1, a)
                is ByteArray -> ps.setBytes(i + 1, a)
                is Double -> ps.setDouble(i + 1, a)
                else -> throw IllegalArgumentException("unsupported bind ${a.javaClass.simpleName}")
            }
        }
    }

    private fun cell(rs: ResultSet, col: Int): Any? = when (val v = rs.getObject(col)) {
        null -> null
        is Int -> v.toLong()
        is Long -> v
        is Double -> v
        is ByteArray -> v
        else -> v.toString()
    }

    companion object {
        /** In-memory database (lost when the handle closes). */
        fun memory(): JdbcSqlDb = JdbcSqlDb(DriverManager.getConnection("jdbc:sqlite::memory:"))

        /** File database in WAL mode; checkpoints are off so the WAL size reflects bytes written. */
        fun open(file: File?, walCheckpoints: Boolean = true): JdbcSqlDb {
            if (file == null) return memory()
            file.parentFile?.mkdirs()
            val c = DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}")
            c.createStatement().use { st ->
                st.execute("PRAGMA journal_mode=WAL")
                if (!walCheckpoints) st.execute("PRAGMA wal_autocheckpoint=0")
            }
            return JdbcSqlDb(c)
        }
    }
}
