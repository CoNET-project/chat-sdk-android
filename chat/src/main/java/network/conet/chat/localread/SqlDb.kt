package network.conet.chat.localread

import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import java.io.File

/**
 * Minimal SQL handle for the local store (spec r3a 7.1, D-A1 replacement). Two implementations:
 * [AndroidSqlDb] (android.database.sqlite, production) and a JDBC one in the JVM test sources
 * (xerial sqlite-jdbc, testImplementation only). Values are String, Long, Double, ByteArray or null.
 * Rows come back as arrays in column order; integers as Long.
 */
interface SqlDb {
    fun execute(sql: String, args: Array<Any?> = emptyArray())
    fun query(sql: String, args: Array<Any?> = emptyArray()): List<Array<Any?>>
    fun <T> transaction(block: () -> T): T
    fun close()
}

/** android.database.sqlite implementation. [file] null = in-memory. */
class AndroidSqlDb private constructor(private val db: SQLiteDatabase) : SqlDb {

    override fun execute(sql: String, args: Array<Any?>) {
        db.execSQL(sql, normalize(args))
    }

    override fun query(sql: String, args: Array<Any?>): List<Array<Any?>> {
        val out = ArrayList<Array<Any?>>()
        db.rawQuery(sql, normalize(args).map { it?.toString() }.toTypedArray()).use { c ->
            while (c.moveToNext()) out.add(readRow(c))
        }
        return out
    }

    override fun <T> transaction(block: () -> T): T {
        db.beginTransaction()
        try {
            val r = block()
            db.setTransactionSuccessful()
            return r
        } finally {
            db.endTransaction()
        }
    }

    override fun close() {
        db.close()
    }

    private fun readRow(c: Cursor): Array<Any?> = Array(c.columnCount) { i ->
        when (c.getType(i)) {
            Cursor.FIELD_TYPE_NULL -> null
            Cursor.FIELD_TYPE_INTEGER -> c.getLong(i)
            Cursor.FIELD_TYPE_FLOAT -> c.getDouble(i)
            Cursor.FIELD_TYPE_BLOB -> c.getBlob(i)
            else -> c.getString(i)
        }
    }

    /** Int becomes Long so the binding type is stable; other values pass through. */
    private fun normalize(args: Array<Any?>): Array<Any?> = Array(args.size) { i ->
        when (val v = args[i]) {
            is Int -> v.toLong()
            else -> v
        }
    }

    companion object {
        /** Opens (or creates) the database file. Null opens an in-memory database. */
        fun open(file: File?): AndroidSqlDb {
            val db = if (file == null) {
                SQLiteDatabase.create(null)
            } else {
                file.parentFile?.mkdirs()
                SQLiteDatabase.openOrCreateDatabase(file, null)
            }
            db.execSQL("PRAGMA foreign_keys = OFF")
            return AndroidSqlDb(db)
        }
    }
}
