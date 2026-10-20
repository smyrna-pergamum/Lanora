using Microsoft.Data.Sqlite;

namespace Lanora.Data;

/// <summary>Small ADO helpers; all values are passed as parameters.</summary>
public static class Db
{
    public static SqliteCommand Command(SqliteConnection c, SqliteTransaction? tx, string sql, params (string Name, object? Value)[] ps)
    {
        var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return cmd;
    }

    public static int Exec(SqliteConnection c, SqliteTransaction? tx, string sql, params (string, object?)[] ps)
    {
        using var cmd = Command(c, tx, sql, ps);
        return cmd.ExecuteNonQuery();
    }

    public static long Insert(SqliteConnection c, SqliteTransaction? tx, string sql, params (string, object?)[] ps)
    {
        using var cmd = Command(c, tx, sql + "; SELECT last_insert_rowid();", ps);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    public static T? Scalar<T>(SqliteConnection c, SqliteTransaction? tx, string sql, params (string, object?)[] ps)
    {
        using var cmd = Command(c, tx, sql, ps);
        var v = cmd.ExecuteScalar();
        if (v is null || v is DBNull) return default;
        var target = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
        return (T)Convert.ChangeType(v, target, System.Globalization.CultureInfo.InvariantCulture);
    }

    public static List<T> Query<T>(SqliteConnection c, SqliteTransaction? tx, string sql, Func<SqliteDataReader, T> map, params (string, object?)[] ps)
    {
        using var cmd = Command(c, tx, sql, ps);
        using var r = cmd.ExecuteReader();
        var list = new List<T>();
        while (r.Read()) list.Add(map(r));
        return list;
    }

    public static string? Str(this SqliteDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetString(i);
    }

    public static long? Long(this SqliteDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetInt64(i);
    }

    public static int? Int(this SqliteDataReader r, string col) => (int?)r.Long(col);

    public static double? Dbl(this SqliteDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetDouble(i);
    }

    public static bool Bool(this SqliteDataReader r, string col) => (r.Long(col) ?? 0) != 0;
}
