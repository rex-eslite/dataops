import pymssql

conn = pymssql.connect(
    server="192.168.85.19", port=3333,
    user="REXSHIH", password="es#123",
    database="esiqprddb", tds_version="5.0"
)
cur = conn.cursor()
cur.execute("SELECT @@version")
print(cur.fetchall())
cur.close()
conn.close()