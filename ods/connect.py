import pyodbc

conn = pyodbc.connect("Driver=/usr/lib/x86_64-linux-gnu/odbc/libtdsodbc.so;Server=192.168.85.19;Port=3333;Database=esiqprddb;UID=REXSHIH;PWD=es#123;TDS_Version=5.0", autocommit=True)
cur = conn.cursor()
#cur.execute("SELECT @@version")
cur.execute("select TOP 5 * from ESADMIN.DMTB_PRODUCTTYPE_ECMCH")

for row in cur.fetchall():
    print(row)

cur.close()
conn.close()