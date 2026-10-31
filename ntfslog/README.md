# ntfslog

Reimplementación en Go del parseo de `$LogFile` de **NTFS Log Tracker v1.71** (Junghoon Oh), con el mismo resultado que el original:

- la tabla `LogFile` de la DB SQLite (filas, valores, rowids y tabla `TimeZone`);
- el CSV `NLT_LogFile_*.csv`, idéntico byte a byte.

Está en Go puro, sin cgo: SQLite es `modernc.org/sqlite`.

## Uso

```bash
go build -o ntfslog.exe ./cmd/ntfslog
```

```bash
ntfslog.exe -logfile "C:\caso\$LogFile" -utc=-3 -db salida.db -csv C:\caso\salida
```

| Opción | Equivale en el original a |
|---|---|
| `-utc N` | combo de huso horario (-12..14) |
| `-dst` | casilla DST (+1 hora) |
| `-mft P` | campo `$MFT` (opcional; aporta FileName, FullPath y tiempos) |
| `-db P` | DB SQLite (esquema UTF-16le y páginas de 1024 bytes, como el original) |
| `-csv P` | archivo CSV, o una carpeta para `NLT_LogFile_<fecha>.csv` |
| `-trace P` | JSONL con cada sentencia SQL que ejecutaría el original (para verificación) |

Como biblioteca:

```go
st, err := nlt.Parse(logFileBytes, nlt.Options{UTC: -3, DST: false, MFT: mftBytes})
nlt.WriteDB("out.db", st)
nlt.WriteCSV(w, st)
```

## Verificación

- `re/oracle/` ejecuta el original bajo Frida (sesiones REA) y graba cada sentencia SQL, la DB y el CSV en `runs/*`.
- `sh re/oracle/verify_all.sh` corre el port sobre cada referencia y compara tres cosas:
  - el flujo SQL, instrucción por instrucción (`trace_diff.py`);
  - la DB (`compare.py`);
  - el CSV, byte a byte.

Las 10 corridas de referencia son idénticas: 4 `$LogFile` distintos, dos corridas con `$MFT`, y husos UTC-3, UTC0, UTC+9 DST y UTC-5 DST.

### Simulaciones (fuzz diferencial)

- **Generadores:** `re/fuzz/gen_*.py` crean casos en `fuzz/cases/<id>/`. Hay cuatro familias:
  - mutaciones de estructura LFS;
  - registros con valores límite por evento;
  - volúmenes NTFS reales en VHD con actividad simulada;
  - `$MFT` adversarios.
- **Runner:** `python re/fuzz/campaign.py` ejecuta el original (bajo Frida, de a una instancia) y el port en cada caso, y clasifica el resultado:

  | Resultado | Significado |
  |---|---|
  | `match` | igual |
  | `match-crash` | el original muere y el port lo predice, con las mismas sentencias previas |
  | `match-nondet` | igual salvo filas que varían entre dos ejecuciones del propio original |
  | `diverge*` | diferencia real |

- **Regresión:** `--go-only` vuelve a comparar el port contra las salidas guardadas del original, sin volver a ejecutarlo.

## Notas de fidelidad

Se reproducen a propósito estos comportamientos del original:

- **Páginas de cola LFS 2.0:** también lee las copias de cola. Los LSN repetidos se insertan dos veces; gana la primera aparición y el segundo INSERT falla en silencio.
- **Escapado sin deshacer:** el original escapa `'` → `''` y reemplaza `,` → `/` en el registro en memoria. Las filas posteriores que copian nombres de él guardan `''`.
- **Temp Event:** las filas "Temp Event" se insertan y se borran al final, y cuentan en las ventanas de búsqueda hacia atrás.
- **Tiempos de Add Index Entry:** en las filas de Add Index Entry los tiempos no se ajustan al huso horario.
- **CSV:** se escribe en la página de códigos ANSI del hilo (`WideCharToMultiByte`, con best-fit y `?`). Fuera de Windows se aproxima con cp1252.
- **`qsort`:** el de MSVC 2010 está portado tal cual. No es estable, y así el orden de páginas con claves iguales coincide.

- **`$LogFile` no soportado** (sin páginas RSTR, o LFS distinto de 1.1/2.0): el original no aborta. Deja la tabla LogFile vacía, inserta la fila de TimeZone y exporta el CSV solo con encabezado; el port hace lo mismo.
- **Ajuste horario fuera de rango** (`AdjustTimeString`): si el resultado cae antes de 1601, el original imprime la fecha de entrada sin ajustar, y el port también.
- **Nombres con U+FFFF:** el original pasa cada nombre por `Format("%s")`. El CRT trata un U+FFFF escrito como `WEOF` y deja el nombre en blanco (vacío para `wcscmp`, `wcsstr` y `%s`). Las rutas del `$MFT` con ese nombre se descartan. U+FFFE no se ve afectado.
- **Surrogates sueltos (SQLite 3.7.3):** `prepare16` une cada unidad 0xD800..0xDFFF con la siguiente, sea cual sea. Si esa unidad es una comilla, la sentencia no compila y no se inserta la fila (ni se consume rowid). Si no, se guarda el par resultante. U+FFFE y U+FFFF se guardan como U+FFFD.
- **LSN ≥ 2^63:** SQLite 3.7.3 lo guarda como REAL (se pierde el último dígito y se redondea a double). Los LSN que caen en el mismo double chocan en la clave primaria y gana el primero. Los REAL se ordenan después de todos los INTEGER, y el CSV los escribe con `%!.15g` de SQLite.
- **Campos CSV largos:** se escriben completos. En el original, a partir de ~0xd00 unidades el campo se lee de un buffer de pila ya liberado y su contenido varía entre ejecuciones; es un área no determinista y no se reproduce.

**Límites (no deterministas en el propio original):**

- **Año de 5 dígitos (30827):** el original suma el huso a un FILETIME sin inicializar. El resultado cambia en cada ejecución (2332, 2422, 2259...), así que ninguna reimplementación puede reproducirlo. El port devuelve la fecha sin ajustar.
- **Campos CSV de más de ~3500 caracteres:** el original relee cada valor desde un buffer de un frame de pila ya liberado.
  - Corta el campo en 0xdaa, 0xe8c, 0xe8e, 0xf20, 0xf5e o 0xf60 unidades y agrega de 0 a 8 caracteres basura; el corte varía entre ejecuciones.
  - El port escribe el campo completo.
  - El harness compara exacto hasta 0xdaa unidades, el corte más temprano medido.
  - Depende también de la versión de Windows. En Windows Server 2025, desde unas 0xeff unidades, el original omite la fila entera del CSV.
- **Run length de 13–15 bytes:** pisa el byte bajo del Parser* guardado. Que el puntero corrupto haga caer al original depende de la dirección del heap.
  - Con la misma entrada y el mismo SO, el original murió en 19 de 20 VMs y sobrevivió en 1.
  - El port predice la caída, que es el resultado mayoritario.

Las otras lecturas de memoria no inicializada (tmpHdr, frame y slots SYSTEMTIME nunca escritos) se leen como cero y están registradas como incógnitas en REA.

**Estado del fuzz diferencial:** 377 casos, entre ellos 168 volúmenes NTFS reales. Todos coinciden con el original:

| Resultado | Casos |
|---|---|
| match | 284 |
| match-nondet | 69 |
| match-crash | 24 |

Las 10 corridas de referencia son idénticas.
