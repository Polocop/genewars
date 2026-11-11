# GWRecomp — Diagnóstico y corrección de 0 cache hits

Fecha: 2026-11-02
Rama/worktree: `storage/reusable-object-cache` / `<worktree>`
HEAD de `main` y del worktree: `b4ebf1acab37912182182b5eade49760f3a0c6d9`

## Resultado

**CAUSA RAÍZ Y CORRECCIÓN (histórico).** La causa era un dato de orquestación del runner incluido por accidente en el hash de entorno: `CODEX_TOOL_CALL_ID`. El runner cambia ese valor en cada llamada de herramienta; cada build real se lanzó en una llamada distinta. Como `object_cache_key()` incorporaba todas las variables de entorno excepto una pequeña lista, ese ID cambiaba las 12 claves aunque los inputs de compilación fueran idénticos.

Se excluyó únicamente `CODEX_TOOL_CALL_ID`, que Clang no interpreta. Una prueba con un objeto real de GWRecomp confirmó que cambiar ese ID no cambia el objeto compilado. La corrección no elimina ni normaliza rutas de `-Work`, flags, dependencias o variables de entorno de compilación.

El hit dirigido y las regresiones pequeñas quedaron validados en esa etapa. La aceptación final de dos builds completos está documentada en la sección final de este informe.

## Diagnóstico previo a la aceptación final

Los manifiestos de `cache-acceptance-cold2` y `cache-acceptance-warm` identifican el mismo espacio (`cache-accept1`, `<GWRECOMP_WORK>\reusable-object-cache\cache-accept1`). Para los 12 objetos:

- Las dos claves históricas difieren.
- Las 12 entradas del primer build aún existen; sus sellos y hashes de contenido son válidos.
- Los SHA-256 de los objetos recompilados en ambos builds son iguales.
- Por tanto, los misses fueron **A: claves realmente distintas**. No fueron fallo de búsqueda, rechazo por corrupción ni espacios de caché diferentes.

El manifiesto histórico no guardó los valores del entorno. Por ello no se puede recalcular retroactivamente el SHA del entorno de cada proceso. La causa concreta se estableció combinando el algoritmo de clave, los nombres de las claves históricas y el entorno del runner: `CODEX_TOOL_CALL_ID` está incluido en el hash antiguo, se inyecta por llamada y no es una entrada de Clang. Los builds fueron dos llamadas separadas. No se atribuye el fallo a los directorios `-Work`.

| Objeto | Clave frío | Clave warm | SHA-256 del objeto en ambos |
|---|---|---|---|
| `ifctitle_creature_probe_closure.obj` | `78ea686062f8b0302356cec2391f121ced68d2e25cb9a592aff6fb18e598e67e` | `81e1cd524a4c9d8c177cdcb5c0735f5e344ef1f4d81f89b9e069f22fd9ee61c0` | `72fe58493607e8ddc492b28e69331fce5df34c34061cf59bf5298eebde7e0839` |
| `lbdataload_callback_init_slice.obj` | `5685af852d598ae22f7df349fb1eeb619d576b378d2f6b4a984634487ff74ba4` | `66b1013b88cbfdb5c230ff1df55f1533fff066f2d9c756601cfd6a3020c01080` | `4b637839e033a5f75b035a82fcd28ae2de5b2fd1b49d560cb4f1e67209ad699c` |
| `recomp_context.obj` | `62efe3edc087848aba1ff34e57fa91bf04885ad053b80ba5fa88ecc71ea5f53c` | `d03251926d37c5a936df1afbffa8764267ee0b41cb4ffb62e705cb236942b014` | `9e6492849ea4684d81b869c52f4baae9e0b3f4cc42fcae068d200dab66814667` |
| `gw_interrupts.obj` | `b19143d34c4bb6d825997eea109cd30d79cd1044a8a83a31bb7c521c7522d7e2` | `8f696747cc9bf4f78045b1b4c3db509f35101505c7fc93cd0a7ab6b8c6a24ea8` | `e9a39464b5e9ef6ad07019942943aa8b2438157191cc42577da961fc5b17b76d` |
| `gw_recomp_trace.obj` | `0ebc3b984552bf244ad155c2783076233bee4ac18661df9f8fbdff961aca5c58` | `27193594a19e8f8f28e20c2902ba94258d4006c7ecc530994345c0d43e3e4af3` | `78604c9115c04505b2269de2c7a9caa37c946561ccd56bca1ca86ca1c41807a6` |
| `gw_segments.obj` | `f90c4dcf07be73581a0894807a68be169980a239f0cb28bcb69942412c75366d` | `2f2f5c99621f59404ac0382fb6ee87e7d2b6de11c1aa4a951232693481ef2adb` | `2ee7202474bdc2c0f8baf5c7f2f9c105fdc8a1215b8b4b95d30b98ce987c783c` |
| `gw_pit8254.obj` | `3e3a267975b9047defe1ed9c5584cea6fe92fc8059085e17c4380e3168695035` | `84716650976f2fd0de132f55b7eb97dd61c7ab9e7fadc9956291c4b2565d13f7` | `5204e67b45fefef8de90bcd8daa28e2185e468dcbe0a9803306220f2ec1e7b50` |
| `gw_dos_services.obj` | `8fb923d1cdfa1901316e0aa3619282fcb4e7863f391e9fe36d0b6abb01e784fc` | `ed2246affd8633bc427b47a1570d37046a4d6d4047d8ec8ff8f6c02adf09bebf` | `bf4af8ea567c52e872312527c57ec4fd2b65f1f87e90cb58e0f3ce34f28528f6` |
| `gw_vbe_provider.obj` | `47dd17ebf2c6fb343bc9b0c8fd9544f9e3dc39fee195b371958fbd58cd1e7561` | `ce1e5cf10b3606eff2b1aa68647d674aeef2b3b551297f5ae30fd4aab9886142` | `e15b2804e2627213686c41d93946f7a8162d9a6824b9819d4a1fd0b4de542266` |
| `recomp_x87.obj` | `f1db935ed7eeafb479edd64e60e175ebab7e8befecb4a6eab12bd75e3ec87b9e` | `0678cc30d5b0f18c545fa38780668d59f91220e9082d418f652ec4b06d8b6485` | `fe14a1b4b93a73a6607575ff43ebed7539a86e50d663fcc20b243ae0a730dff0` |
| `gw_camera_interpolation.obj` | `d0e429f321aab5cd4e9372c8a03bac03b102e8326c5d1ca1b27191e11f50cca5` | `c41fd521f9735a4c8f99cd705875d321dea02a9124bbad351eafe9fff8be2f6d` | `5149120655f7866d6c042569236f5822551a7e5f4cadab657c5f1de25c3c5602` |
| `gw_func_coverage.obj` | `1fa7a817781ec5655b0c4d01178af2c5477a25f40fd737f7d9b1ebe8dd209f1b` | `0fac07aeb282a16f192eeef725f20644a6bce4d6e6e6ba13bc46a89de82cf8c6` | `ceac8d9ca5d2f3ed4151a9d36541422f5c38ac423701c20ef7ef9ed8701c01f0` |

Recomputación de solo lectura desde los dos árboles existentes: los 12 conjuntos de flags normalizados, identidades/comandos efectivos, hashes de fuente, rutas/hash de dependencias y digest de entorno controlado coinciden entre raíces `-Work`. Este cotejo usó IDs simulados distintos con la política corregida; no compiló los objetos ni reconstruyó los valores históricos ausentes.

## Prueba dirigida con un objeto real

Se tomó `gw_camera_interpolation.c` y `gw_camera_interpolation.h` de GWRecomp, copiados sin cambios a dos work roots desechables bajo E:. La compilación usó Clang x64, target `i686-w64-windows-gnu` y los flags de la integración.

- Work A: miss; se almacenó el objeto y su sello SHA-256.
- Work B: hit auténtico con `CODEX_TOOL_CALL_ID` distinto; se devolvió la misma ruta de objeto validada.
- Objeto de 1.666 B. SHA-256 del hit y de una compilación directa sin caché: `5149120655f7866d6c042569236f5822551a7e5f4cadab657c5f1de25c3c5602`. Coincide también con el objeto de los builds reales anteriores.
- Dependencia: se cambió `int current_valid` a `short current_valid` únicamente en la copia aislada del header. El key cambió, hubo miss y el objeto recompilado tuvo otro SHA-256.
- Corrupción: se alteró el contenido del objeto almacenado en la caché de prueba. El sello dejó de validar; se recompiló y el objeto reparado volvió a coincidir con la referencia.
- El test mostró además que, con el filtro anterior, variar solo `CODEX_TOOL_CALL_ID` cambia el key; con el filtro actual, los keys coinciden.

El test usa el código fuente/header auténticos y las dependencias reales, no un objeto artificial. Los directorios de prueba están dentro del temporal propio de la suite en E: y se retiraron al cerrar el test; no se tocaron los builds ni cachés anteriores.

## Corrección e instrumentación

- `object_cache.py`: añadió `CODEX_TOOL_CALL_ID` a las variables de runner que no participan en el key. Se conserva el entorno completo para Clang; únicamente se ignora en la clave la identidad de la llamada del orquestador.
- Añadió `object_cache_key_diagnostics()`, que expone clave, argumentos normalizados, fuente, dependencias y SHA-256 por variable de entorno sin guardar valores crudos.
- `test_ifctitle_creature_probe.py`: con `GWRECOMP_OBJECT_CACHE_DIAGNOSTICS=1`, agrega esos componentes al manifiesto de uso. El diagnóstico es optativo y no cambia el cálculo de la clave.
- `rebuild.ps1`: agregó el switch `-ObjectCacheDiagnostics` porque limpia las variables `GWRECOMP_*` heredadas; el manifiesto de build registra si se activó.
- El filtro puntual está cubierto por el test que demuestra tanto el comportamiento previo (dos keys) como el corregido (un key). No se modificaron flags, entradas, rutas ni criterios fail-closed.

## Cuatro bypasses

Todos son exclusiones fail-closed intencionadas, no errores de integración:

1. `test_ifctitle_creature_probe.obj`: dependencia SDL `SDL_assert.h` contiene macro sensible a ruta/tiempo.
2. `gw_cdda_audio.obj`: la misma dependencia SDL.
3. `gw_vsb16.obj`: la misma dependencia SDL.
4. `gw_terrain_renderer.obj`: `bits/c++config.h` contiene macro sensible a ruta/tiempo.

El detector escanea el texto bruto de cada dependencia; por ello puede excluir una unidad aunque el macro no se expanda en esa unidad. Es conservador. No se forzaron hits para estos objetos.

## Pruebas y coste antes de la aceptación final

- `tools/rebuild/test_object_cache.py`: **13/13 OK**, 12,21 s; incluye los tests previos y la prueba dirigida GWRecomp.
- Parser PowerShell: OK. `git diff --check`: OK.
- DryRun de `-ObjectCacheDiagnostics`: lo presenta habilitado y no crea Work, caché ni archivos.
- No se ejecutó otra compilación completa. Los dos intentos anteriores tardaron 442,4 s y 421,8 s en la fase de build, crearon directorios -Work lógicos de ~357 MB cada uno y el objeto de cierre alcanzó ~3,2 GB de RAM. Completar ahora la aceptación real requiere repetir frío y warm para demostrar los 12 hits; el coste de almacenamiento adicional previsto es del orden de otros dos `-Work` de ~357 MB, más el objeto-cache que no se reutilice. La corrección dirigida reduce el riesgo y justifica esa validación posterior, pero esta tarea no la ejecutó.

Los cuatro bypasses siguen reproduciéndose. El total de entrada del cache legacy anterior continúa en ~94,77 MB porque se conservó sin purga; la prueba dirigida usó un cache temporal pequeño y no amplió ese cache.

## Preservación y estado

`main` permanece limpio en `b4ebf1acab37912182182b5eade49760f3a0c6d9`. No hubo merge, cambios de gameplay/audio ni limpieza de las entradas históricas. Las modificaciones siguen sin commit en la rama de caché. Los dos builds completos previos y sus evidencias permanecen en E:.

**Dictamen histórico previo:** la corrección solo tenía aceptación dirigida en esa etapa. El dictamen definitivo aparece en “Aceptación real final”.

## Aceptación real final (2026-11-02)

**Dictamen: APTA CON LIMITACIONES.** Dos builds completos de compilación/enlace sobre el mismo commit y overlay produjeron 12 hits reales en caliente, hashes de objetos y ejecutable determinista idénticos, y mantuvieron los cuatro bypasses fail-closed. La suite específica pasó 13/13. No se ejecutó el juego ni una prueba de replay/runtime; por eso esta aceptación no declara equivalencia funcional completa. Recomendación: integrar únicamente como opción explícita, conservando bypasses y pruebas, y validar el runtime con la regresión de juego antes de promoverla como ruta predeterminada.

### Precondiciones e identidad

- Commit base/HEAD exacto en ambos: `b4ebf1acab37912182182b5eade49760f3a0c6d9`. `main` mantuvo ese mismo HEAD y limpio; no se hicieron commit ni merge.
- La rama sigue en `<worktree>` con cambios locales de infraestructura de caché solamente (driver de build, módulo/pruebas de caché y documentación). Sin cambios de gameplay/audio ni en otros worktrees.
- Overlay semántico idéntico en A/B: `tests/test_ifctitle_creature_probe.py` SHA-256 `d15b530f466b0a3211c4b75cef5401291ee0836a9fe664a79dcc448326d8587b`; `tools/rebuild/object_cache.py` SHA-256 `6313e13db522432701f74e0984cf94bb8485cf93f5883c4c9807969c229b4f97`.
- Script rebuild registrado en ambos: SHA-256 `953ca29c27f8cef3cb38ab813b19628ef8cdcaf47ddd22145c7ff0190020446d`. Toolchain igual en ambos; Clang x64 SHA-256 `c5d3d309c036d1666d50500e87be514dc9916adc427e7aec267c95178bec14ff`. Cache ID/ruta iguales: `cache-accept1` / `<GWRECOMP_WORK>\reusable-object-cache\cache-accept1`.
- El Build A tuvo 12 misses para las claves probadas: las nuevas entradas reutilizables estaban ausentes al inicio. `CODEX_TOOL_CALL_ID` no aparece en ninguno de los 12 diagnósticos/key componentes; excluirlo no cambió argumentos, opciones, fuentes, dependencias o entorno semántico de compilación. En B las mismas 12 claves se usaron desde otro Work y los objetos restaurados fueron idénticos byte a byte al A.

### Builds, resultados y almacenamiento

| Métrica | Build A frío | Build B caliente |
|---|---:|---:|
| BuildId / Work | `cache-acceptance-final-cold` | `cache-acceptance-final-warm` |
| Fase 6 build | 418.1 s | 197.4 s |
| Cache hits / misses / bypasses | 0 / 12 / 4 | 12 / 0 / 4 |
| Bytes de objeto añadidos a caché | 47381414 | 0 |
| Tamaño lógico de archivos en Work | 328,334,402 B | 328,334,359 B |
| Ejecutable determinista SHA-256 | `eb913729c5b8e430918c768f9caa4d54c3f971e54e39a63532483000843775e7` | `eb913729c5b8e430918c768f9caa4d54c3f971e54e39a63532483000843775e7` |

- La fase de build bajó 220,7 s (52,8 %) entre A y B. Ambos builds completaron las fases 1–8, enlazaron y generaron manifiesto con exit 0.
- Código C generado: `base.c` SHA-256 `cfcee6e81aad70faaa992d2688bc034c8116928e0c41866e388941d4e9cc8dea` en ambos; `ifctitle_creature_probe_closure.c` SHA-256 `b200081f36d7fa4be8bfbd4e95e1aea3d072b26786996ef9912cf4eea39b0354` en ambos. Ejecutable determinista de ambos: `eb913729c5b8e430918c768f9caa4d54c3f971e54e39a63532483000843775e7` (30.956.299 B). El ejecutable predeterminado difiere entre A/B (`7e8005cec6db3f5f733934843104a88b54b8f3d5511195920c5e80dff569d865` / `fc061a09ef57f2af62576ca30871baa62a1bc2f65e1fb84e7f48d8cd5c95a04f`). Se compararon los binarios: las únicas diferencias están en los 4 bytes del `PE TimeDateStamp` y el campo `PE checksum` derivado; la fase 7 enlaza con `--no-insert-timestamp`, y sus ejecutables son idénticos.
- A produjo 47.381.414 B de objetos cacheados; B añadió 0 B. El tamaño lógico total del directorio de caché pasó de 94.765.996 B antes de A a 142.148.994 B después de A/B (delta 47.382.998 B con sellos/metadatos). Work A+B conservan 656.668.761 B lógicos en total.
- El espacio libre de E: medido antes de A fue 299.510.968.320 B y después de B 298.794.971.136 B (variación observada: −715.997.184 B). No es ahorro físico: los dos Work, ejecutables y evidencias quedaron en disco; la caché solo evitó recompilar y volver a almacenar 47,38 MB de objetos cacheables en B. La caída de espacio libre no se atribuye íntegramente al build porque pueden intervenir asignaciones concurrentes/sistema de archivos. No se borró ningún output.
- No se usó una referencia histórica sin caché: no se encontró una referencia demostrablemente idéntica en commit, overlay y entradas. A es la referencia fría válida para B.

### Integridad de objetos

| Objeto | Estado A | Estado B | SHA-256 en A y B |
|---|---|---|---|
| `test_ifctitle_creature_probe.obj` | bypass | bypass | `45d5f8111ee465a1c259bd369ece1abf856a9e7be9d53279b3c87ecdc76ccba2` |
| `ifctitle_creature_probe_closure.obj` | miss | hit | `72fe58493607e8ddc492b28e69331fce5df34c34061cf59bf5298eebde7e0839` |
| `lbdataload_callback_init_slice.obj` | miss | hit | `4b637839e033a5f75b035a82fcd28ae2de5b2fd1b49d560cb4f1e67209ad699c` |
| `recomp_context.obj` | miss | hit | `9e6492849ea4684d81b869c52f4baae9e0b3f4cc42fcae068d200dab66814667` |
| `gw_interrupts.obj` | miss | hit | `e9a39464b5e9ef6ad07019942943aa8b2438157191cc42577da961fc5b17b76d` |
| `gw_recomp_trace.obj` | miss | hit | `78604c9115c04505b2269de2c7a9caa37c946561ccd56bca1ca86ca1c41807a6` |
| `gw_segments.obj` | miss | hit | `2ee7202474bdc2c0f8baf5c7f2f9c105fdc8a1215b8b4b95d30b98ce987c783c` |
| `gw_pit8254.obj` | miss | hit | `5204e67b45fefef8de90bcd8daa28e2185e468dcbe0a9803306220f2ec1e7b50` |
| `gw_dos_services.obj` | miss | hit | `bf4af8ea567c52e872312527c57ec4fd2b65f1f87e90cb58e0f3ce34f28528f6` |
| `gw_vbe_provider.obj` | miss | hit | `e15b2804e2627213686c41d93946f7a8162d9a6824b9819d4a1fd0b4de542266` |
| `recomp_x87.obj` | miss | hit | `fe14a1b4b93a73a6607575ff43ebed7539a86e50d663fcc20b243ae0a730dff0` |
| `gw_camera_interpolation.obj` | miss | hit | `5149120655f7866d6c042569236f5822551a7e5f4cadab657c5f1de25c3c5602` |
| `gw_func_coverage.obj` | miss | hit | `ceac8d9ca5d2f3ed4151a9d36541422f5c38ac423701c20ef7ef9ed8701c01f0` |
| `gw_cdda_audio.obj` | bypass | bypass | `47a3b1865ad6b41ac46eea87e7c54ada6b8703dd6e010c3f1035cd7fbe27aaf3` |
| `gw_vsb16.obj` | bypass | bypass | `93ea118d1f7c0cd8819f5d95eb151b1c47bb2f17f348c50bd53b6e6ea3d30bf5` |
| `gw_terrain_renderer.obj` | bypass | bypass | `4a7295edd2a30953fc21490796fef0506e63fc53d7ddf9ecc1eda83521f4f94f` |

Se verificaron SHA-256 del contenido de los 12 objetos recuperados desde caché (12/12), sus sellos, las 12 claves A/B y los 16 hashes de objetos comparados entre ambos builds (16/16 iguales). Los cuatro bypasses se mantuvieron y sus objetos quedaron en los Work: `test_ifctitle_creature_probe.obj` (harness, SDL `SDL_assert.h`), `gw_cdda_audio.obj` y `gw_vsb16.obj` (SDL `SDL_assert.h`), y `gw_terrain_renderer.obj` (`bits/c++config.h`); el detector conservador de macros sensibles a ruta/tiempo impidió cachearlos.

### Pruebas y límites

- `tools/rebuild/test_object_cache.py`: **13/13 PASS**, 12,590 s. Incluye hit real sobre `gw_camera_interpolation.c`, mismo SHA que compilación directa, invalidación por cambio de header, rechazo/reconstrucción de objeto corrupto y clave estable ante distintos IDs de llamada.
- Parser PowerShell de `rebuild.ps1`: 0 errores. `git diff --check`: PASS. Ambos builds: PASS incremental native SDL2 interactive build, enlace determinista y manifiesto.
- No se ejecutó la ventana/juego, replay ni suite de aceptación runtime. La caché valida compilación, restauración, enlace y determinismo binario medido; esto no prueba por sí solo equivalencia funcional completa del juego.

### Recomendación final

La caché queda **APTA CON LIMITACIONES** para integrar como función optativa en infraestructura. Mantenerla desactivada por defecto hasta que la regresión runtime existente pase con esta rama; conservar los cuatro bypasses fail-closed. No integrar como mecanismo predeterminado ni afirmar ahorro neto de disco: dos directorios Work aún guardan intermediarios y ejecutables completos. No hubo merge, commit, limpieza ni cambios de `main`.
