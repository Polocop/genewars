# v3.0: lectura de entidades de Gene Wars 1.1

Base de código: 8a2b2d0c80b4f92de7abc3077dc0033f7f96bb09.
LE 1.1 identificado por SHA-256 2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f.
Las direcciones de datos son lineales guest de este entorno. Los EIP citados son direcciones de enlace.

| Tabla | Base | Registros | Paso | Thing +0x06 |
| --- | ---: | ---: | ---: | ---: |
| Criaturas | 0x0032CF86 | 300 | 0x7C | 1 |
| Plantas | 0x003360D6 | 512 | 0x31 | 2 |
| Especialistas | 0x0033C2D6 | 20 | 0xC8 | 3 |
| Edificios | 0x0033D276 | 256 | 0x43 | 4 |
| Efectos | 0x00341576 | 200 | 0x51 | 5 |

Los primeros cuatro límites coinciden con el inicio de la tabla siguiente. Para edificios, el código de 0x11D50/0x11D57 usa la base y el paso 0x43. El grupo de 0x10C0 bytes que figura en un inventario histórico contiene 64 registros. 0x29610–0x29618 indexa los efectos con paso 0x51. El tipo coincidente indica un objeto residente, no prueba que se deba dibujar.

- 0x78B66 y 0x78B6A leen Y de +0x09 y X de +0x07 como palabras con signo y llaman a 0x65630. +0x18 es el byte de propietario en el censo previo, no un identificador de paleta.
- 0x65630 usa el mapa de 0x002F4F86, celdas de 14 bytes, altura con signo en +0x02 y coordenadas con ocho bits fraccionarios. Envuelve ambos ejes módulo 128. En 0x65707–0x65795 interpola por los dos triángulos de cada celda. El lector guarda altura q6 en unidades de mapa antes de la escala de pantalla. 0x78BA1 invoca la ranura virtual +4 de la tabla +0x23 y 0x78BA8–0x78BAB resta su contribución vertical tras desplazarla seis bits. Las cinco tablas contienen dos implementaciones en los snapshots inspeccionados. 0x6A2E0 (VA rebased 0x2552E0) devuelve dword +0x27 menos dword +0x11, observado en criaturas, especialistas y efectos. 0x6EE40 (VA rebased 0x259E40) devuelve cero, observado en plantas y edificios. El lector combina esa contribución con el suelo interpolado y escalado para obtener la elevación de dibujo en q6. Solo se aceptan escalas 1 y 2 y contratos de vtable identificados. No se invocan métodos guest.
- 0x919C0 / 0x91AE0 reciben el ancla de pantalla en EAX/EDX y el fotograma en EBX. El fotograma contiene el puntero a elementos en +0x00 y el conteo de elementos en +0x0B. Cada elemento mide 10 bytes: puntero de sprite +0x00, desplazamientos firmados X/Y +0x04/+0x06 y flags +0x08. La anchura/altura del descriptor de sprite están en +0x04/+0x05. 0x91A56 y 0x91B7D combinan los flags del elemento con el estado de 0x376AB8. En 0x91A64–0x91A78 se ve el ajuste de X por flip y anchura. 0x919CF y 0x91AEF conservan CL y lo pasan al blit. Falta demostrar qué variantes de ese argumento son equipo, tinte o modo de blit y ligar cada llamada a la entidad propietaria.
- La tabla de efectos sí contiene objetos con geometría propia. El inventario no demuestra que cada haz, explosión o destello tenga una entrada. En particular, falta ligar la nave y el haz a sus emisores con posición verificable.
- El terreno lit de la base pasa a gl_Position.z el valor a_pos.z de su orden de rasterización. Esa profundidad no se puede compartir con billboards hasta definir una profundidad común a partir de las posiciones de mundo y validar el signo respecto de la proyección. La textura del terreno y la niebla tampoco son una prueba de visibilidad de una entidad en la tabla.

## Uso

El lector const de runtime/gw_entity_3d.h no asigna fotogramas ni altera la simulación. GW_ENTITY_LAYOUT_PROBE=<ruta CSV> permite inspeccionar los candidatos del primer IFCMain con datos desde el punto de publicación del runtime interactivo. El diagnóstico fuera del juego tests/test_gw_entity_3d_snapshot.c permite comprobar el mismo lector contra los snapshots GWSNAP2 existentes.

## Alcance

Forman parte de este escalón el lector y el inventario. La escena con billboards, el atlas, las sombras, las luces desde entidades, la separación de todos los indicadores de interfaz y la ampliación del zoom siguen pendientes. Suprimir píxeles de WScreen antes de identificar los blits por entidad dejaría huecos y mezclaría efectos con indicadores de interfaz.

## Asociación de dibujo en el escalón 2

La instrumentación abre un ámbito de propietario alrededor de las llamadas de dibujo 0x79178, 0x7925B, 0x793BD y 0x793EC. Captura EAX antes de que lo reutilice el método virtual y restaura el propietario anterior al salir. La traza es opcional en modo interactivo con GW_ENTITY_DRAW_PROBE=<ruta CSV>.

| Subrutina de fotograma | Llamadas al blit | Blit | Registro del fotograma |
| --- | --- | --- | --- |
| 0x919C0 | 0x91A39, 0x91AB7 | 0x904E0 | EBP |
| 0x91AE0 | 0x91B60, 0x91BE4 | 0x90F90 | EBP |
| 0x965F0 | 0x96670, 0x966F2 | 0x99A20 | [SS:ESP] |

Se registra el descriptor del sprite que recibe EBX y su puntero de datos en +0x00, además de las dimensiones en +0x04/+0x05 y el ancla de cada componente (EAX/EDX y origen de clip 0x376A80/84). El bit 0 del estado 0x376AB8 es el flip horizontal del blit normal. Se conservan la palabra completa, ECX, la huella de la paleta VGA activa y, en 0x90F90, el argumento adicional de pila que prepara el llamador. El significado visual de todos los selectores y efectos de blit sigue requiriendo validación. Un registro con entity_type=0 indica un objeto sin enlace confirmado al censo. El punto de observación está antes de que el blit recorte la imagen y no significa que haya escrito píxeles.

## Clasificación de 0x90F90

El remapeo adicional apuntó a seis tablas de 256 bytes en el tramo de Exceland, siempre con CL=0xC0 y con los flags 0x0000 o 0x0001. Las huellas de paleta de la traza son iguales a las del DAC de los cuatro snapshots y a la paleta MAIN.PAL de la instalación. Las tablas conservan los mismos bytes en los cuatro snapshots. La traza contiene el puntero y los flags en vivo. Los bytes de las tablas proceden de los snapshots, no de un volcado del mismo tick.

| Tabla guest | Flags 0 | Flags 1 | Modo observado |
| --- | ---: | ---: | --- |
| 0x00364254 | 4 | 0 | Opaco con remapeo |
| 0x00364354 | 6 | 0 | Opaco con remapeo |
| 0x00364454 | 6 | 0 | Opaco con remapeo |
| 0x00364554 | 190 | 0 | Opaco con remapeo |
| 0x00364654 | 57 | 136 | Opaco con remapeo |
| 0x00364754 | 1 | 5 | Opaco con remapeo |

En 0x90FDB y 0x90FF2, los flags 0/2 llevan a la ruta de copiado directo. Con el flip horizontal, 0x91056 salta a 0x91566 cuando no están activos los bits 0x04/0x08. En 0x915CA–0x915F5 se reemplaza C0–CF por el selector CL más el nibble bajo. El byte resultante indexa la tabla adicional y 0x915BC escribe ese color sin leer el destino. El camino normal hace la misma sustitución cerca de 0x917BF y escribe en 0x917D4. Estos casos corresponden al subpase opaco con profundidad y descarte de transparencia.

Con los bits 0x04/0x08 se permite leer el destino. Por ejemplo, 0x910C9–0x910CE y 0x91136–0x91141 consultan 0x366A54, con un orden distinto de los dos índices. La dirección de la tabla adicional no basta para asignar una mezcla. El host clasifica los bits 0x04 y 0x08 como translúcidos de reserva. La mezcla original de estos casos queda sin verificar en una llamada efectiva. No hubo ninguna llamada a 0x90F90 en el tramo observado de Brown tras cargar. La prueba de Brown no permite afirmar que esa misión nunca ejecute la rutina.

El decodificador de host gw_sprite_90f90.h aplica el selector y el remapeo antes de convertir a RGBA. Mantiene alfa 255 para el remapeo opaco y usa 140/255 en los píxeles visibles de los flags 0x04/0x08. El futuro subpase translúcido debe usar GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA y desactivar la escritura de profundidad. El diagnóstico GW_ENTITY_ATLAS_PROBE=1 publica estos sprites desde IFCMain y prueba la subida RGBA8 al atlas en el hilo de presentación, con GL_NEAREST y un presupuesto de 32 KiB por lote. El atlas conserva las coordenadas de las entradas para el futuro pase de billboards. Actualmente el compositor sigue dibujando las entidades desde WScreen.

## Cobertura de entidades en WScreen

En la entrada de IFCMain::Draw (0x22F40) el diagnóstico limpia la máscara del host. Al volver de MapDisplay::Draw (0x22F58) comienza el pase de HUD. La máscara sigue observando escrituras después de ese punto. Cada byte marca la entrada del atlas, contando desde uno, para un blit 0x90F90 opaco con captura válida. Un escritor posterior sin una entrada de entidad borra la marca incluso cuando escribe el mismo índice de paleta. El x menor que 128 y el arte del HUD entre 128 y 175 quedan excluidos. El panel 0x24C60 se guarda y se compone por separado en la ruta existente, por lo que las escrituras temporales que esta ruta restaura se excluyen del observador de cobertura.

La máscara se recoge con GW_ENTITY_ATLAS_PROBE y se puede exportar con la captura pres_ del presentador. Identifica candidatos a reemplazar. La presentación todavía requiere comprobar que cada entrada se dibujó realmente en GPU antes de retirar su cobertura de WScreen. Los blits 0x904E0 y 0x99A20 y los efectos que leen el destino conservan sus píxeles en esta revisión.
