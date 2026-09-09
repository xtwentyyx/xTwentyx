# xTwentyx en Cloudflare Workers

Publica `twenty.lua` en `/main.lua` sin mostrarlo durante una navegación normal.

## Comportamiento

- `/` muestra únicamente una página sencilla con **Hola**.
- Una navegación normal a `/main.lua` redirige a `/`.
- Una solicitud válida con `X-Lua-Token` o `Authorization: Bearer` recibe el Lua como texto plano.
- Una solicitud desconocida o con un token incorrecto nunca recibe el Lua.
- La respuesta Lua incluye encabezados que prohíben su almacenamiento en cachés públicas.

## Cargar desde ejecutores compatibles

La mayoría de los ejecutores compatibles con el formato UNC permiten una función `request` y cabeceras. Adapta el nombre de la función si el ejecutor usa `http_request`, `syn.request` o `http.request`:

```lua
local response = request({
    Url = "https://TU-WORKER.workers.dev/main.lua",
    Method = "GET",
    Headers = {
        ["X-Lua-Token"] = "TU_TOKEN"
    }
})

assert(response.StatusCode == 200, "No autorizado")
loadstring(response.Body)()
```

El token permite descargar el script. Cualquier persona que lo obtenga podrá hacer la misma solicitud, por lo que debe tratarse como una contraseña.

## Ejecutores sin cabeceras

`game:HttpGet` no permite añadir `X-Lua-Token`. La única compatibilidad posible sin cabeceras es reconocer características imitables de la solicitud, como `User-Agent`.

El Worker incluye `HEURISTIC_UA_ALLOWLIST`, desactivado por defecto. Se pueden escribir fragmentos de agentes separados por comas en `wrangler.jsonc`, pero esto **solo es un disfraz visual y no es autenticación**: un navegador o programa puede copiar esas características. No debe activarse para código sensible.

## Cambiar el Lua

1. Sustituye el contenido de `twenty.lua`.
2. Ejecuta las pruebas.
3. Ejecuta `pnpm deploy`.

`examples/main.example.lua` está claramente marcado como ejemplo.

## Cambiar el token

Ejecuta `pnpm wrangler secret put LUA_ACCESS_TOKEN`, pega el nuevo valor solo cuando Wrangler lo solicite y vuelve a desplegar. Nunca añadas el token al repositorio.

## Comprobaciones

```bash
curl -i https://TU-WORKER.workers.dev/
curl -i -H "Accept: text/html" https://TU-WORKER.workers.dev/main.lua
curl -i -H "X-Lua-Token: TU_TOKEN" https://TU-WORKER.workers.dev/main.lua
curl -i -H "X-Lua-Token: incorrecto" https://TU-WORKER.workers.dev/main.lua
```

## Límite importante

El Worker controla quién descarga el archivo, pero no puede impedir que un cliente autorizado capture el Lua después de recibirlo. No se afirma que el código sea imposible de extraer.
