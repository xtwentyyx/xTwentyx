-- Firebase se incluye al preparar el script; la entrega no requiere editar la URL.
local XTEYX_DATABASE_URL = "https://xtwentyx-keys-default-rtdb.firebaseio.com"

local LicenseGate = (function()
    local G = {alive = true, connections = {}, currentCleanup = nil, root = nil}
    local Http = game:GetService("HttpService")
    local Tween = game:GetService("TweenService")
    local env = _G
    pcall(function() if type(getgenv)=="function" then local value=getgenv();if type(value)=="table" then env=value end end end)
    -- Rescata los originales antes de cerrar una version anterior: su limpieza
    -- podia descartar respaldos aunque la pieza siguiera agrandada o invisible.
    local inherited = env.XTEYX_HitboxStates
    local recovered, recoveryOwner = setmetatable({}, {__mode="k"}), {}
    local bodyProperties = {"Size", "Transparency", "Color", "Material", "CanCollide", "CanQuery", "Massless"}
    if type(inherited) == "table" then
        for part, state in pairs(inherited) do
            if type(state) == "table" and state.Size ~= nil then
                local copy = {Region=state.Region, CleanVersion=state.CleanVersion, Owner=recoveryOwner, Revision=0}
                for _, property in ipairs(bodyProperties) do copy[property] = state[property] end
                recovered[part] = copy
            end
        end
    end
    if type(env.XTEYX_KeyGate_Cleanup) == "function" then pcall(env.XTEYX_KeyGate_Cleanup) end
    if type(env.CDT_Optifine_Cleanup) == "function" then pcall(env.CDT_Optifine_Cleanup) end
    if type(inherited) == "table" then
        -- Invalida los reintentos de la sesion anterior y transfiere el respaldo.
        for part in pairs(inherited) do inherited[part] = nil end
        env.XTEYX_HitboxStates = recovered
        local function recoverPart(part, state, attempt)
            if env.XTEYX_HitboxStates ~= recovered or recovered[part] ~= state
                or state.Owner ~= recoveryOwner or state.Revision ~= 0 then return end
            local restored = true
            for _, property in ipairs(bodyProperties) do
                if state[property] ~= nil then
                    local ok = pcall(function()
                        if part[property] ~= state[property] then part[property] = state[property] end
                        if part[property] ~= state[property] then error("Restauracion pendiente") end
                    end)
                    if not ok then restored = false end
                end
            end
            if restored and attempt >= 2 then
                recovered[part] = nil
            elseif attempt < 3 then
                task.delay(0.1 * (attempt + 1), function() recoverPart(part, state, attempt + 1) end)
            end
        end
        for part, state in pairs(recovered) do recoverPart(part, state, 0) end
    end

    -- SHA-256 local. La base de datos guarda el hash, nunca la key completa.
    function G.hash(value)
        local bit = bit32
        assert(bit, "Este entorno necesita bit32 para verificar la key.")
        local band, bxor, bnot, rshift, rrotate = bit.band, bit.bxor, bit.bnot, bit.rshift, bit.rrotate
        local K = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}
        local H = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
        local len = #value
        value = value .. string.char(128) .. string.rep(string.char(0), (55 - len) % 64)
        local bits = len * 8
        local high, low = math.floor(bits / 4294967296), bits % 4294967296
        for shift = 24, 0, -8 do value = value .. string.char(band(rshift(high, shift), 255)) end
        for shift = 24, 0, -8 do value = value .. string.char(band(rshift(low, shift), 255)) end
        for block = 1, #value, 64 do
            local W = {}
            for i = 0, 15 do
                local a,b,c,d = string.byte(value, block+i*4, block+i*4+3)
                W[i] = a*16777216 + b*65536 + c*256 + d
            end
            for i = 16, 63 do
                local x,y = W[i-15],W[i-2]
                W[i] = (W[i-16] + bxor(rrotate(x,7),rrotate(x,18),rshift(x,3)) + W[i-7] + bxor(rrotate(y,17),rrotate(y,19),rshift(y,10))) % 4294967296
            end
            local a,b,c,d,e,f,g,h = H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]
            for i = 0,63 do
                local t1 = (h + bxor(rrotate(e,6),rrotate(e,11),rrotate(e,25)) + bxor(band(e,f),band(bnot(e),g)) + K[i+1] + W[i]) % 4294967296
                local t2 = (bxor(rrotate(a,2),rrotate(a,13),rrotate(a,22)) + bxor(band(a,b),band(a,c),band(b,c))) % 4294967296
                h,g,f,e,d,c,b,a = g,f,e,(d+t1)%4294967296,c,b,a,(t1+t2)%4294967296
            end
            local state = {a,b,c,d,e,f,g,h}
            for i = 1,8 do H[i] = (H[i] + state[i]) % 4294967296 end
        end
        local out = {}
        for i = 1,8 do out[i] = string.format("%08x",H[i]) end
        return table.concat(out)
    end

    function G.normalize(code)
        local value = tostring(code or ""):upper():gsub("[%s%-]", "")
        if #value ~= 35 or value:sub(1,3) ~= "XTW" or not value:sub(4):match("^[A-F0-9]+$") then return nil end
        return value
    end
    function G.validURL(url)
        return type(url) == "string" and (url:match("^https://[a-z0-9%-]+%.firebaseio%.com$") or url:match("^https://[a-z0-9%-]+%.[a-z0-9%-]+%.firebasedatabase%.app$")) ~= nil
    end
    function G.serverTime(headers)
        local date
        for name,value in pairs(headers or {}) do if tostring(name):lower() == "date" then date = tostring(value) end end
        if not date then return nil end
        local day,month,year,hour,minute,second = date:match("%a+, (%d+) (%a+) (%d+) (%d+):(%d+):(%d+) GMT")
        local months = {Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
        if not day or not months[month] then return nil end
        local ok,result = pcall(function() return DateTime.fromUniversalTime(tonumber(year),months[month],tonumber(day),tonumber(hour),tonumber(minute),tonumber(second)).UnixTimestampMillis end)
        return ok and result or nil
    end
    function G.request(url, timeout)
        local finished, response = false, nil
        local started = os.clock()
        task.spawn(function()
            local ok,value = pcall(function()
                local transport = (type(request)=="function" and request) or (type(http_request)=="function" and http_request) or (type(syn)=="table" and syn.request) or (type(http)=="table" and http.request)
                local args = {Url=url,Method="GET",Headers={["Cache-Control"]="no-cache, no-store",Accept="application/json"}}
                if type(transport)=="function" then return transport(args) end
                return Http:RequestAsync(args)
            end)
            if ok then response=value end
            finished=true
        end)
        while G.alive and not finished and os.clock()-started < (timeout or 10) do
            if G.currentProof then G.refreshStatus(G.currentProof) end
            task.wait(0.05)
        end
        if not G.alive or not finished then return nil end
        return response, os.clock()-started
    end
    function G.verify(code, timeout)
        local normalized = G.normalize(code)
        if not normalized then return nil, "Revisa la key. Debe empezar por XTW-." end
        if not G.validURL(XTEYX_DATABASE_URL) then return nil, "Falta conectar este script a tu proyecto." end
        local response,elapsed = G.request(XTEYX_DATABASE_URL.."/licenses/"..G.hash(normalized)..".json", timeout)
        if type(response) ~= "table" then return nil, "No se pudo verificar. Revisa Internet y vuelve a intentar." end
        local status = tonumber(response.StatusCode or response.Status)
        if status == 401 or status == 403 then return nil, "Key inexistente, vencida o bloqueada." end
        if status ~= 200 then return nil, "no respondio correctamente. Intenta otra vez." end
        local ok,data = pcall(function() return Http:JSONDecode(response.Body or "") end)
        if not ok or type(data) ~= "table" or data.revoked ~= false or type(data.durationMs) ~= "number" or type(data.startedAt) ~= "number" or data.startedAt ~= data.startedAt or data.startedAt < 0 or data.startedAt > 253086724799999 or data.durationMs < 0 or data.durationMs > 315576000000 or data.durationMs % 1 ~= 0 then return nil, "La respuesta de la key no es valida." end
        -- Firebase decide el acceso con sus reglas y su hora. Date solo permite
        -- cerrar antes del proximo sondeo; nunca se usa la hora del dispositivo.
        local remaining
        local serverNow = G.serverTime(response.Headers or response.headers)
        if data.durationMs > 0 and serverNow then
            remaining = (data.startedAt + data.durationMs - serverNow)/1000 - 1 - (elapsed or 0)
            if remaining <= 0 then return nil, "El tiempo de esta key termino." end
        end
        return {remaining=remaining, checkedAt=os.clock(), permanent=data.durationMs==0,
            expiresAt=data.durationMs>0 and data.startedAt+data.durationMs or nil, durationMs=data.durationMs}
    end

    function G.formatDuration(seconds, compact)
        local total=math.max(0,math.ceil(seconds))
        local days=math.floor(total/86400)
        local hours=math.floor(total/3600)%24
        local minutes=math.floor(total/60)%60
        local secs=total%60
        if compact then
            if days>0 then return string.format("%dd %02dh",days,hours) end
            if hours>0 then return string.format("%dh %02dm",hours,minutes) end
            return string.format("%dm %02ds",minutes,secs)
        end
        local clock=string.format("%02dh %02dm %02ds",hours,minutes,secs)
        return days>0 and tostring(days).."d "..clock or clock
    end
    function G.status(proof)
        if proof.permanent then return {title="Key permanente",detail="Sin vencimiento",short="Key permanente",urgent=false} end
        if not proof.deadlineText and proof.expiresAt then
            local ok,label=pcall(function()
                return DateTime.fromUnixTimestampMillis(proof.expiresAt):FormatLocalTime("DD/MM/YYYY · HH:mm", "es-es")
            end)
            if ok then proof.deadlineText="Vence: "..label.." · hora local" end
        end
        local remaining=proof.remaining and proof.remaining-math.max(0,os.clock()-proof.checkedAt) or nil
        local estimated=false
        if not remaining and proof.expiresAt then
            -- Solo para mostrar el contador si el ejecutor omite la cabecera Date.
            -- Esta estimacion nunca concede acceso ni modifica la verificacion.
            local ok,now=pcall(function() return DateTime.now().UnixTimestampMillis end)
            if ok then remaining=math.min(proof.durationMs/1000,(proof.expiresAt-now)/1000);estimated=true end
        end
        local prefix=estimated and "≈ " or ""
        return {title=remaining and "Key · "..prefix..G.formatDuration(remaining) or "Key activa",
            detail=proof.deadlineText or "Vencimiento no disponible en este entorno",
            short=remaining and "Key · "..prefix..G.formatDuration(remaining,true) or "Key activa",
            urgent=remaining~=nil and remaining<=3600}
    end
    function G.refreshStatus(proof, force)
        if not G.licenseDisplay or not G.currentCleanup then return end
        local owner=G.menuEnv or env
        if not G.alive or owner.CDT_Optifine_Cleanup~=G.currentCleanup then return end
        local now=os.clock()
        if not force and G.nextStatusAt and now<G.nextStatusAt then return end
        G.nextStatusAt=now+1
        local ok=pcall(G.licenseDisplay,G.status(proof))
        if not ok then G.licenseDisplay=nil end
    end
    function G.clearUI()
        for _,c in ipairs(G.connections) do pcall(function() c:Disconnect() end) end
        G.connections = {}
        if G.root then G.root:Destroy(); G.root=nil end
    end
    function G.stopMenu()
        local cleanup=G.currentCleanup
        local owner=G.menuEnv or env
        G.currentCleanup=nil
        G.menuEnv=nil
        G.licenseDisplay=nil
        G.currentProof=nil
        G.nextStatusAt=nil
        if cleanup and owner.CDT_Optifine_Cleanup==cleanup then pcall(cleanup) end
    end
    function G.cleanup()
        G.alive=false
        G.clearUI()
        G.stopMenu()
        if env.XTEYX_KeyGate_Cleanup == G.cleanup then env.XTEYX_KeyGate_Cleanup=nil end
    end
    env.XTEYX_KeyGate_Cleanup=G.cleanup
    function G.connect(signal,fn) local c=signal:Connect(fn);table.insert(G.connections,c);return c end
    function G.make(kind,props,parent)
        local object=Instance.new(kind)
        for name,value in pairs(props) do object[name]=value end
        object.Parent=parent
        return object
    end
    function G.prompt(reason)
        G.clearUI()
        local accepted,proof,busy=nil,nil,false
        local parent=game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui")
        pcall(function() parent=game:GetService("CoreGui") end)
        local root=G.make("ScreenGui",{Name="XTEYX_KeyAccess",ResetOnSpawn=false,IgnoreGuiInset=true,DisplayOrder=99999,ZIndexBehavior=Enum.ZIndexBehavior.Sibling},parent)
        G.root=root
        local card=G.make("CanvasGroup",{AnchorPoint=Vector2.new(0.5,0.5),Position=UDim2.fromScale(0.5,0.5),Size=UDim2.fromOffset(372,292),BackgroundColor3=Color3.fromRGB(16,19,29),GroupTransparency=1},root)
        G.make("UICorner",{CornerRadius=UDim.new(0,16)},card)
        G.make("UIStroke",{Color=Color3.fromRGB(65,70,92),Transparency=0.25,Thickness=1},card)
        local scale=G.make("UIScale",{Scale=0.94},card)
        local function resize()
            local camera=game:GetService("Workspace").CurrentCamera
            if camera then scale.Scale=math.min(1,(camera.ViewportSize.X-24)/372,(camera.ViewportSize.Y-24)/292) end
        end
        resize()
        local camera=game:GetService("Workspace").CurrentCamera
        if camera then G.connect(camera:GetPropertyChangedSignal("ViewportSize"),resize) end
        G.make("TextLabel",{BackgroundTransparency=1,Position=UDim2.fromOffset(24,24),Size=UDim2.fromOffset(272,27),Text="xTWENTYx",TextSize=24,Font=Enum.Font.BuilderSansBold,TextColor3=Color3.fromRGB(245,247,255),TextXAlignment=Enum.TextXAlignment.Left},card)
        G.make("TextLabel",{BackgroundTransparency=1,Position=UDim2.fromOffset(24,61),Size=UDim2.fromOffset(324,20),Text="Introduce tu key para abrir X.T.E.Y.X",TextSize=14,Font=Enum.Font.BuilderSansMedium,TextColor3=Color3.fromRGB(202,208,225),TextXAlignment=Enum.TextXAlignment.Left},card)
        local close=G.make("TextButton",{BackgroundTransparency=1,Position=UDim2.fromOffset(320,18),Size=UDim2.fromOffset(36,36),Text="×",TextSize=27,Font=Enum.Font.BuilderSansMedium,TextColor3=Color3.fromRGB(218,224,240)},card)
        local input=G.make("TextBox",{Position=UDim2.fromOffset(24,98),Size=UDim2.fromOffset(324,48),BackgroundColor3=Color3.fromRGB(28,32,47),Text="",PlaceholderText="XTW-…",PlaceholderColor3=Color3.fromRGB(162,172,199),TextColor3=Color3.fromRGB(248,249,255),TextSize=14,Font=Enum.Font.Code,ClearTextOnFocus=false,TextXAlignment=Enum.TextXAlignment.Left},card)
        G.make("UICorner",{CornerRadius=UDim.new(0,9)},input)
        G.make("UIPadding",{PaddingLeft=UDim.new(0,12),PaddingRight=UDim.new(0,12)},input)
        local message=G.make("TextLabel",{BackgroundTransparency=1,Position=UDim2.fromOffset(24,152),Size=UDim2.fromOffset(324,43),Text=reason or "El tiempo cuenta desde que el administrador crea la key.",TextWrapped=true,TextSize=13,Font=Enum.Font.BuilderSansMedium,TextColor3=Color3.fromRGB(202,208,225),TextXAlignment=Enum.TextXAlignment.Left},card)
        local enter=G.make("TextButton",{Position=UDim2.fromOffset(24,209),Size=UDim2.fromOffset(324,44),BackgroundColor3=Color3.fromRGB(107,119,238),Text="Verificar y abrir",TextColor3=Color3.fromRGB(255,255,255),TextSize=15,Font=Enum.Font.BuilderSansBold,AutoButtonColor=true},card)
        G.make("UICorner",{CornerRadius=UDim.new(0,9)},enter)
        local function submit()
            if busy or not G.alive then return end
            busy=true;input.TextEditable=false;enter.Text="Verificando…";message.Text="Comprobando el acceso…"
            local raw=input.Text
            task.spawn(function()
                local ok,result,why=pcall(G.verify,raw)
                if not G.alive or G.root~=root then return end
                if ok and result then accepted=G.normalize(raw);proof=result;return end
                message.Text=ok and why or "Este entorno no pudo verificar la key. Revisa la conexion y bit32."
                message.TextColor3=Color3.fromRGB(255,172,179)
                enter.Text="Volver a intentar";input.TextEditable=true;busy=false
            end)
        end
        G.connect(enter.Activated,submit)
        G.connect(input.FocusLost,function(pressedEnter) if pressedEnter then submit() end end)
        G.connect(close.Activated,G.cleanup)
        Tween:Create(card,TweenInfo.new(0.25,Enum.EasingStyle.Quint,Enum.EasingDirection.Out),{GroupTransparency=0}):Play()
        while G.alive and not accepted do task.wait(0.1) end
        G.clearUI()
        return accepted,proof
    end
    function G.monitor(code,proof)
        local owner=G.menuEnv or env
        while G.alive and G.currentCleanup and owner.CDT_Optifine_Cleanup==G.currentCleanup do
            G.currentProof=proof
            G.refreshStatus(proof,true)
            local age=os.clock()-proof.checkedAt
            local remaining=proof.remaining and proof.remaining-age or nil
            if remaining and remaining <= 0 then return "El tiempo de esta key termino." end
            local pause=math.min(40,remaining and math.max(0,remaining-10) or 40)
            local start=os.clock()
            while G.alive and os.clock()-start < pause do
                if owner.CDT_Optifine_Cleanup~=G.currentCleanup then return nil end
                G.refreshStatus(proof)
                task.wait(math.min(0.25,pause-(os.clock()-start)))
            end
            if not G.alive or owner.CDT_Optifine_Cleanup~=G.currentCleanup then return nil end
            remaining=proof.remaining and proof.remaining-(os.clock()-proof.checkedAt) or nil
            -- Las keys a punto de vencer se consultan como minimo una vez por
            -- segundo. Ninguna respuesta tardia reabre una sesion cancelada.
            if pause==0 then task.wait(math.min(1,math.max(0,remaining or 1))) end
            local timeout=math.min(10,remaining or 10)
            if timeout<=0 then return "El tiempo de esta key termino." end
            local result,why=G.verify(code,timeout)
            if not result then return why end
            proof=result
        end
        return nil
    end
    function G.run(startMenu)
        task.spawn(function()
            local reason
            while G.alive do
                local code,proof=G.prompt(reason)
                if not code or not G.alive then break end
                local ok,cleanup,menuEnv,display=pcall(startMenu)
                if not ok then
                    if type(env.CDT_Optifine_Cleanup)=="function" then pcall(env.CDT_Optifine_Cleanup) end
                    reason="El menu no pudo iniciarse en este entorno. Vuelve a intentarlo."
                    warn("X.T.E.Y.X: "..tostring(cleanup))
                else
                    G.currentCleanup=cleanup
                    G.menuEnv=menuEnv or env
                    G.licenseDisplay=type(display)=="function" and display or nil
                    local monitored,why=pcall(G.monitor,code,proof)
                    G.stopMenu()
                    reason=monitored and why or "No se pudo mantener la verificacion. Vuelve a intentar."
                    if not reason then break end
                end
            end
            G.cleanup()
        end)
    end
    return G
end)()

-- MENU_START se sustituye durante la preparacion del archivo completo.

local function startAuthorizedMenu()
--[[
    X.T.E.Y.X / ANIMATED SIDEBAR
    Adaptacion nativa del estilo Dashboard Sidebar de Arun Dass (21st.dev).
    Referencia de diseno: https://21st.dev/community/components?q=mod+menu&preview=%2F%40arunjdass%2Fcomponents%2Fdashboard-sidebar
    Panel de 400 x 454; barra lateral abierta al iniciar y un solo boton para plegarla.
    Boton hamburguesa/X inspirado en Open Close Menu Button de Origin UI.
    Minimizado reversible de 0.32 s, texto ampliado y contraste reforzado.
    Intro xTWENTYx de 2.6 s con letras animadas y acceso directo al menu.
    Transparencia compartida por ambos paneles y tipografia Builder Sans.
    Indicador integrado de tiempo restante y vencimiento para la version con key.
    Rueda de proximidad, colores personalizables y restauracion de hitboxes por pieza.
    Hitbox v3: recuperacion de cuerpos antiguos y respaldos persistentes por pieza.
    ESP optimizado: proyeccion compartida, cuerpos en cache y dibujos reutilizados.
    Conserva las funciones de juego, el acceso flotante y la configuracion.
    CDT_Optifine_Config.json conserva la compatibilidad con tus ajustes.
]]

local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")
local UserInputService = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")
local RunService = game:GetService("RunService")
local Workspace = game:GetService("Workspace")

local LocalPlayer = Players.LocalPlayer

-- Superficies neutras, texto legible y un unico acento azul.
local THEME = {
    Background = Color3.fromRGB(18, 18, 21),
    Header = Color3.fromRGB(23, 23, 27),
    Panel = Color3.fromRGB(28, 28, 33),
    PanelAlt = Color3.fromRGB(39, 39, 46),
    Hover = Color3.fromRGB(48, 48, 57),
    Input = Color3.fromRGB(21, 21, 25),
    Border = Color3.fromRGB(64, 64, 74),
    BorderSoft = Color3.fromRGB(43, 43, 51),
    Accent = Color3.fromRGB(71, 112, 210),
    AccentHover = Color3.fromRGB(85, 128, 231),
    AccentText = Color3.fromRGB(175, 195, 255),
    White = Color3.fromRGB(252, 253, 255),
    Text = Color3.fromRGB(238, 241, 248),
    Muted = Color3.fromRGB(207, 213, 225),
    Dim = Color3.fromRGB(185, 194, 210),
    Black = Color3.fromRGB(10, 13, 18),
}

local Compact = {UI = {}, Surfaces = setmetatable({}, {__mode = "k"}), Transparency = 0.2}
local mainConnections = {}
local playerCardConnections = {}
local suggestionConnections = {}
local destroyed = false

local function connect(signal, callback)
    local connection = signal:Connect(callback)
    table.insert(mainConnections, connection)
    return connection
end

local function connectPooled(pool, signal, callback)
    local connection = signal:Connect(callback)
    table.insert(pool, connection)
    return connection
end

local function disconnectPool(pool)
    for index = #pool, 1, -1 do
        local connection = pool[index]
        if connection and connection.Connected then
            connection:Disconnect()
        end
        table.remove(pool, index)
    end
end

local function create(className, properties, parent)
    local object = Instance.new(className)
    for property, value in pairs(properties or {}) do
        object[property] = value
    end
    if object:IsA("TextLabel") or object:IsA("TextButton") or object:IsA("TextBox") then
        if not object.TextWrapped and (not properties or properties.TextTruncate == nil) then
            object.TextTruncate = Enum.TextTruncate.AtEnd
        end
    end
    object.Parent = parent
    if object:IsA("TextLabel") or object:IsA("TextButton") or object:IsA("TextBox") then
        if not properties or properties.Font == nil then object.Font = Enum.Font.BuilderSansMedium end
        object.TextTransparency = 0
        object.TextStrokeColor3 = THEME.Black
        object.TextStrokeTransparency = 0.72
        object.LineHeight = 1.08
    end
    if object:IsA("TextBox") then
        connect(object.Focused, function()
            local outline = object:FindFirstChildOfClass("UIStroke")
                or (object.Parent and object.Parent:FindFirstChildOfClass("UIStroke"))
            if outline then
                object:SetAttribute("RestingBorder", outline.Color)
                outline.Color = THEME.AccentHover
            end
        end)
        connect(object.FocusLost, function()
            local outline = object:FindFirstChildOfClass("UIStroke")
                or (object.Parent and object.Parent:FindFirstChildOfClass("UIStroke"))
            local resting = object:GetAttribute("RestingBorder")
            if outline and resting then outline.Color = resting end
        end)
    end
    if Compact.registerSurface then Compact.registerSurface(object) end
    return object
end

local function corner(object, radius)
    return create("UICorner", {
        CornerRadius = UDim.new(0, (radius and radius <= 4) and 6 or (radius or 6)),
    }, object)
end

local function stroke(object, color, transparency, thickness)
    return create("UIStroke", {
        Color = color or THEME.Border,
        Transparency = transparency or 0,
        Thickness = thickness or 1,
    }, object)
end

local function padding(object, left, right, top, bottom)
    return create("UIPadding", {
        PaddingLeft = UDim.new(0, left or 0),
        PaddingRight = UDim.new(0, right or 0),
        PaddingTop = UDim.new(0, top or 0),
        PaddingBottom = UDim.new(0, bottom or 0),
    }, object)
end

local function tween(object, duration, properties, style, direction)
    local animation = TweenService:Create(
        object,
        TweenInfo.new(
            duration or 0.18,
            style or Enum.EasingStyle.Quint,
            direction or Enum.EasingDirection.Out
        ),
        properties
    )
    animation:Play()
    return animation
end

local runtimeEnvironment = _G
pcall(function()
    if type(getgenv) == "function" then
        local shared = getgenv()
        if type(shared) == "table" then runtimeEnvironment = shared end
    end
end)

if runtimeEnvironment.CDT_Optifine_Cleanup then
    pcall(runtimeEnvironment.CDT_Optifine_Cleanup)
end

runtimeEnvironment.CDT_Optifine_Config = runtimeEnvironment.CDT_Optifine_Config or {}
local runtimeConfig = runtimeEnvironment.CDT_Optifine_Config

-- Autoguardado persistente. Si el ejecutor no permite archivos, getgenv()
-- conserva la configuracion mientras dure la sesion.
local AutoSave = {
    ConfigFile = "CDT_Optifine_Config.json",
    PersistentSaveAvailable = type(writefile) == "function",
    PersistentLoadAvailable = type(readfile) == "function",
    RequestId = 0,
    LastSavedConfig = nil,
    HttpService = game:GetService("HttpService"),
    UI = {},
}

AutoSave.encodeStoredValue = function(value)
    if typeof(value) == "EnumItem" then
        local enumType, enumName = string.match(
            tostring(value),
            "^Enum%.([^.]+)%.(.+)$"
        )
        return {
            __cdtEnumType = enumType,
            __cdtEnumName = enumName,
        }
    end

    if type(value) == "table" then
        local encoded = {}
        for key, childValue in pairs(value) do
            local childType = type(childValue)
            if childType == "boolean"
                or childType == "number"
                or childType == "string"
                or childType == "table"
                or typeof(childValue) == "EnumItem" then
                encoded[tostring(key)] = AutoSave.encodeStoredValue(childValue)
            end
        end
        return encoded
    end

    return value
end

AutoSave.decodeStoredValue = function(value)
    if type(value) ~= "table" then
        return value
    end

    if type(value.__cdtEnumType) == "string"
        and type(value.__cdtEnumName) == "string" then
        local success, enumItem = pcall(function()
            return Enum[value.__cdtEnumType][value.__cdtEnumName]
        end)
        return success and enumItem or nil
    end

    local decoded = {}
    for key, childValue in pairs(value) do
        decoded[key] = AutoSave.decodeStoredValue(childValue)
    end
    return decoded
end

AutoSave.loadSavedConfig = function()
    if not AutoSave.PersistentLoadAvailable then
        return false
    end

    local success, storedText = pcall(readfile, AutoSave.ConfigFile)
    if not success or type(storedText) ~= "string" or storedText == "" then
        return false
    end

    local decodedSuccess, decodedConfig = pcall(function()
        return AutoSave.HttpService:JSONDecode(storedText)
    end)
    if not decodedSuccess or type(decodedConfig) ~= "table" then
        return false
    end

    decodedConfig = AutoSave.decodeStoredValue(decodedConfig)
    for key, value in pairs(decodedConfig) do
        runtimeConfig[key] = value
    end
    AutoSave.LastSavedConfig = storedText
    return true
end

AutoSave.Loaded = AutoSave.loadSavedConfig()

AutoSave.saveConfigNow = function()
    runtimeConfig.AutosaveVersion = 1
    if not AutoSave.PersistentSaveAvailable then
        return false
    end

    local encodeSuccess, encodedConfig = pcall(function()
        return AutoSave.HttpService:JSONEncode(
            AutoSave.encodeStoredValue(runtimeConfig)
        )
    end)
    if not encodeSuccess or type(encodedConfig) ~= "string" then
        return false
    end

    if encodedConfig == AutoSave.LastSavedConfig then
        return true
    end

    local writeSuccess = pcall(writefile, AutoSave.ConfigFile, encodedConfig)
    if writeSuccess then
        AutoSave.LastSavedConfig = encodedConfig
    end
    return writeSuccess
end

AutoSave.queueConfigSave = function()
    if destroyed then return end
    AutoSave.RequestId = AutoSave.RequestId + 1
    local requestId = AutoSave.RequestId
    task.delay(0.3, function()
        if not destroyed and requestId == AutoSave.RequestId then
            AutoSave.saveConfigNow()
        end
    end)
end

local guiParent = CoreGui
pcall(function()
    if gethui then
        guiParent = gethui()
    end
end)

local oldGui = guiParent:FindFirstChild("XTEYX_Animated")
    or guiParent:FindFirstChild("XTEYX_Dashboard")
    or guiParent:FindFirstChild("XTEYX_Compact")
    or guiParent:FindFirstChild("CDT_Optifine_TP_Remastered")
if oldGui then
    oldGui:Destroy()
end

local ScreenGui = create("ScreenGui", {
    Name = "XTEYX_Animated",
    IgnoreGuiInset = false,
    ResetOnSpawn = false,
    DisplayOrder = 999,
    ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
}, guiParent)

local Main = create("CanvasGroup", {
    Name = "Main",
    Visible = false,
    AnchorPoint = Vector2.new(1, 0),
    Position = UDim2.new(1, -20, 0, 70),
    Size = UDim2.fromOffset(400, 454),
    BackgroundColor3 = THEME.Background,
    BorderSizePixel = 0,
    ClipsDescendants = true,
    GroupTransparency = 0,
}, ScreenGui)
corner(Main, 10)
stroke(Main, THEME.Border, 0, 1)

local MainScale = create("UIScale", {
    Scale = 1,
}, Main)

local Header = create("Frame", {
    Name = "Header",
    Size = UDim2.new(1, 0, 0, 44),
    BackgroundColor3 = THEME.Header,
    BorderSizePixel = 0,
    Active = true,
}, Main)
corner(Header, 10)

create("Frame", {
    Position = UDim2.new(0, 0, 1, -1),
    Size = UDim2.new(1, 0, 0, 1),
    BackgroundColor3 = THEME.BorderSoft,
    BorderSizePixel = 0,
}, Header)

local Brand = create("Frame", {
    Position = UDim2.fromOffset(12, 8),
    Size = UDim2.fromOffset(28, 28),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
}, Header)
corner(Brand, 4)

create("TextLabel", {
    Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1,
    Text = "X",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansExtraBold,
    TextSize = 18,
}, Brand)
Brand.Visible = false

Compact.UI.Breadcrumb = create("TextLabel", {
    Position = UDim2.fromOffset(50, 10),
    Size = UDim2.fromOffset(224, 22),
    BackgroundTransparency = 1,
    Text = "X.T.E.Y.X / Luz y zoom",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 13,
    TextXAlignment = Enum.TextXAlignment.Left,
}, Header)

create("TextLabel", {
    Position = UDim2.fromOffset(62, 29),
    Size = UDim2.fromOffset(160, 17),
    BackgroundTransparency = 1,
    Text = "",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, Header)

local VisionSystem = {UI = {}, TabOpen = true}
local CameraSystem = {UI = {}, TabOpen = false}
if guiParent:FindFirstChild("CDT_Optifine_CameraOverlay") then
    guiParent.CDT_Optifine_CameraOverlay:Destroy()
end
CameraSystem.UI.OverlayGui = create("ScreenGui", {
    Name = "CDT_Optifine_CameraOverlay",
    IgnoreGuiInset = true,
    ResetOnSpawn = false,
    DisplayOrder = 1000,
    ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
}, guiParent)

-- Barra lateral inspirada en la referencia, dibujada con controles nativos.
-- No requiere React, descargas de iconos ni recursos externos.
Compact.makeIcon = function(parent, name, x, y, size, color)
    local icon = create("Frame", {
        Name = "Icon_" .. name, Position = UDim2.fromOffset(x, y),
        Size = UDim2.fromOffset(size, size), BackgroundTransparency = 1,
        BorderSizePixel = 0, ZIndex = parent.ZIndex + 1,
    }, parent)
    local function line(x1, y1, x2, y2)
        local dx, dy = x2 - x1, y2 - y1
        local object = create("Frame", {
            AnchorPoint = Vector2.new(0.5, 0.5),
            Position = UDim2.fromScale((x1 + x2) / 48, (y1 + y2) / 48),
            Size = UDim2.fromOffset(math.sqrt(dx * dx + dy * dy) * size / 24, 1.4),
            Rotation = math.deg(math.atan2(dy, dx)), BackgroundColor3 = color,
            BorderSizePixel = 0, ZIndex = icon.ZIndex,
        }, icon)
        corner(object, 1)
    end
    local function ring(cx, cy, diameter)
        local object = create("Frame", {
            AnchorPoint = Vector2.new(0.5, 0.5), Position = UDim2.fromScale(cx / 24, cy / 24),
            Size = UDim2.fromScale(diameter / 24, diameter / 24), BackgroundTransparency = 1,
            BorderSizePixel = 0, ZIndex = icon.ZIndex,
        }, icon)
        corner(object, 999)
        stroke(object, color, 0, 1.4)
    end
    if name == "vision" then
        ring(12, 12, 8)
        for angle = 0, 7 do
            local radians = angle * math.pi / 4
            line(12 + math.cos(radians) * 8, 12 + math.sin(radians) * 8,
                12 + math.cos(radians) * 10.5, 12 + math.sin(radians) * 10.5)
        end
    elseif name == "esp" then
        ring(12, 12, 7)
        line(2, 12, 7, 6); line(7, 6, 17, 6); line(17, 6, 22, 12)
        line(22, 12, 17, 18); line(17, 18, 7, 18); line(7, 18, 2, 12)
    elseif name == "camera" then
        ring(12, 12, 13)
        line(12, 1, 12, 6); line(12, 18, 12, 23)
        line(1, 12, 6, 12); line(18, 12, 23, 12)
    elseif name == "players" then
        ring(9, 7, 6); ring(18, 9, 4)
        line(3, 21, 3, 17); line(3, 17, 6, 14); line(6, 14, 12, 14)
        line(12, 14, 15, 17); line(15, 17, 15, 21)
        line(18, 15, 21, 17); line(21, 17, 21, 21)
    elseif name == "hitbox" then
        line(4, 7, 12, 3); line(12, 3, 20, 7); line(20, 7, 12, 11); line(12, 11, 4, 7)
        line(4, 7, 4, 17); line(4, 17, 12, 21); line(12, 21, 20, 17)
        line(20, 17, 20, 7); line(12, 11, 12, 21)
    elseif name == "terminal" then
        line(4, 5, 10, 11); line(10, 11, 4, 17); line(13, 18, 21, 18)
    elseif name == "settings" then
        for _, spec in ipairs({{5, 8}, {12, 16}, {19, 7}}) do
            line(spec[1], 2, spec[1], spec[2] - 3)
            line(spec[1], spec[2] + 3, spec[1], 22)
            ring(spec[1], spec[2], 5)
        end
    elseif name == "search" then
        ring(10, 10, 13); line(15, 15, 22, 22)
    elseif name == "collapse" then
        line(3, 3, 21, 3); line(21, 3, 21, 21); line(21, 21, 3, 21); line(3, 21, 3, 3)
        line(9, 3, 9, 21); line(16, 8, 12, 12); line(12, 12, 16, 16)
    else
        line(3, 3, 21, 3); line(21, 3, 21, 21); line(21, 21, 3, 21); line(3, 21, 3, 3)
        line(9, 3, 9, 21); line(14, 8, 18, 12); line(18, 12, 14, 16)
    end
    return icon
end
Compact.tintIcon = function(icon, color)
    for _, object in ipairs(icon:GetDescendants()) do
        if object:IsA("UIStroke") then object.Color = color
        elseif object:IsA("Frame") and object.BackgroundTransparency < 1 then object.BackgroundColor3 = color end
    end
end
Compact.NavExpanded = false
Compact.UI.SectionButton = create("TextButton", {
    Name = "ToggleSidebar", Position = UDim2.fromOffset(10, 8), Size = UDim2.fromOffset(30, 28),
    BackgroundColor3 = THEME.PanelAlt, BackgroundTransparency = 1,
    BorderSizePixel = 0, Text = "", AutoButtonColor = false, ZIndex = 40,
}, Header)
corner(Compact.UI.SectionButton, 6)
Compact.UI.ToggleOpenIcon = Compact.makeIcon(Compact.UI.SectionButton, "expand", 6, 5, 18, THEME.Muted)
Compact.UI.ToggleCloseIcon = Compact.makeIcon(Compact.UI.SectionButton, "collapse", 6, 5, 18, THEME.Muted)
Compact.UI.ToggleCloseIcon.Visible = false
Compact.UI.Navigation = create("Frame", {
    Name = "DashboardSidebar", Position = UDim2.fromOffset(0, 0),
    Size = UDim2.new(0, 0, 1, 0), BackgroundColor3 = THEME.Header,
    BorderSizePixel = 0, ClipsDescendants = true, ZIndex = 60,
}, Main)
corner(Compact.UI.Navigation, 10)
create("Frame", {
    Position = UDim2.new(1, -1, 0, 0), Size = UDim2.new(0, 1, 1, 0),
    BackgroundColor3 = THEME.BorderSoft, BorderSizePixel = 0, ZIndex = 61,
}, Compact.UI.Navigation)
Compact.UI.NavBrand = create("TextLabel", {
    Position = UDim2.fromOffset(12, 12), Size = UDim2.fromOffset(30, 30),
    BackgroundColor3 = THEME.PanelAlt, BorderSizePixel = 0, Text = "X",
    TextColor3 = THEME.White, Font = Enum.Font.BuilderSansBold, TextSize = 16,
    ZIndex = 62,
}, Compact.UI.Navigation)
corner(Compact.UI.NavBrand, 6)
create("TextLabel", {
    Position = UDim2.fromOffset(52, 10), Size = UDim2.fromOffset(116, 20),
    BackgroundTransparency = 1, Text = "X.T.E.Y.X", TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold, TextSize = 15, TextXAlignment = Enum.TextXAlignment.Left,
    ZIndex = 62,
}, Compact.UI.Navigation)
Compact.UI.NavSubtitle = create("TextLabel", {
    Position = UDim2.fromOffset(52, 30), Size = UDim2.fromOffset(116, 16),
    BackgroundTransparency = 1, Text = "Panel de juego", TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSans, TextSize = 12, TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 62,
}, Compact.UI.Navigation)
Compact.UI.NavSearchFrame = create("Frame", {
    Position = UDim2.fromOffset(12, 62), Size = UDim2.fromOffset(192, 32),
    BackgroundColor3 = THEME.Input, BorderSizePixel = 0, ZIndex = 62,
}, Compact.UI.Navigation)
corner(Compact.UI.NavSearchFrame, 6)
stroke(Compact.UI.NavSearchFrame, THEME.BorderSoft, 0, 1)
Compact.makeIcon(Compact.UI.NavSearchFrame, "search", 10, 8, 16, THEME.Muted)
Compact.UI.NavSearch = create("TextBox", {
    Position = UDim2.fromOffset(34, 0), Size = UDim2.fromOffset(150, 32),
    BackgroundTransparency = 1, Text = "", PlaceholderText = "Buscar una opcion...",
    PlaceholderColor3 = THEME.Dim, TextColor3 = THEME.Text, Font = Enum.Font.BuilderSans,
    TextSize = 13, TextXAlignment = Enum.TextXAlignment.Left, ClearTextOnFocus = false, ZIndex = 63,
}, Compact.UI.NavSearchFrame)
AutoSave.WindowTabs = create("ScrollingFrame", {
    Name = "Navigation", Position = UDim2.fromOffset(8, 108),
    Size = UDim2.new(1, -16, 1, -168), BackgroundTransparency = 1,
    BorderSizePixel = 0, CanvasSize = UDim2.fromOffset(0, 266),
    CanvasPosition = Vector2.new(0, 0), ScrollBarThickness = 2,
    ScrollBarImageColor3 = THEME.Border, ScrollingDirection = Enum.ScrollingDirection.Y,
    ScrollingEnabled = true, Active = true, ClipsDescendants = true, ZIndex = 61,
}, Compact.UI.Navigation)
Compact.UI.VisualGroup = create("TextLabel", {
    Position = UDim2.fromOffset(10, 0), Size = UDim2.fromOffset(172, 18),
    BackgroundTransparency = 1, Text = "VISUAL", TextColor3 = THEME.Dim,
    Font = Enum.Font.BuilderSansMedium, TextSize = 12, TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 62,
}, AutoSave.WindowTabs)
Compact.UI.ActionGroup = create("TextLabel", {
    Position = UDim2.fromOffset(10, 136), Size = UDim2.fromOffset(172, 18),
    BackgroundTransparency = 1, Text = "HERRAMIENTAS", TextColor3 = THEME.Dim,
    Font = Enum.Font.BuilderSansMedium, TextSize = 12, TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 62,
}, AutoSave.WindowTabs)
Compact.UI.EmptySearch = create("TextLabel", {
    Position = UDim2.fromOffset(10, 8), Size = UDim2.fromOffset(180, 48),
    BackgroundTransparency = 1, Text = "No hay coincidencias.\nPrueba otro nombre.",
    TextColor3 = THEME.Muted, Font = Enum.Font.BuilderSans, TextSize = 13,
    TextWrapped = true, Visible = false, ZIndex = 62,
}, AutoSave.WindowTabs)
Compact.UI.NavFooter = create("Frame", {
    Position = UDim2.new(0, 8, 1, -52), Size = UDim2.new(1, -16, 0, 44),
    BackgroundTransparency = 1, BorderSizePixel = 0, ZIndex = 61,
}, Compact.UI.Navigation)
create("Frame", {
    Size = UDim2.new(1, 0, 0, 1), BackgroundColor3 = THEME.BorderSoft, BorderSizePixel = 0, ZIndex = 62,
}, Compact.UI.NavFooter)
Compact.setNavigationOpen = function(open) Compact.NavExpanded = open end
connect(Compact.UI.SectionButton.Activated, function()
    Compact.setNavigationOpen(not Compact.NavExpanded)
end)


local function makeTopTab(text, positionX, width)
    local button = create("TextButton", {
        Position = UDim2.fromOffset(positionX, 0),
        Size = UDim2.fromOffset(width, 55),
        BackgroundTransparency = 1,
        BorderSizePixel = 0,
        Text = text,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        AutoButtonColor = false,
    }, AutoSave.WindowTabs)
    button.TextXAlignment = Enum.TextXAlignment.Left
    padding(button, 14, 10, 0, 0)
    corner(button, 6)
    return button
end

local TerminalTab = makeTopTab("Consola", 0, 106)
local SettingsTab = makeTopTab("Ajustes", 106, 96)
local PlayersTab = makeTopTab("Jugadores", 202, 88)
PlayersTab.Visible = false
PlayersTab.TextXAlignment = Enum.TextXAlignment.Left

local CloseTPTabButton = create("TextButton", {
    Position = UDim2.fromOffset(264, 18),
    Size = UDim2.fromOffset(20, 20),
    BackgroundColor3 = THEME.Panel,
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Text = "X",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
    Visible = false,
    ZIndex = 4,
}, AutoSave.WindowTabs)
corner(CloseTPTabButton, 3)

local HitboxTab = makeTopTab("HITBOX", 290, 88)
HitboxTab.Visible = false
HitboxTab.TextXAlignment = Enum.TextXAlignment.Left

local CloseHitboxTabButton = create("TextButton", {
    Position = UDim2.fromOffset(352, 18),
    Size = UDim2.fromOffset(20, 20),
    BackgroundColor3 = THEME.Panel,
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Text = "X",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
    Visible = false,
    ZIndex = 4,
}, AutoSave.WindowTabs)
corner(CloseHitboxTabButton, 3)

local EspTab = makeTopTab("ESP", 290, 88)
EspTab.Visible = false
EspTab.TextXAlignment = Enum.TextXAlignment.Left

local CloseEspTabButton = create("TextButton", {
    Position = UDim2.fromOffset(352, 18),
    Size = UDim2.fromOffset(20, 20),
    BackgroundColor3 = THEME.Panel,
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Text = "X",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
    Visible = false,
    ZIndex = 4,
}, AutoSave.WindowTabs)
corner(CloseEspTabButton, 3)

CameraSystem.UI.Tab = makeTopTab("CAM", 290, 88)
CameraSystem.UI.Tab.Visible = false
CameraSystem.UI.Tab.TextXAlignment = Enum.TextXAlignment.Left

CameraSystem.UI.Close = create("TextButton", {
    Position = UDim2.fromOffset(352, 18),
    Size = UDim2.fromOffset(20, 20),
    BackgroundColor3 = THEME.Panel,
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Text = "X",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
    Visible = false,
    ZIndex = 4,
}, AutoSave.WindowTabs)
corner(CameraSystem.UI.Close, 3)

VisionSystem.UI.Tab = makeTopTab("Luz y zoom", 202, 88)
VisionSystem.UI.Tab.TextXAlignment = Enum.TextXAlignment.Left
VisionSystem.UI.Close = create("TextButton", {
    Position = UDim2.fromOffset(264, 18), Size = UDim2.fromOffset(20, 20),
    BackgroundColor3 = THEME.Panel, BackgroundTransparency = 1, BorderSizePixel = 0,
    Text = "X", TextColor3 = THEME.Muted, Font = Enum.Font.BuilderSansBold, TextSize = 12,
    AutoButtonColor = false, ZIndex = 4,
}, AutoSave.WindowTabs)
corner(VisionSystem.UI.Close, 3)

local TabIndicator = create("Frame", {
    Position = UDim2.fromOffset(0, 10),
    Size = UDim2.fromOffset(3, 20),
    BackgroundColor3 = THEME.Accent,
    BorderSizePixel = 0,
}, AutoSave.WindowTabs)
corner(TabIndicator, 2)
TabIndicator.ZIndex = 5

local HeaderKey = create("TextLabel", {
    Position = UDim2.new(1, -112, 0, 9),
    Size = UDim2.fromOffset(60, 26),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
    Text = "INSERT",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
}, Header)
corner(HeaderKey, 4)
stroke(HeaderKey, THEME.BorderSoft, 0, 1)

local MinimizeButton = create("TextButton", {
    Position = UDim2.new(1, -44, 0, 4),
    Size = UDim2.fromOffset(36, 36),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 16,
    AutoButtonColor = false,
}, Header)
corner(MinimizeButton, 8)
stroke(MinimizeButton, THEME.Border, 0.1, 1)

local Body = create("Frame", {
    Name = "Body",
    Position = UDim2.fromOffset(0, 52),
    Size = UDim2.new(1, 0, 1, -60),
    BackgroundTransparency = 1,
    ClipsDescendants = true,
}, Main)

local TerminalPage = create("ScrollingFrame", {
    Name = "TerminalPage",
    Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1,
}, Body)

local PlayersPage = create("ScrollingFrame", {
    Name = "PlayersPage",
    Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1,
    Visible = false,
}, Body)

local SettingsPage = create("ScrollingFrame", {
    Name = "SettingsPage",
    Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1,
    Visible = false,
}, Body)

local HitboxPage = create("ScrollingFrame", {
    Name = "HitboxPage",
    Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1,
    Visible = false,
}, Body)

local EspPage = create("ScrollingFrame", {
    Name = "EspPage",
    Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1,
    Visible = false,
}, Body)

CameraSystem.UI.Page = create("ScrollingFrame", {
    Name = "CameraPage",
    Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1,
    Visible = false,
}, Body)

local function pageTitle(parent, title, subtitle)
    create("TextLabel", {
        Name = "SectionDescription", Position = UDim2.fromOffset(12, 0),
        Size = UDim2.new(1, -24, 0, 30), BackgroundTransparency = 1,
        Text = subtitle, TextColor3 = THEME.Muted, Font = Enum.Font.BuilderSans,
        TextSize = 13, TextWrapped = true, TextXAlignment = Enum.TextXAlignment.Left,
    }, parent)
end

pageTitle(TerminalPage, "Consola", "Ejecuta comandos y revisa la actividad del menu.")
pageTitle(PlayersPage, "Jugadores", "Busca un jugador para teletransportarte o asignarle una tecla.")
pageTitle(SettingsPage, "Ajustes", "Personaliza el tamano del menu y tus atajos.")
pageTitle(HitboxPage, "Hitbox por zonas", "Ajusta el tamano y la visibilidad de cada zona del personaje.")
pageTitle(EspPage, "Indicadores de jugadores", "Lineas, cajas, esqueleto y rueda de proximidad.")
pageTitle(
    CameraSystem.UI.Page,
    "Camara",
    "Configura el objetivo, el alcance y la suavidad del seguimiento."
)

-- Terminal: panel de salida.
local ConsolePanel = create("Frame", {
    Position = UDim2.fromOffset(18, 68),
    Size = UDim2.fromOffset(500, 284),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, TerminalPage)
corner(ConsolePanel, 4)
stroke(ConsolePanel, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(14, 0),
    Size = UDim2.new(1, -28, 0, 36),
    BackgroundTransparency = 1,
    Text = "Actividad",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, ConsolePanel)

create("Frame", {
    Position = UDim2.fromOffset(0, 35),
    Size = UDim2.new(1, 0, 0, 1),
    BackgroundColor3 = THEME.BorderSoft,
    BorderSizePixel = 0,
}, ConsolePanel)

local Console = create("ScrollingFrame", {
    Position = UDim2.fromOffset(10, 44),
    Size = UDim2.new(1, -20, 1, -54),
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    ScrollBarThickness = 2,
    ScrollBarImageColor3 = THEME.Accent,
    CanvasSize = UDim2.new(),
    AutomaticCanvasSize = Enum.AutomaticSize.Y,
    ScrollingDirection = Enum.ScrollingDirection.Y,
}, ConsolePanel)
padding(Console, 3, 5, 2, 4)

local ConsoleLayout = create("UIListLayout", {
    SortOrder = Enum.SortOrder.LayoutOrder,
    Padding = UDim.new(0, 6),
}, Console)

local CommandBar = create("Frame", {
    Position = UDim2.fromOffset(18, 362),
    Size = UDim2.fromOffset(500, 46),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
}, TerminalPage)
corner(CommandBar, 4)
stroke(CommandBar, THEME.Border, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(13, 0),
    Size = UDim2.fromOffset(18, 46),
    BackgroundTransparency = 1,
    Text = ">",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
}, CommandBar)

local CommandBox = create("TextBox", {
    Position = UDim2.fromOffset(36, 0),
    Size = UDim2.new(1, -132, 1, 0),
    BackgroundTransparency = 1,
    Text = "",
    PlaceholderText = "Escribe un comando; por ejemplo: cmds",
    PlaceholderColor3 = THEME.Dim,
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 13,
    TextXAlignment = Enum.TextXAlignment.Left,
    ClearTextOnFocus = false,
}, CommandBar)

local ExecuteButton = create("TextButton", {
    AnchorPoint = Vector2.new(1, 0.5),
    Position = UDim2.new(1, -6, 0.5, 0),
    Size = UDim2.fromOffset(88, 34),
    BackgroundColor3 = THEME.Accent,
    BorderSizePixel = 0,
    Text = "Ejecutar",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, CommandBar)
corner(ExecuteButton, 4)

local SuggestionFrame = create("ScrollingFrame", {
    Position = UDim2.fromOffset(18, 354),
    Size = UDim2.fromOffset(500, 0),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    ScrollBarThickness = 2,
    ScrollBarImageColor3 = THEME.Accent,
    CanvasSize = UDim2.new(),
    Visible = false,
    ZIndex = 30,
}, TerminalPage)
corner(SuggestionFrame, 4)
stroke(SuggestionFrame, THEME.Border, 0, 1)
padding(SuggestionFrame, 5, 5, 5, 5)

create("UIListLayout", {
    SortOrder = Enum.SortOrder.LayoutOrder,
    Padding = UDim.new(0, 3),
}, SuggestionFrame)

-- Terminal: columna de accesos rapidos.
local QuickPanel = create("Frame", {
    Position = UDim2.fromOffset(530, 68),
    Size = UDim2.fromOffset(212, 340),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, TerminalPage)
corner(QuickPanel, 4)
stroke(QuickPanel, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(14, 0),
    Size = UDim2.new(1, -28, 0, 36),
    BackgroundTransparency = 1,
    Text = "Accesos rapidos",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, QuickPanel)

create("Frame", {
    Position = UDim2.fromOffset(0, 35),
    Size = UDim2.new(1, 0, 0, 1),
    BackgroundColor3 = THEME.BorderSoft,
    BorderSizePixel = 0,
}, QuickPanel)

local function makeQuickButton(y, title, description)
    local button = create("TextButton", {
        Position = UDim2.fromOffset(10, y),
        Size = UDim2.new(1, -20, 0, 66),
        BackgroundColor3 = THEME.PanelAlt,
        BorderSizePixel = 0,
        Text = "",
        AutoButtonColor = false,
    }, QuickPanel)
    corner(button, 4)
    stroke(button, THEME.BorderSoft, 0, 1)

    create("Frame", {
        Position = UDim2.fromOffset(0, 0),
        Size = UDim2.fromOffset(0, 0),
        BackgroundColor3 = THEME.Accent,
        BorderSizePixel = 0,
    }, button)

    create("TextLabel", {
        Position = UDim2.fromOffset(14, 10),
        Size = UDim2.new(1, -28, 0, 22),
        BackgroundTransparency = 1,
        Text = title,
        TextColor3 = THEME.White,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, button)

    create("TextLabel", {
        Position = UDim2.fromOffset(14, 33),
        Size = UDim2.new(1, -28, 0, 22),
        BackgroundTransparency = 1,
        Text = description,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, button)

    return button
end

local OpenTPButton = makeQuickButton(48, "Jugadores", "Abrir lista de jugadores")
local ShowCmdsButton = makeQuickButton(124, "Ver comandos", "Mostrar comandos disponibles")

local RuntimeCard = create("Frame", {
    Position = UDim2.fromOffset(10, 210),
    Size = UDim2.new(1, -20, 0, 116),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
}, QuickPanel)
corner(RuntimeCard, 4)
stroke(RuntimeCard, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(12, 11),
    Size = UDim2.new(1, -24, 0, 20),
    BackgroundTransparency = 1,
    Text = "Tu sesion",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, RuntimeCard)

create("TextLabel", {
    Position = UDim2.fromOffset(12, 39),
    Size = UDim2.new(1, -24, 0, 20),
    BackgroundTransparency = 1,
    Text = "●  Menu disponible",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    TextXAlignment = Enum.TextXAlignment.Left,
}, RuntimeCard)

local RuntimeKeyLabel = create("TextLabel", {
    Position = UDim2.fromOffset(12, 70),
    Size = UDim2.new(1, -24, 0, 28),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "MINIMIZAR: INSERT",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
}, RuntimeCard)
corner(RuntimeKeyLabel, 3)

-- TP Menu.
local SearchBar = create("Frame", {
    Position = UDim2.fromOffset(18, 68),
    Size = UDim2.fromOffset(580, 44),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
}, PlayersPage)
corner(SearchBar, 4)
stroke(SearchBar, THEME.Border, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(13, 0),
    Size = UDim2.fromOffset(22, 44),
    BackgroundTransparency = 1,
    Text = "F",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
}, SearchBar)

local PlayerSearch = create("TextBox", {
    Position = UDim2.fromOffset(39, 0),
    Size = UDim2.new(1, -50, 1, 0),
    BackgroundTransparency = 1,
    Text = "",
    PlaceholderText = "Buscar por nombre o usuario...",
    PlaceholderColor3 = THEME.Dim,
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 13,
    TextXAlignment = Enum.TextXAlignment.Left,
    ClearTextOnFocus = false,
}, SearchBar)

local RefreshPlayersButton = create("TextButton", {
    Position = UDim2.fromOffset(610, 68),
    Size = UDim2.fromOffset(132, 44),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "Actualizar",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, PlayersPage)
corner(RefreshPlayersButton, 4)
stroke(RefreshPlayersButton, THEME.Border, 0, 1)

local PlayerCount = create("TextLabel", {
    Position = UDim2.fromOffset(18, 119),
    Size = UDim2.new(1, -36, 0, 18),
    BackgroundTransparency = 1,
    Text = "0 JUGADORES DISPONIBLES",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, PlayersPage)

local PlayerList = create("ScrollingFrame", {
    Position = UDim2.fromOffset(18, 143),
    Size = UDim2.fromOffset(724, 265),
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    ScrollBarThickness = 2,
    ScrollBarImageColor3 = THEME.Accent,
    CanvasSize = UDim2.new(),
    AutomaticCanvasSize = Enum.AutomaticSize.Y,
    ScrollingDirection = Enum.ScrollingDirection.Y,
}, PlayersPage)
padding(PlayerList, 1, 5, 1, 5)

local PlayerGrid = create("UIGridLayout", {
    CellSize = UDim2.fromOffset(350, 76),
    CellPadding = UDim2.fromOffset(10, 10),
    FillDirection = Enum.FillDirection.Horizontal,
    FillDirectionMaxCells = 2,
    SortOrder = Enum.SortOrder.LayoutOrder,
}, PlayerList)

-- Hitbox de piernas.
local HitboxSystem = {UI = {Regions = {}}}
local HitboxStatusPanel = create("Frame", {
    Position = UDim2.fromOffset(18, 70),
    Size = UDim2.fromOffset(724, 98),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, HitboxPage)
corner(HitboxStatusPanel, 4)
stroke(HitboxStatusPanel, THEME.BorderSoft, 0, 1)


create("TextLabel", {
    Position = UDim2.fromOffset(18, 17),
    Size = UDim2.new(1, -190, 0, 22),
    BackgroundTransparency = 1,
    Text = "Zonas del personaje",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, HitboxStatusPanel)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 44),
    Size = UDim2.new(1, -190, 0, 36),
    BackgroundTransparency = 1,
    Text = "Compatible con avatares R6 y R15. No modifica tu propio personaje.",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 13,
    TextWrapped = true,
    TextXAlignment = Enum.TextXAlignment.Left,
    TextYAlignment = Enum.TextYAlignment.Top,
}, HitboxStatusPanel)

local HitboxToggleButton = create("TextButton", {
    AnchorPoint = Vector2.new(1, 0.5),
    Position = UDim2.new(1, -18, 0.5, 0),
    Size = UDim2.fromOffset(146, 42),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "Activar",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, HitboxStatusPanel)
corner(HitboxToggleButton, 4)
stroke(HitboxToggleButton, THEME.Border, 0, 1)

local HitboxSizePanel = create("Frame", {
    Position = UDim2.fromOffset(18, 182),
    Size = UDim2.fromOffset(350, 190),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, HitboxPage)
corner(HitboxSizePanel, 4)
stroke(HitboxSizePanel, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 16),
    Size = UDim2.new(1, -36, 0, 22),
    BackgroundTransparency = 1,
    Text = "TAMANO DE LA HITBOX",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, HitboxSizePanel)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 43),
    Size = UDim2.new(1, -36, 0, 20),
    BackgroundTransparency = 1,
    Text = "Rango permitido: 1.0 a 15.0 studs.",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, HitboxSizePanel)

local HitboxMinusButton = create("TextButton", {
    Position = UDim2.fromOffset(18, 78),
    Size = UDim2.fromOffset(46, 42),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "-",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 17,
    AutoButtonColor = false,
}, HitboxSizePanel)
corner(HitboxMinusButton, 4)
stroke(HitboxMinusButton, THEME.Border, 0, 1)

local HitboxValueBox = create("TextBox", {
    Position = UDim2.fromOffset(76, 78),
    Size = UDim2.fromOffset(140, 42),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "4.0",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    ClearTextOnFocus = false,
}, HitboxSizePanel)
corner(HitboxValueBox, 4)
stroke(HitboxValueBox, THEME.Border, 0, 1)

local HitboxPlusButton = create("TextButton", {
    Position = UDim2.fromOffset(228, 78),
    Size = UDim2.fromOffset(46, 42),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "+",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 17,
    AutoButtonColor = false,
}, HitboxSizePanel)
corner(HitboxPlusButton, 4)
stroke(HitboxPlusButton, THEME.Border, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(282, 78),
    Size = UDim2.fromOffset(50, 42),
    BackgroundTransparency = 1,
    Text = "STUDS",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
}, HitboxSizePanel)

local HitboxSlider = create("Frame", {
    Position = UDim2.fromOffset(18, 151),
    Size = UDim2.fromOffset(314, 7),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Active = true,
}, HitboxSizePanel)
corner(HitboxSlider, 4)

local HitboxSliderFill = create("Frame", {
    Size = UDim2.new(0.214, 0, 1, 0),
    BackgroundColor3 = THEME.Accent,
    BorderSizePixel = 0,
}, HitboxSlider)
corner(HitboxSliderFill, 4)

local HitboxSliderKnob = create("Frame", {
    AnchorPoint = Vector2.new(0.5, 0.5),
    Position = UDim2.new(0.214, 0, 0.5, 0),
    Size = UDim2.fromOffset(15, 15),
    BackgroundColor3 = THEME.White,
    BorderSizePixel = 0,
}, HitboxSlider)
corner(HitboxSliderKnob, 8)
stroke(HitboxSliderKnob, THEME.Accent, 0, 2)

local HitboxVisualPanel = create("Frame", {
    Position = UDim2.fromOffset(382, 182),
    Size = UDim2.fromOffset(360, 190),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, HitboxPage)
corner(HitboxVisualPanel, 4)
stroke(HitboxVisualPanel, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 16),
    Size = UDim2.new(1, -36, 0, 22),
    BackgroundTransparency = 1,
    Text = "VISUALIZACION",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, HitboxVisualPanel)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 44),
    Size = UDim2.new(1, -36, 0, 38),
    BackgroundTransparency = 1,
    Text = "Muestra las zonas ampliadas para medir el area.",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 12,
    TextWrapped = true,
    TextXAlignment = Enum.TextXAlignment.Left,
    TextYAlignment = Enum.TextYAlignment.Top,
}, HitboxVisualPanel)

local HitboxVisualButton = create("TextButton", {
    Position = UDim2.fromOffset(18, 94),
    Size = UDim2.fromOffset(150, 42),
    BackgroundColor3 = THEME.Accent,
    BorderSizePixel = 0,
    Text = "Visible",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, HitboxVisualPanel)
corner(HitboxVisualButton, 4)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 147),
    Size = UDim2.new(1, -36, 0, 24),
    BackgroundTransparency = 1,
    Text = "Ocultar restaura el cuerpo y pausa la ampliacion.",
    TextColor3 = THEME.Dim,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 12,
    TextWrapped = true,
    TextXAlignment = Enum.TextXAlignment.Left,
}, HitboxVisualPanel)

HitboxSystem.UI.createRegionCard = function(regionName, x, y, width, title, subtitle)
    local card = create("Frame", {
        Position = UDim2.fromOffset(x, y),
        Size = UDim2.fromOffset(width, 88),
        BackgroundColor3 = THEME.Panel,
        BorderSizePixel = 0,
    }, HitboxPage)
    corner(card, 4)
    stroke(card, THEME.BorderSoft, 0, 1)

    create("TextLabel", {
        Position = UDim2.fromOffset(14, 11),
        Size = UDim2.new(1, -128, 0, 19),
        BackgroundTransparency = 1,
        Text = title,
        TextColor3 = THEME.White,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, card)

    create("TextLabel", {
        Position = UDim2.fromOffset(14, 30),
        Size = UDim2.new(1, -128, 0, 18),
        BackgroundTransparency = 1,
        Text = subtitle,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, card)

    local toggleButton = create("TextButton", {
        AnchorPoint = Vector2.new(1, 0),
        Position = UDim2.new(1, -14, 0, 11),
        Size = UDim2.fromOffset(100, 32),
        BackgroundColor3 = THEME.PanelAlt,
        BorderSizePixel = 0,
        Text = "Activa",
        TextColor3 = THEME.AccentText,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 12,
        AutoButtonColor = false,
    }, card)
    corner(toggleButton, 3)
    stroke(toggleButton, THEME.Border, 0, 1)

    create("TextLabel", {
        Position = UDim2.fromOffset(14, 57),
        Size = UDim2.fromOffset(72, 24),
        BackgroundTransparency = 1,
        Text = "Tamano",
        TextColor3 = THEME.Dim,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, card)

    local minusButton = create("TextButton", {
        Position = UDim2.new(1, -148, 0, 55),
        Size = UDim2.fromOffset(28, 26),
        BackgroundColor3 = THEME.Input,
        BorderSizePixel = 0,
        Text = "-",
        TextColor3 = THEME.Text,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        AutoButtonColor = false,
    }, card)
    corner(minusButton, 3)

    local valueBox = create("TextBox", {
        Position = UDim2.new(1, -116, 0, 55),
        Size = UDim2.fromOffset(68, 26),
        BackgroundColor3 = THEME.Input,
        BorderSizePixel = 0,
        Text = "4.0",
        TextColor3 = THEME.White,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 12,
        ClearTextOnFocus = false,
    }, card)
    corner(valueBox, 3)
    stroke(valueBox, THEME.Border, 0, 1)

    local plusButton = create("TextButton", {
        Position = UDim2.new(1, -44, 0, 55),
        Size = UDim2.fromOffset(30, 26),
        BackgroundColor3 = THEME.Input,
        BorderSizePixel = 0,
        Text = "+",
        TextColor3 = THEME.Text,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        AutoButtonColor = false,
    }, card)
    corner(plusButton, 3)

    HitboxSystem.UI.Regions[regionName] = {
        Card = card,
        Toggle = toggleButton,
        Minus = minusButton,
        Value = valueBox,
        Plus = plusButton,
    }
end

HitboxSystem.remasterUI = function()
    HitboxSizePanel.Visible = false
    HitboxVisualPanel.Visible = false

    for _, child in ipairs(HitboxPage:GetChildren()) do
        if child:IsA("TextLabel") and child.Text == "Hitbox por zonas" then
            child.Text = "Hitbox por zonas"
            child.Size = UDim2.new(1, -36, 0, 23)
        end
    end

    for _, child in ipairs(HitboxStatusPanel:GetChildren()) do
        if child:IsA("TextLabel") and child.Text == "Zonas del personaje" then
            child.Text = "Hitbox por zonas"
            child.Size = UDim2.new(1, -360, 0, 22)
        elseif child:IsA("TextLabel")
            and string.find(child.Text, "Compatible con avatares", 1, true) then
            child.Text = "Control independiente para piernas, pies, cuerpo y cabeza."
            child.Size = UDim2.new(1, -360, 0, 36)
            HitboxSystem.UI.StatusText = child
        end
    end

    HitboxVisualButton.Parent = HitboxStatusPanel
    HitboxVisualButton.AnchorPoint = Vector2.new(1, 0.5)
    HitboxVisualButton.Position = UDim2.new(1, -176, 0.5, 0)
    HitboxVisualButton.Size = UDim2.fromOffset(142, 42)

    HitboxSystem.UI.createRegionCard("legs", 18, 182, 350, "Piernas", "R6 y R15, sin incluir los pies.")
    HitboxSystem.UI.createRegionCard("feet", 382, 182, 360, "Pies", "Pies independientes en avatares R15.")
    HitboxSystem.UI.createRegionCard("body", 18, 280, 350, "Cuerpo", "Torso central del personaje.")
    HitboxSystem.UI.createRegionCard("head", 382, 280, 360, "Cabeza", "Hitbox separada para la cabeza.")
end

HitboxSystem.remasterUI()
HitboxSystem.remasterUI = nil
HitboxSystem.UI.createRegionCard = nil

-- ESP visual.
local EspMasterPanel = create("Frame", {
    Position = UDim2.fromOffset(18, 70),
    Size = UDim2.fromOffset(724, 82),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, EspPage)
corner(EspMasterPanel, 4)
stroke(EspMasterPanel, THEME.BorderSoft, 0, 1)


create("TextLabel", {
    Position = UDim2.fromOffset(18, 14),
    Size = UDim2.new(1, -190, 0, 22),
    BackgroundTransparency = 1,
    Text = "Indicadores ESP",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, EspMasterPanel)

local EspSupportLabel = create("TextLabel", {
    Position = UDim2.fromOffset(18, 40),
    Size = UDim2.new(1, -190, 0, 24),
    BackgroundTransparency = 1,
    Text = "Renderizado directo y deteccion automatica de rig.",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, EspMasterPanel)

local EspMasterButton = create("TextButton", {
    AnchorPoint = Vector2.new(1, 0.5),
    Position = UDim2.new(1, -18, 0.5, 0),
    Size = UDim2.fromOffset(146, 42),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "Activar",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, EspMasterPanel)
corner(EspMasterButton, 4)
stroke(EspMasterButton, THEME.Border, 0, 1)

local function makeEspOptionCard(x, y, width, title, description)
    local card = create("Frame", {
        Position = UDim2.fromOffset(x, y),
        Size = UDim2.fromOffset(width, 92),
        BackgroundColor3 = THEME.Panel,
        BorderSizePixel = 0,
    }, EspPage)
    corner(card, 4)
    stroke(card, THEME.BorderSoft, 0, 1)

    create("TextLabel", {
        Position = UDim2.fromOffset(16, 14),
        Size = UDim2.new(1, -150, 0, 20),
        BackgroundTransparency = 1,
        Text = title,
        TextColor3 = THEME.White,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, card)

    create("TextLabel", {
        Position = UDim2.fromOffset(16, 38),
        Size = UDim2.new(1, -150, 0, 40),
        BackgroundTransparency = 1,
        Text = description,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 12,
        TextWrapped = true,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextYAlignment = Enum.TextYAlignment.Top,
    }, card)

    local button = create("TextButton", {
        AnchorPoint = Vector2.new(1, 0.5),
        Position = UDim2.new(1, -16, 0.5, 0),
        Size = UDim2.fromOffset(112, 38),
        BackgroundColor3 = THEME.PanelAlt,
        BorderSizePixel = 0,
        Text = "Activa",
        TextColor3 = THEME.AccentText,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 12,
        AutoButtonColor = false,
    }, card)
    corner(button, 4)
    stroke(button, THEME.Border, 0, 1)

    return card, button
end

local _, EspLinesButton = makeEspOptionCard(
    18,
    166,
    350,
    "Lineas",
    "Salen desde tu personaje hasta cada jugador visible."
)

local _, EspBoxesButton = makeEspOptionCard(
    382,
    166,
    360,
    "Cajas",
    "Dibuja una caja precisa alrededor de cada personaje."
)

local _, EspSkeletonButton = makeEspOptionCard(
    18,
    272,
    350,
    "Esqueleto",
    "Reconoce R6 o R15 y conecta sus articulaciones."
)

local RearAlertCard, RearAlertButton = makeEspOptionCard(
    382,
    272,
    360,
    "Rueda de proximidad",
    "Pasos por direccion. Mas cerca, mas intenso."
)

RearAlertButton.Position = UDim2.new(1, -16, 0, 30)
RearAlertButton.Size = UDim2.fromOffset(112, 32)

local RearDistanceMinus = create("TextButton", {
    Position = UDim2.new(1, -128, 0, 56),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "-",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, RearAlertCard)
corner(RearDistanceMinus, 3)

local RearDistanceValue = create("TextLabel", {
    Position = UDim2.new(1, -96, 0, 56),
    Size = UDim2.fromOffset(48, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "15",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
}, RearAlertCard)
corner(RearDistanceValue, 3)

local RearDistancePlus = create("TextButton", {
    Position = UDim2.new(1, -44, 0, 56),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "+",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, RearAlertCard)
corner(RearDistancePlus, 3)

local RearAlertBanner = create("Frame", {
    Name = "ProximityWheel", AnchorPoint = Vector2.new(0.5, 0.5),
    Position = UDim2.fromScale(0.5, 0.5), Size = UDim2.fromOffset(290, 290),
    BackgroundTransparency = 1, BorderSizePixel = 0, Visible = false, ZIndex = 70,
}, CameraSystem.UI.OverlayGui)

-- Seguimiento de camara con circulo FOV.
CameraSystem.UI.MasterPanel = create("Frame", {
    Position = UDim2.fromOffset(18, 70),
    Size = UDim2.fromOffset(724, 82),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, CameraSystem.UI.Page)
corner(CameraSystem.UI.MasterPanel, 4)
stroke(CameraSystem.UI.MasterPanel, THEME.BorderSoft, 0, 1)


create("TextLabel", {
    Position = UDim2.fromOffset(18, 14),
    Size = UDim2.new(1, -190, 0, 22),
    BackgroundTransparency = 1,
    Text = "Seguimiento de objetivos",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, CameraSystem.UI.MasterPanel)

CameraSystem.UI.Support = create("TextLabel", {
    Position = UDim2.fromOffset(18, 40),
    Size = UDim2.fromOffset(390, 24),
    BackgroundTransparency = 1,
    Text = "Busca automaticamente el jugador mas cercano al centro.",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, CameraSystem.UI.MasterPanel)

CameraSystem.UI.TeamCheck = create("TextButton", {
    Position = UDim2.fromOffset(426, 20),
    Size = UDim2.fromOffset(120, 42),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "TEAM CHECK: ON",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, CameraSystem.UI.MasterPanel)
corner(CameraSystem.UI.TeamCheck, 4)
stroke(CameraSystem.UI.TeamCheck, THEME.Border, 0, 1)

CameraSystem.UI.Master = create("TextButton", {
    AnchorPoint = Vector2.new(1, 0.5),
    Position = UDim2.new(1, -18, 0.5, 0),
    Size = UDim2.fromOffset(146, 42),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "Activar",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, CameraSystem.UI.MasterPanel)
corner(CameraSystem.UI.Master, 4)
stroke(CameraSystem.UI.Master, THEME.Border, 0, 1)

CameraSystem.UI.createCard = function(x, y, width, title, description)
    local card = create("Frame", {
        Position = UDim2.fromOffset(x, y),
        Size = UDim2.fromOffset(width, 92),
        BackgroundColor3 = THEME.Panel,
        BorderSizePixel = 0,
    }, CameraSystem.UI.Page)
    corner(card, 4)
    stroke(card, THEME.BorderSoft, 0, 1)

    create("TextLabel", {
        Position = UDim2.fromOffset(14, 12),
        Size = UDim2.new(1, -28, 0, 19),
        BackgroundTransparency = 1,
        Text = title,
        TextColor3 = THEME.White,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, card)

    create("TextLabel", {
        Position = UDim2.fromOffset(14, 31),
        Size = UDim2.new(1, -28, 0, 17),
        BackgroundTransparency = 1,
        Text = description,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, card)
    return card
end

CameraSystem.UI.FovCard = CameraSystem.UI.createCard(
    18,
    166,
    350,
    "Area de seguimiento",
    "El seguimiento solo funciona dentro de esta area."
)

CameraSystem.UI.FovToggle = create("TextButton", {
    Position = UDim2.fromOffset(222, 12),
    Size = UDim2.fromOffset(114, 32),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = "Visible",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, CameraSystem.UI.FovCard)
corner(CameraSystem.UI.FovToggle, 3)
stroke(CameraSystem.UI.FovToggle, THEME.Border, 0, 1)

CameraSystem.UI.FovMinus = create("TextButton", {
    Position = UDim2.fromOffset(222, 54),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "-",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, CameraSystem.UI.FovCard)
corner(CameraSystem.UI.FovMinus, 3)

CameraSystem.UI.FovValue = create("TextLabel", {
    Position = UDim2.fromOffset(254, 54),
    Size = UDim2.fromOffset(58, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "140 PX",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
}, CameraSystem.UI.FovCard)
corner(CameraSystem.UI.FovValue, 3)

CameraSystem.UI.FovPlus = create("TextButton", {
    Position = UDim2.fromOffset(316, 54),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "+",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, CameraSystem.UI.FovCard)
corner(CameraSystem.UI.FovPlus, 3)

CameraSystem.UI.ZoneCard = CameraSystem.UI.createCard(
    382,
    166,
    360,
    "Zona objetivo",
    "Elige que parte seguira la camara."
)

CameraSystem.UI.ModeCard = CameraSystem.UI.createCard(
    18,
    272,
    350,
    "Movimiento",
    "Suave permite recuperar el control manual."
)

CameraSystem.UI.StatusCard = CameraSystem.UI.createCard(
    382,
    272,
    360,
    "Activacion",
    ""
)

CameraSystem.UI.makeChoice = function(parent, x, width, text, y)
    local button = create("TextButton", {
        Position = UDim2.fromOffset(x, y or 54),
        Size = UDim2.fromOffset(width, 28),
        BackgroundColor3 = THEME.Input,
        BorderSizePixel = 0,
        Text = text,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 12,
        AutoButtonColor = false,
    }, parent)
    corner(button, 3)
    stroke(button, THEME.Border, 0, 1)
    return button
end

CameraSystem.UI.Feet = CameraSystem.UI.makeChoice(CameraSystem.UI.ZoneCard, 14, 104, "Pies")
CameraSystem.UI.Body = CameraSystem.UI.makeChoice(CameraSystem.UI.ZoneCard, 128, 104, "Cuerpo")
CameraSystem.UI.Head = CameraSystem.UI.makeChoice(CameraSystem.UI.ZoneCard, 242, 104, "Cabeza")
CameraSystem.UI.Hard = CameraSystem.UI.makeChoice(CameraSystem.UI.ModeCard, 14, 153, "Directo")
CameraSystem.UI.Smooth = CameraSystem.UI.makeChoice(CameraSystem.UI.ModeCard, 181, 155, "Suave")
CameraSystem.UI.Auto = CameraSystem.UI.makeChoice(
    CameraSystem.UI.StatusCard,
    14,
    82,
    "Auto",
    31
)
CameraSystem.UI.Manual = CameraSystem.UI.makeChoice(
    CameraSystem.UI.StatusCard,
    104,
    88,
    "Manual",
    31
)
CameraSystem.UI.AimKey = CameraSystem.UI.makeChoice(
    CameraSystem.UI.StatusCard,
    200,
    146,
    "TECLA: Q",
    31
)
CameraSystem.UI.Hold = CameraSystem.UI.makeChoice(
    CameraSystem.UI.StatusCard,
    14,
    160,
    "Mantener",
    61
)
CameraSystem.UI.Toggle = CameraSystem.UI.makeChoice(
    CameraSystem.UI.StatusCard,
    186,
    160,
    "Pulsar para alternar",
    61
)

CameraSystem.UI.DistanceCard = create("Frame", {
    Position = UDim2.fromOffset(18, 378),
    Size = UDim2.fromOffset(724, 40),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, CameraSystem.UI.Page)
corner(CameraSystem.UI.DistanceCard, 4)
stroke(CameraSystem.UI.DistanceCard, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(14, 0),
    Size = UDim2.fromOffset(128, 40),
    BackgroundTransparency = 1,
    Text = "Distancia maxima",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, CameraSystem.UI.DistanceCard)

create("TextLabel", {
    Position = UDim2.fromOffset(142, 0),
    Size = UDim2.fromOffset(64, 40),
    BackgroundTransparency = 1,
    Text = "5-5000 ST",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, CameraSystem.UI.DistanceCard)

CameraSystem.UI.DistanceMinus = create("TextButton", {
    Position = UDim2.fromOffset(216, 7),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "-",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, CameraSystem.UI.DistanceCard)
corner(CameraSystem.UI.DistanceMinus, 3)

CameraSystem.UI.DistanceValue = create("TextBox", {
    Position = UDim2.fromOffset(248, 7),
    Size = UDim2.fromOffset(72, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "500",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    ClearTextOnFocus = false,
}, CameraSystem.UI.DistanceCard)
corner(CameraSystem.UI.DistanceValue, 3)
stroke(CameraSystem.UI.DistanceValue, THEME.Border, 0, 1)

CameraSystem.UI.DistancePlus = create("TextButton", {
    Position = UDim2.fromOffset(324, 7),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "+",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, CameraSystem.UI.DistanceCard)
corner(CameraSystem.UI.DistancePlus, 3)

create("Frame", {
    Position = UDim2.fromOffset(362, 8),
    Size = UDim2.fromOffset(1, 24),
    BackgroundColor3 = THEME.BorderSoft,
    BorderSizePixel = 0,
}, CameraSystem.UI.DistanceCard)

create("TextLabel", {
    Position = UDim2.fromOffset(378, 0),
    Size = UDim2.fromOffset(144, 40),
    BackgroundTransparency = 1,
    Text = "INTENSIDAD SUAVE (%)",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, CameraSystem.UI.DistanceCard)

CameraSystem.UI.IntensityMinus = create("TextButton", {
    Position = UDim2.fromOffset(532, 7),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "-",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, CameraSystem.UI.DistanceCard)
corner(CameraSystem.UI.IntensityMinus, 3)

CameraSystem.UI.IntensityValue = create("TextBox", {
    Position = UDim2.fromOffset(564, 7),
    Size = UDim2.fromOffset(98, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "35",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    ClearTextOnFocus = false,
}, CameraSystem.UI.DistanceCard)
corner(CameraSystem.UI.IntensityValue, 3)
stroke(CameraSystem.UI.IntensityValue, THEME.Border, 0, 1)

CameraSystem.UI.IntensityPlus = create("TextButton", {
    Position = UDim2.fromOffset(668, 7),
    Size = UDim2.fromOffset(28, 26),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "+",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
    AutoButtonColor = false,
}, CameraSystem.UI.DistanceCard)
corner(CameraSystem.UI.IntensityPlus, 3)

CameraSystem.UI.FovCircle = create("Frame", {
    Name = "CameraFovCircle",
    AnchorPoint = Vector2.new(0.5, 0.5),
    Position = UDim2.fromScale(0.5, 0.5),
    Size = UDim2.fromOffset(280, 280),
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Visible = false,
    ZIndex = 80,
}, CameraSystem.UI.OverlayGui)
corner(CameraSystem.UI.FovCircle, 999)
CameraSystem.UI.FovStroke = stroke(CameraSystem.UI.FovCircle, THEME.Accent, 0.05, 1.5)

CameraSystem.UI.CaptureShield = create("TextButton", {
    Name = "AimInputCapture",
    Size = UDim2.fromScale(1, 1),
    BackgroundColor3 = THEME.Black,
    BackgroundTransparency = 0.28,
    BorderSizePixel = 0,
    Text = "PRESIONA UNA TECLA O BOTON DEL MOUSE\nESC PARA CANCELAR",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 16,
    AutoButtonColor = false,
    Active = true,
    Modal = true,
    Visible = false,
    ZIndex = 90,
}, CameraSystem.UI.OverlayGui)

CameraSystem.UI.createCard = nil
CameraSystem.UI.makeChoice = nil

-- Controles visuales integrados en el mismo menu, sin cambiar su diseno.
VisionSystem.UI.Page = create("ScrollingFrame", {
    Name = "VisionPage", Size = UDim2.fromScale(1, 1),
    BackgroundTransparency = 1, Visible = false,
}, Body)
pageTitle(VisionSystem.UI.Page, "Luz y zoom", "Ajusta la luz del entorno y acerca la imagen con una tecla.")

do
    local function label(parent, text, x, y, width, height, size, color)
        return create("TextLabel", {
            Position = UDim2.fromOffset(x, y), Size = UDim2.fromOffset(width, height),
            BackgroundTransparency = 1, Text = text, TextColor3 = color or THEME.Text,
            Font = Enum.Font.BuilderSansMedium, TextSize = size and (size >= 13 and 15 or 13) or 13,
            TextXAlignment = Enum.TextXAlignment.Left, TextWrapped = true,
        }, parent)
    end
    local function panel(y, height)
        local object = create("Frame", {
            Position = UDim2.fromOffset(12, y), Size = UDim2.fromOffset(376, height),
            BackgroundColor3 = THEME.Panel, BorderSizePixel = 0,
        }, VisionSystem.UI.Page)
        corner(object, 4)
        stroke(object, THEME.BorderSoft, 0, 1)
        return object
    end
    local function button(parent, text, x, y, width, height)
        local object = create("TextButton", {
            Position = UDim2.fromOffset(x, y), Size = UDim2.fromOffset(width, height),
            BackgroundColor3 = THEME.PanelAlt, BorderSizePixel = 0, Text = text,
            TextColor3 = THEME.Text, Font = Enum.Font.BuilderSansBold, TextSize = 13,
            AutoButtonColor = false,
        }, parent)
        corner(object, 4)
        stroke(object, THEME.Border, 0, 1)
        return object
    end
    local function slider(parent, name, x, y, width)
        local track = create("Frame", {
            Name = name, Position = UDim2.fromOffset(x, y), Size = UDim2.fromOffset(width, 22),
            BackgroundTransparency = 1, Active = true,
        }, parent)
        local rail = create("Frame", {
            Position = UDim2.fromOffset(0, 8), Size = UDim2.new(1, 0, 0, 6),
            BackgroundColor3 = THEME.Border, BorderSizePixel = 0,
        }, track)
        corner(rail, 3)
        local fill = create("Frame", {
            Size = UDim2.fromScale(0, 1), BackgroundColor3 = THEME.Accent, BorderSizePixel = 0,
        }, rail)
        corner(fill, 3)
        local knob = create("Frame", {
            AnchorPoint = Vector2.new(0.5, 0.5), Position = UDim2.fromScale(0, 0.5),
            Size = UDim2.fromOffset(12, 12), BackgroundColor3 = THEME.White, BorderSizePixel = 0,
        }, track)
        corner(knob, 6)
        return {Track = track, Fill = fill, Knob = knob}
    end
    local light = panel(38, 146)
    label(light, "Iluminacion", 16, 10, 210, 24, 13, THEME.White)
    label(light, "Se mantiene al morir, reaparecer o cambiar el ambiente.", 16, 44, 344, 30, 11, THEME.Muted)
    VisionSystem.UI.LightToggle = button(light, "Activar", 246, 12, 114, 32)
    label(light, "Intensidad", 16, 84, 160, 22, 11)
    VisionSystem.UI.LightSlider = slider(light, "LightSlider", 22, 112, 332)
    VisionSystem.UI.LightValue = label(light, "2.0 / 5", 270, 84, 90, 22, 12, THEME.White)

    local zoom = panel(196, 284)
    label(zoom, "Zoom", 16, 10, 210, 24, 13, THEME.White)
    label(zoom, "Acerca la imagen sin mover tu personaje.", 16, 44, 344, 22, 11, THEME.Muted)
    VisionSystem.UI.ZoomToggle = button(zoom, "Activado", 246, 12, 114, 32)
    label(zoom, "Aumento · 1.5x a 15x", 16, 76, 210, 24, 11)
    VisionSystem.UI.ZoomValue = create("TextBox", {
        Position = UDim2.fromOffset(264, 74), Size = UDim2.fromOffset(96, 28),
        BackgroundColor3 = THEME.Input, BorderSizePixel = 0, Text = "4.0",
        TextColor3 = THEME.White, Font = Enum.Font.BuilderSansBold, TextSize = 13,
        ClearTextOnFocus = false,
    }, zoom)
    corner(VisionSystem.UI.ZoomValue, 3)
    stroke(VisionSystem.UI.ZoomValue, THEME.Border, 0, 1)
    VisionSystem.UI.ZoomSlider = slider(zoom, "ZoomSlider", 22, 112, 332)
    label(zoom, "Menos", 16, 137, 90, 20, 10, THEME.Muted)
    label(zoom, "Mas", 320, 137, 40, 20, 10, THEME.Muted)
    VisionSystem.UI.ZoomKey = button(zoom, "TECLA: C", 16, 168, 344, 32)
    VisionSystem.UI.ZoomHold = button(zoom, "Mantener", 16, 212, 166, 32)
    VisionSystem.UI.ZoomToggleMode = button(zoom, "Pulsar para alternar", 190, 212, 170, 32)
    VisionSystem.UI.ZoomStatus = label(zoom, "", 16, 254, 344, 22, 11, THEME.Muted)
    label(VisionSystem.UI.Page, "El zoom no aumenta la distancia que carga el servidor. Apagar restaura la vista.",
        12, 492, 376, 36, 11, THEME.Muted)

    VisionSystem.UI.CaptureShield = create("TextButton", {
        Name = "ZoomInputCapture", Size = UDim2.fromScale(1, 1),
        BackgroundColor3 = THEME.Black, BackgroundTransparency = 0.18,
        BorderSizePixel = 0,
        Text = "ZOOM: PRESIONA UNA TECLA O BOTON DEL MOUSE\nESC CANCELA | SUPR QUITA LA TECLA",
        TextColor3 = THEME.White, Font = Enum.Font.BuilderSansBold, TextSize = 16,
        AutoButtonColor = false, Active = true, Modal = true, Visible = false, ZIndex = 91,
    }, CameraSystem.UI.OverlayGui)
end


-- Ajustes.
local KeyPanel = create("Frame", {
    Position = UDim2.fromOffset(18, 70),
    Size = UDim2.fromOffset(350, 164),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, SettingsPage)
corner(KeyPanel, 4)
stroke(KeyPanel, THEME.BorderSoft, 0, 1)

create("Frame", {
    Position = UDim2.fromOffset(0, 0),
    Size = UDim2.fromOffset(3, 164),
    BackgroundColor3 = THEME.Accent,
    BorderSizePixel = 0,
}, KeyPanel)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 16),
    Size = UDim2.new(1, -36, 0, 22),
    BackgroundTransparency = 1,
    Text = "Mostrar u ocultar el menu",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, KeyPanel)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 43),
    Size = UDim2.new(1, -36, 0, 38),
    BackgroundTransparency = 1,
    Text = "Minimiza o restaura el menu desde cualquier pagina.",
    TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSansMedium,
    TextSize = 13,
    TextWrapped = true,
    TextXAlignment = Enum.TextXAlignment.Left,
    TextYAlignment = Enum.TextYAlignment.Top,
}, KeyPanel)

local CurrentKey = create("TextLabel", {
    Position = UDim2.fromOffset(18, 94),
    Size = UDim2.fromOffset(116, 42),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "INSERT",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 13,
}, KeyPanel)
corner(CurrentKey, 4)
stroke(CurrentKey, THEME.Border, 0, 1)

local ChangeKeyButton = create("TextButton", {
    Position = UDim2.fromOffset(146, 94),
    Size = UDim2.new(1, -164, 0, 42),
    BackgroundColor3 = THEME.Accent,
    BorderSizePixel = 0,
    Text = "Cambiar tecla",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    AutoButtonColor = false,
}, KeyPanel)
corner(ChangeKeyButton, 4)

local AppearancePanel = create("Frame", {
    Position = UDim2.fromOffset(382, 70),
    Size = UDim2.fromOffset(360, 164),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, SettingsPage)
corner(AppearancePanel, 4)
stroke(AppearancePanel, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 16),
    Size = UDim2.new(1, -36, 0, 22),
    BackgroundTransparency = 1,
    Text = "Apariencia",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, AppearancePanel)

AutoSave.UI.AutosaveBadge = create("TextLabel", {
    AnchorPoint = Vector2.new(1, 0),
    Position = UDim2.new(1, -18, 0, 12),
    Size = UDim2.fromOffset(104, 28),
    BackgroundColor3 = THEME.PanelAlt,
    BorderSizePixel = 0,
    Text = AutoSave.PersistentSaveAvailable and "AUTO • ACTIVO" or "AUTO • SESION",
    TextColor3 = THEME.AccentText,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
}, AppearancePanel)
corner(AutoSave.UI.AutosaveBadge, 3)
stroke(AutoSave.UI.AutosaveBadge, THEME.BorderSoft, 0, 1)

local function settingRow(parent, y, title, description, status)
    create("TextLabel", {
        Position = UDim2.fromOffset(18, y),
        Size = UDim2.new(1, -135, 0, 20),
        BackgroundTransparency = 1,
        Text = title,
        TextColor3 = THEME.Text,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, parent)

    create("TextLabel", {
        Position = UDim2.fromOffset(18, y + 21),
        Size = UDim2.new(1, -135, 0, 18),
        BackgroundTransparency = 1,
        Text = description,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, parent)

    local badge = create("TextLabel", {
        AnchorPoint = Vector2.new(1, 0),
        Position = UDim2.new(1, -18, 0, y + 2),
        Size = UDim2.fromOffset(92, 30),
        BackgroundColor3 = THEME.PanelAlt,
        BorderSizePixel = 0,
        Text = status,
        TextColor3 = THEME.AccentText,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 12,
    }, parent)
    corner(badge, 3)
    stroke(badge, THEME.BorderSoft, 0, 1)
end

settingRow(AppearancePanel, 48, "Animaciones", "Movimiento suave al minimizar", "Activas")

create("TextLabel", {
    Position = UDim2.fromOffset(18, 99),
    Size = UDim2.fromOffset(180, 24),
    BackgroundTransparency = 1,
    Text = "Escala del menu",
    TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, AppearancePanel)

AutoSave.UI.WindowScaleValue = create("TextLabel", {
    AnchorPoint = Vector2.new(1, 0),
    Position = UDim2.new(1, -18, 0, 96),
    Size = UDim2.fromOffset(70, 28),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Text = "100%",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 12,
}, AppearancePanel)
corner(AutoSave.UI.WindowScaleValue, 3)
stroke(AutoSave.UI.WindowScaleValue, THEME.Border, 0, 1)

AutoSave.UI.WindowScaleTrack = create("Frame", {
    Position = UDim2.fromOffset(18, 138),
    Size = UDim2.new(1, -36, 0, 6),
    BackgroundColor3 = THEME.Input,
    BorderSizePixel = 0,
    Active = true,
}, AppearancePanel)
corner(AutoSave.UI.WindowScaleTrack, 3)

AutoSave.UI.WindowScaleFill = create("Frame", {
    Size = UDim2.new(0.625, 0, 1, 0),
    BackgroundColor3 = THEME.Accent,
    BorderSizePixel = 0,
}, AutoSave.UI.WindowScaleTrack)
corner(AutoSave.UI.WindowScaleFill, 3)

AutoSave.UI.WindowScaleKnob = create("Frame", {
    AnchorPoint = Vector2.new(0.5, 0.5),
    Position = UDim2.new(0.625, 0, 0.5, 0),
    Size = UDim2.fromOffset(14, 14),
    BackgroundColor3 = THEME.White,
    BorderSizePixel = 0,
}, AutoSave.UI.WindowScaleTrack)
corner(AutoSave.UI.WindowScaleKnob, 7)
stroke(AutoSave.UI.WindowScaleKnob, THEME.Accent, 0, 2)

local HelpPanel = create("Frame", {
    Position = UDim2.fromOffset(18, 248),
    Size = UDim2.fromOffset(724, 160),
    BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0,
}, SettingsPage)
corner(HelpPanel, 4)
stroke(HelpPanel, THEME.BorderSoft, 0, 1)

create("TextLabel", {
    Position = UDim2.fromOffset(18, 15),
    Size = UDim2.new(1, -36, 0, 22),
    BackgroundTransparency = 1,
    Text = "Atajos de teclado",
    TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold,
    TextSize = 15,
    TextXAlignment = Enum.TextXAlignment.Left,
}, HelpPanel)

local function controlHint(y, keyText, description)
    local badge = create("TextLabel", {
        Position = UDim2.fromOffset(18, y),
        Size = UDim2.fromOffset(112, 32),
        BackgroundColor3 = THEME.Input,
        BorderSizePixel = 0,
        Text = keyText,
        TextColor3 = THEME.Text,
        Font = Enum.Font.BuilderSansBold,
        TextSize = 12,
    }, HelpPanel)
    corner(badge, 3)
    stroke(badge, THEME.Border, 0, 1)

    create("TextLabel", {
        Position = UDim2.fromOffset(146, y),
        Size = UDim2.new(1, -164, 0, 32),
        BackgroundTransparency = 1,
        Text = description,
        TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
    }, HelpPanel)
end

controlHint(48, "TAB", "Completa la primera sugerencia de la terminal.")
controlHint(91, "ESC", "Cancela la seleccion de una nueva tecla.")

-- Reutiliza los controles y sus callbacks; solo reorganiza la presentacion.
Compact.applyLayout = function()
    local function place(o, x, y, w, h)
        o.AnchorPoint = Vector2.new(0, 0)
        o.Position = UDim2.fromOffset(x, y)
        o.Size = UDim2.fromOffset(w, h)
    end
    local function labels(o)
        local list = {}
        for _, child in ipairs(o:GetChildren()) do
            if child:IsA("TextLabel") then table.insert(list, child) end
        end
        table.sort(list, function(a, b) return a.Position.Y.Offset < b.Position.Y.Offset end)
        return list
    end
    local function master(o, y, button, secondary)
        place(o, 12, y, 376, 128)
        local text = labels(o)
        if text[1] then place(text[1], 16, 10, 344, 22) end
        if text[2] then
            place(text[2], 16, 36, 344, 34)
            text[2].TextWrapped = true
            text[2].TextSize = 13
        end
        place(button, secondary and 196 or 16, 82, secondary and 164 or 344, 32)
        if secondary then place(secondary, 16, 82, 168, 32) end
    end
    for _, page in ipairs({TerminalPage, PlayersPage, SettingsPage, HitboxPage,
        EspPage, CameraSystem.UI.Page, VisionSystem.UI.Page}) do
        page.CanvasSize = UDim2.fromOffset(0, 0)
        page.AutomaticCanvasSize = Enum.AutomaticSize.Y
        page.ScrollBarThickness = 3
        page.ScrollBarImageColor3 = THEME.Muted
        page.ScrollingDirection = Enum.ScrollingDirection.Y
        page.BorderSizePixel = 0
        page.ClipsDescendants = true
        page.Active = true
    end

    place(ConsolePanel, 12, 38, 376, 190)
    place(CommandBar, 12, 238, 376, 42)
    place(SuggestionFrame, 12, 230, 376, 0)
    place(QuickPanel, 12, 292, 376, 236)
    place(OpenTPButton, 10, 44, 174, 62)
    place(ShowCmdsButton, 192, 44, 174, 62)
    place(RuntimeCard, 10, 118, 356, 104)
    for _, button in ipairs({OpenTPButton, ShowCmdsButton}) do
        local text = labels(button)
        if text[1] then place(text[1], 12, 9, 150, 20) end
        if text[2] then
            place(text[2], 12, 29, 150, 28)
            text[2].TextWrapped = true
        end
    end
    place(RuntimeKeyLabel, 12, 68, 332, 26)
    CommandBox.PlaceholderText = "Comando... (cmds para ayuda)"

    -- La lista ocupa una sola columna y conserva TP, busqueda y teclas.
    PlayersPage.ScrollingEnabled = false
    place(SearchBar, 12, 38, 266, 40)
    place(RefreshPlayersButton, 286, 38, 102, 40)
    place(PlayerCount, 12, 86, 376, 18)
    PlayerList.Position = UDim2.fromOffset(12, 112)
    PlayerList.Size = UDim2.new(1, -24, 1, -120)
    PlayerGrid.CellSize = UDim2.new(1, -6, 0, 76)
    PlayerGrid.CellPadding = UDim2.fromOffset(0, 8)
    PlayerGrid.FillDirectionMaxCells = 1

    master(HitboxStatusPanel, 38, HitboxToggleButton, HitboxVisualButton)
    for index, name in ipairs({"legs", "feet", "body", "head"}) do
        local card = HitboxSystem.UI.Regions[name].Card
        place(card, 12, 178 + (index - 1) * 100, 376, 88)
        for _, text in ipairs(labels(card)) do
            if text.TextSize < 10 then text.TextSize = 12 end
        end
    end
    master(EspMasterPanel, 38, EspMasterButton)
    local espCards = {EspLinesButton.Parent, EspBoxesButton.Parent, EspSkeletonButton.Parent, RearAlertButton.Parent}
    for index, card in ipairs(espCards) do
        place(card, 12, 178 + (index - 1) * 96, 376, 84)
        for _, text in ipairs(labels(card)) do
            if text.TextSize < 10 then text.TextSize = 12 end
        end
    end

    master(CameraSystem.UI.MasterPanel, 38, CameraSystem.UI.Master, CameraSystem.UI.TeamCheck)
    local cameraCards = {CameraSystem.UI.FovCard, CameraSystem.UI.ZoneCard,
        CameraSystem.UI.ModeCard, CameraSystem.UI.StatusCard}
    for index, card in ipairs(cameraCards) do
        place(card, 12, 178 + (index - 1) * 104 + (index > 1 and 82 or 0), 376, index == 1 and 174 or 92)
    end
    local fovLabels = labels(CameraSystem.UI.FovCard)
    if fovLabels[1] then place(fovLabels[1], 14, 10, 198, 22) end
    if fovLabels[2] then
        place(fovLabels[2], 14, 34, 194, 44)
        fovLabels[2].TextWrapped = true
        fovLabels[2].TextSize = 12
    end
    place(CameraSystem.UI.FovToggle, 222, 12, 140, 32)
    place(CameraSystem.UI.DistanceCard, 12, 676, 376, 100)
    for _, child in ipairs(CameraSystem.UI.DistanceCard:GetChildren()) do
        if child:IsA("GuiObject") or child:IsA("TextLabel") or child:IsA("TextButton") or child:IsA("TextBox") or child:IsA("Frame") then
            local x = child.Position.X.Offset
            if x >= 378 then
                child.Position = UDim2.fromOffset(x - 364, child.Position.Y.Offset + 50)
            elseif x == 362 then
                place(child, 14, 48, 348, 1)
            end
        end
    end
    place(CameraSystem.UI.IntensityMinus, 216, 57, 28, 28)
    place(CameraSystem.UI.IntensityValue, 248, 57, 72, 28)
    place(CameraSystem.UI.IntensityPlus, 324, 57, 28, 28)
    local distanceLabels = labels(CameraSystem.UI.DistanceCard)
    for _, text in ipairs(distanceLabels) do
        if string.find(text.Text, "INTENSIDAD", 1, true) then
            text.Text = "Suavidad (%)"
            place(text, 14, 50, 196, 40)
            text.TextSize = 13
        end
    end
    for _, panel in ipairs({KeyPanel, EspMasterPanel}) do
        for _, child in ipairs(panel:GetChildren()) do
            if child:IsA("Frame") and child.Size.X.Offset == 3 and child.Size.X.Scale == 0 then
                child.Visible = false
            end
        end
    end
    -- Campos de ajustes en orden: apariencia, tecla y ayuda.
    place(AppearancePanel, 12, 38, 376, 274)
    place(KeyPanel, 12, 324, 376, 164)
    place(HelpPanel, 12, 500, 376, 160)
    local keyLabels = labels(KeyPanel)
    if keyLabels[1] then place(keyLabels[1], 18, 14, 340, 22) end
    for _, text in ipairs(labels(HelpPanel)) do
        if text.Position.X.Offset >= 146 then
            text.Size = UDim2.fromOffset(212, 36)
            text.TextWrapped = true
        end
    end
end

-- Transparencia del fondo; el texto y los indicadores conservan su contraste.
Compact.UI.TransparencyTitle = create("TextLabel", {
    Position = UDim2.fromOffset(18, 174), Size = UDim2.fromOffset(240, 24),
    BackgroundTransparency = 1, Text = "Transparencia del menu", TextColor3 = THEME.Text,
    Font = Enum.Font.BuilderSansBold, TextSize = 13, TextXAlignment = Enum.TextXAlignment.Left,
}, AppearancePanel)
Compact.UI.TransparencyValue = create("TextBox", {
    Position = UDim2.new(1, -88, 0, 170), Size = UDim2.fromOffset(70, 28),
    BackgroundColor3 = THEME.Input, BorderSizePixel = 0, Text = "20%",
    TextColor3 = THEME.White, Font = Enum.Font.BuilderSansBold, TextSize = 13,
    ClearTextOnFocus = false,
}, AppearancePanel)
corner(Compact.UI.TransparencyValue, 6)
create("TextLabel", {
    Position = UDim2.fromOffset(18, 204), Size = UDim2.new(1, -36, 0, 26),
    BackgroundTransparency = 1, Text = "0% solido · 85% mas transparente",
    TextColor3 = THEME.Muted, Font = Enum.Font.BuilderSans, TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
}, AppearancePanel)
Compact.UI.TransparencyTrack = create("Frame", {
    Position = UDim2.fromOffset(22, 238), Size = UDim2.new(1, -44, 0, 24),
    BackgroundTransparency = 1, Active = true, BorderSizePixel = 0,
}, AppearancePanel)
Compact.UI.TransparencyRail = create("Frame", {
    Position = UDim2.fromOffset(0, 9), Size = UDim2.new(1, 0, 0, 6),
    BackgroundColor3 = THEME.Border, BorderSizePixel = 0,
}, Compact.UI.TransparencyTrack)
corner(Compact.UI.TransparencyRail, 3)
Compact.UI.TransparencyFill = create("Frame", {
    Size = UDim2.fromScale(0.2 / 0.85, 1), BackgroundColor3 = THEME.Accent, BorderSizePixel = 0,
}, Compact.UI.TransparencyRail)
corner(Compact.UI.TransparencyFill, 3)
Compact.UI.TransparencyKnob = create("Frame", {
    AnchorPoint = Vector2.new(0.5, 0.5), Position = UDim2.fromScale(0.2 / 0.85, 0.5),
    Size = UDim2.fromOffset(14, 14), BackgroundColor3 = THEME.White, BorderSizePixel = 0,
}, Compact.UI.TransparencyTrack)
corner(Compact.UI.TransparencyKnob, 7)

Compact.registerSurface = function(object)
    if not Compact.Ready or not object.Parent then return end
    if object:GetAttribute("ColorSwatch") then return end
    if object ~= Main and not object:IsDescendantOf(Main) then return end
    local frame = (object == Main or object:IsA("Frame")) and (object.Size.Y.Offset >= 26 or object.Size.Y.Scale > 0)
    if not (frame or object == Compact.UI.NavBrand or object:IsA("TextButton") or object:IsA("TextBox") or object:IsA("ImageLabel")) then return end
    if object.BackgroundTransparency >= 1 then return end
    local base = Compact.Surfaces[object]
    if base == nil then
        base = object.BackgroundTransparency
        Compact.Surfaces[object] = base
    end
    object.BackgroundTransparency = base + (1 - base) * Compact.Transparency
end

-- Guarda el fondo de cada estado para que seleccionar o pasar el cursor
-- no vuelva a dejar opaca una opcion de la barra lateral.
Compact.surfaceTarget = function(object, base)
    Compact.Surfaces[object] = base
    return base + (1 - base) * Compact.Transparency
end

Compact.setTransparency = function(value, save)
    local numeric = tonumber(value)
    if not numeric or numeric ~= numeric then numeric = Compact.Transparency end
    Compact.Transparency = math.clamp(math.floor(numeric * 100 + 0.5) / 100, 0, 0.85)
    if Compact.updateNavAppearance then Compact.updateNavAppearance() end
    for object, base in pairs(Compact.Surfaces) do
        if object.Parent then object.BackgroundTransparency = base + (1 - base) * Compact.Transparency end
    end
    Compact.UI.TransparencyValue.Text = tostring(math.floor(Compact.Transparency * 100 + 0.5)) .. "%"
    local ratio = Compact.Transparency / 0.85
    Compact.UI.TransparencyFill.Size = UDim2.fromScale(ratio, 1)
    Compact.UI.TransparencyKnob.Position = UDim2.fromScale(ratio, 0.5)
    runtimeConfig.MenuTransparency = Compact.Transparency
    if save ~= false then AutoSave.queueConfigSave() end
end

Compact.initializeTransparency = function()
    Compact.Ready = true
    Compact.registerSurface(Main)
    for _, object in ipairs(Main:GetDescendants()) do Compact.registerSurface(object) end
    Compact.setTransparency(tonumber(runtimeConfig.MenuTransparency) or 0.2, false)
end

connect(Compact.UI.TransparencyValue.FocusLost, function()
    local text = string.gsub(Compact.UI.TransparencyValue.Text, "%%", "")
    local numeric = tonumber((string.gsub(text, ",", ".")))
    Compact.setTransparency(numeric and numeric / 100 or Compact.Transparency)
end)
Compact.moveTransparency = function(input)
    local track = Compact.UI.TransparencyTrack
    if track.AbsoluteSize.X <= 0 then return end
    local ratio = math.clamp((input.Position.X - track.AbsolutePosition.X) / track.AbsoluteSize.X, 0, 1)
    Compact.setTransparency(ratio * 0.85)
end
connect(Compact.UI.TransparencyTrack.InputBegan, function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        Compact.TransparencyInput = input
        Compact.moveTransparency(input)
    end
end)
connect(UserInputService.InputChanged, function(input)
    local drag = Compact.TransparencyInput
    if drag and (input == drag or (drag.UserInputType == Enum.UserInputType.MouseButton1
        and input.UserInputType == Enum.UserInputType.MouseMovement)) then Compact.moveTransparency(input) end
end)
connect(UserInputService.InputEnded, function(input)
    if input == Compact.TransparencyInput then Compact.TransparencyInput = nil end
end)
connect(UserInputService.WindowFocusReleased, function() Compact.TransparencyInput = nil end)


Compact.applyReadableLayout = function()
    local function fix(parent)
        for _, object in ipairs(parent:GetDescendants()) do
            if object:IsA("TextLabel") or object:IsA("TextButton") or object:IsA("TextBox") then
                object.TextTransparency = 0
                object.TextSize = math.max(13, object.TextSize)
                if object:IsA("TextLabel") and object.TextXAlignment == Enum.TextXAlignment.Left
                    and object.Size.Y.Offset >= 26 then object.TextWrapped = true end
            end
        end
    end
    fix(Main)
    -- Field values and section names carry the strongest text hierarchy.
    Compact.UI.Breadcrumb.TextSize = 14
    Compact.UI.TransparencyValue.TextSize = 15
    Compact.UI.TransparencyTitle.TextSize = 15
    Compact.UI.TransparencyTitle.Size = UDim2.fromOffset(250, 24)
    AutoSave.UI.WindowScaleValue.TextSize = 14
    PlayerSearch.TextSize = 14
    CommandBox.TextSize = 14
    CurrentKey.TextSize = 15
    local fields = {CameraSystem.UI.DistanceValue, CameraSystem.UI.IntensityValue,
        CameraSystem.UI.FovValue, VisionSystem.UI.ZoomValue}
    for _, field in ipairs(fields) do field.TextSize = 14 end
    for _, region in pairs(HitboxSystem.UI.Regions) do region.Value.TextSize = 14 end
    -- More room for instructions instead of ellipses or tiny text.
    for _, parent in ipairs({KeyPanel, HelpPanel, AppearancePanel, RuntimeCard}) do
        for _, text in ipairs(parent:GetChildren()) do
            if text:IsA("TextLabel") and text.TextXAlignment == Enum.TextXAlignment.Left
                and text.TextColor3 == THEME.Muted then text.TextWrapped = true end
        end
    end
end

-- Estado de la key dentro del menu: sin ventanas flotantes adicionales.
Compact.UI.LicenseStatus = create("Frame", {
    Name = "LicenseStatus", Position = UDim2.new(0, 12, 1, -46),
    Size = UDim2.new(1, -24, 0, 38), BackgroundColor3 = THEME.Panel,
    BorderSizePixel = 0, Visible = false,
}, Main)
corner(Compact.UI.LicenseStatus, 7)
Compact.UI.LicenseDot = create("Frame", {
    Position = UDim2.fromOffset(10, 10), Size = UDim2.fromOffset(5, 5),
    BackgroundColor3 = THEME.AccentText, BorderSizePixel = 0,
}, Compact.UI.LicenseStatus)
corner(Compact.UI.LicenseDot, 3)
Compact.UI.LicenseRemaining = create("TextLabel", {
    Name = "KeyRemaining", Position = UDim2.fromOffset(24, 2), Size = UDim2.new(1, -34, 0, 19),
    BackgroundTransparency = 1, Text = "Key activa", TextColor3 = THEME.White,
    Font = Enum.Font.BuilderSansBold, TextSize = 15, TextXAlignment = Enum.TextXAlignment.Left,
}, Compact.UI.LicenseStatus)
Compact.UI.LicenseExpiry = create("TextLabel", {
    Name = "KeyExpiry", Position = UDim2.fromOffset(24, 20), Size = UDim2.new(1, -34, 0, 16),
    BackgroundTransparency = 1, Text = "", TextColor3 = THEME.Muted,
    Font = Enum.Font.BuilderSans, TextSize = 13, TextXAlignment = Enum.TextXAlignment.Left,
}, Compact.UI.LicenseStatus)
Compact.updateLicense = function(status)
    if destroyed or not status then return end
    Compact.UI.LicenseStatus.Visible = true
    Body.Size = UDim2.new(1, Body.Size.X.Offset, 1, -104)
    Compact.UI.LicenseRemaining.Text = status.title
    Compact.UI.LicenseExpiry.Text = status.detail
    Compact.UI.NavSubtitle.Text = status.short
    local color = status.urgent and Color3.fromRGB(255, 204, 137) or THEME.AccentText
    Compact.UI.LicenseRemaining.TextColor3 = color
    Compact.UI.LicenseDot.BackgroundColor3 = color
end


local toggleKey = runtimeConfig.ToggleKey
if typeof(toggleKey) ~= "EnumItem" then
    toggleKey = Enum.KeyCode.Insert
end

local function keyLabel(keyCode)
    if keyCode == Enum.UserInputType.MouseButton1 then
        return "MOUSE 1"
    elseif keyCode == Enum.UserInputType.MouseButton2 then
        return "MOUSE 2"
    elseif keyCode == Enum.UserInputType.MouseButton3 then
        return "MOUSE 3"
    end
    local spaced = string.gsub(keyCode.Name, "(%l)(%u)", "%1 %2")
    return string.upper(spaced)
end

local activePage = tostring(runtimeConfig.ActivePage or "vision")
if activePage ~= "terminal"
    and activePage ~= "settings"
    and activePage ~= "players"
    and activePage ~= "hitbox"
    and activePage ~= "esp"
    and activePage ~= "camera"
    and activePage ~= "vision" then
    activePage = "terminal"
end
local menuAnimating = false
local minimized = false
local tpTabOpen = true
local hitboxTabOpen = true
local espTabOpen = true
local isBindingKey = false
local isBindingPlayerKey = false
local pendingBindingPlayer = nil
local playerKeybinds = {}
local boundKeyByUserId = {}
local playerKeyButtons = {}
local hitboxEnabled = runtimeConfig.HitboxEnabled == true
local hitboxVisible = runtimeConfig.HitboxVisible ~= false
HitboxSystem.Regions = {
    legs = {
        Label = "Piernas",
        Enabled = runtimeConfig.HitboxLegsEnabled ~= false,
        Size = tonumber(runtimeConfig.HitboxLegsSize)
            or tonumber(runtimeConfig.HitboxSize)
            or 4,
        EnabledKey = "HitboxLegsEnabled",
        SizeKey = "HitboxLegsSize",
    },
    feet = {
        Label = "Pies",
        Enabled = runtimeConfig.HitboxFeetEnabled == true,
        Size = tonumber(runtimeConfig.HitboxFeetSize) or 3,
        EnabledKey = "HitboxFeetEnabled",
        SizeKey = "HitboxFeetSize",
    },
    body = {
        Label = "Cuerpo",
        Enabled = runtimeConfig.HitboxBodyEnabled == true,
        Size = tonumber(runtimeConfig.HitboxBodySize) or 5,
        EnabledKey = "HitboxBodyEnabled",
        SizeKey = "HitboxBodySize",
    },
    head = {
        Label = "Cabeza",
        Enabled = runtimeConfig.HitboxHeadEnabled == true,
        Size = tonumber(runtimeConfig.HitboxHeadSize) or 4,
        EnabledKey = "HitboxHeadEnabled",
        SizeKey = "HitboxHeadSize",
    },
}
for _, region in pairs(HitboxSystem.Regions) do
    region.Size = math.clamp(math.floor(region.Size * 2 + 0.5) / 2, 1, 15)
end
local hitboxRefreshElapsed = 0
local originalHitboxStates = type(runtimeEnvironment.XTEYX_HitboxStates) == "table"
    and runtimeEnvironment.XTEYX_HitboxStates or setmetatable({}, {__mode = "k"})
runtimeEnvironment.XTEYX_HitboxStates = originalHitboxStates
local watchedHitboxPlayers = setmetatable({}, {__mode = "k"})
local espEnabled = runtimeConfig.EspEnabled == true
local espLinesEnabled = runtimeConfig.EspLines ~= false
local espBoxesEnabled = runtimeConfig.EspBoxes ~= false
local espSkeletonEnabled = runtimeConfig.EspSkeleton ~= false
local rearAlertEnabled = runtimeConfig.RearAlert ~= false
local rearAlertDistance = tonumber(runtimeConfig.RearAlertDistance) or 15
rearAlertDistance = math.clamp(math.floor(rearAlertDistance + 0.5), 5, 50)
local drawingAvailable = false
pcall(function()
    drawingAvailable = Drawing ~= nil and type(Drawing.new) == "function"
end)
local espEntries = {}
local EspSystem = {}
local rearAlertElapsed = 0
CameraSystem.Enabled = runtimeConfig.CameraEnabled == true
CameraSystem.TabOpen = true
if (activePage == "players" and not tpTabOpen)
    or (activePage == "hitbox" and not hitboxTabOpen)
    or (activePage == "esp" and not espTabOpen)
    or (activePage == "camera" and not CameraSystem.TabOpen)
    or (activePage == "vision" and not VisionSystem.TabOpen) then
    activePage = "terminal"
end
CameraSystem.FovVisible = runtimeConfig.CameraFovVisible ~= false
CameraSystem.FovRadius = math.clamp(
    math.floor((tonumber(runtimeConfig.CameraFovRadius) or 140) / 10 + 0.5) * 10,
    50,
    320
)
CameraSystem.MaxDistance = math.clamp(
    math.floor((tonumber(runtimeConfig.CameraMaxDistance) or 500) + 0.5),
    5,
    5000
)
CameraSystem.SmoothIntensity = math.clamp(
    math.floor((tonumber(runtimeConfig.CameraSmoothIntensity) or 35) + 0.5),
    1,
    100
)
CameraSystem.TargetZone = runtimeConfig.CameraTargetZone
if CameraSystem.TargetZone ~= "feet"
    and CameraSystem.TargetZone ~= "body"
    and CameraSystem.TargetZone ~= "head" then
    CameraSystem.TargetZone = "body"
end
CameraSystem.Mode = runtimeConfig.CameraMode == "hard" and "hard" or "smooth"
CameraSystem.ActivationMode = runtimeConfig.CameraActivationMode == "manual"
    and "manual" or "auto"
CameraSystem.ManualBehavior = runtimeConfig.CameraManualBehavior == "toggle"
    and "toggle" or "hold"
CameraSystem.Binding = runtimeConfig.CameraAimKey
if typeof(CameraSystem.Binding) ~= "EnumItem" then
    CameraSystem.Binding = Enum.KeyCode.Q
end
CameraSystem.IsBindingKey = false
CameraSystem.ManualHeld = false
CameraSystem.ManualToggled = false
CameraSystem.TargetPlayer = nil
CameraSystem.LastTargetUserId = nil
CameraSystem.TeamCheck = runtimeConfig.CameraTeamCheck ~= false
CameraSystem.TeamCache = setmetatable({}, {__mode = "k"})
CameraSystem.TeamSignalCache = setmetatable({}, {__mode = "k"})
AutoSave.WindowScale = math.clamp(
    tonumber(runtimeConfig.WindowScale) or 1,
    1,
    1.25
)
runtimeConfig.WindowScale = AutoSave.WindowScale
PlayerSearch.Text = tostring(runtimeConfig.TPSearch or "")
local responsiveScale = 1
local normalSize = UDim2.fromOffset(400, 454)
local currentToast = nil
local clearSuggestions
local refreshPlayerList

AutoSave.syncWindowScaleControls = function()
    local ratio = (AutoSave.WindowScale - 1) / 0.25
    AutoSave.UI.WindowScaleValue.Text = tostring(
        math.floor(AutoSave.WindowScale * 100 + 0.5)
    ) .. "%"
    AutoSave.UI.WindowScaleFill.Size = UDim2.new(ratio, 0, 1, 0)
    AutoSave.UI.WindowScaleKnob.Position = UDim2.new(ratio, 0, 0.5, 0)
end

local function syncHitboxControls()
    HitboxToggleButton.Text = hitboxEnabled and "Desactivar" or "Activar"
    HitboxToggleButton.BackgroundColor3 = hitboxEnabled and hitboxVisible and THEME.Accent or THEME.PanelAlt
    HitboxToggleButton.TextColor3 = hitboxEnabled and hitboxVisible and THEME.White or THEME.AccentText

    HitboxVisualButton.Text = hitboxVisible and "Ocultar" or "Mostrar"
    HitboxVisualButton.BackgroundColor3 = hitboxVisible and THEME.Accent or THEME.PanelAlt
    HitboxVisualButton.TextColor3 = hitboxVisible and THEME.White or THEME.Muted
    if HitboxSystem.UI.StatusText then
        HitboxSystem.UI.StatusText.Text = HitboxSystem.RepairMessage
            or not hitboxEnabled and "Apagada. Sin ampliacion."
            or not hitboxVisible and "En pausa. Mostrar vuelve a aplicar los tamanos."
            or "Activa. Ocultar restaura el cuerpo y pausa la ampliacion."
    end

    for regionName, region in pairs(HitboxSystem.Regions) do
        local controls = HitboxSystem.UI.Regions[regionName]
        controls.Value.Text = string.format("%.1f", region.Size)
        controls.Toggle.Text = region.Enabled and "Activa" or "Inactiva"
        controls.Toggle.BackgroundColor3 = region.Enabled and THEME.Accent or THEME.PanelAlt
        controls.Toggle.TextColor3 = region.Enabled and THEME.White or THEME.Muted
    end
end

local function styleEspToggle(button, state, enabledText, disabledText)
    button.Text = state and enabledText or disabledText
    button.BackgroundColor3 = state and THEME.Accent or THEME.PanelAlt
    button.TextColor3 = state and THEME.White or THEME.Muted
end

local function syncEspControls()
    styleEspToggle(EspMasterButton, espEnabled, "Desactivar", "Activar")
    styleEspToggle(EspLinesButton, espLinesEnabled, "Activas", "Inactivas")
    styleEspToggle(EspBoxesButton, espBoxesEnabled, "Activo", "Inactivo")
    styleEspToggle(EspSkeletonButton, espSkeletonEnabled, "Activo", "Inactivo")
    styleEspToggle(RearAlertButton, rearAlertEnabled, "Activa", "Inactiva")
    RearDistanceValue.Text = tostring(rearAlertDistance) .. " ST"

    if drawingAvailable then
        EspSupportLabel.Text = "Amigos verdes > companeros azules > enemigos blancos."
        EspSupportLabel.TextColor3 = THEME.Muted
    else
        EspSupportLabel.Text = "Este ejecutor no ofrece la API Drawing necesaria."
        EspSupportLabel.TextColor3 = THEME.Text
    end
end

CameraSystem.styleChoice = function(button, selected)
    button.BackgroundColor3 = selected and THEME.Accent or THEME.Input
    button.TextColor3 = selected and THEME.White or THEME.Muted
end

CameraSystem.isEngaged = function()
    if not CameraSystem.Enabled then
        return false
    end
    if CameraSystem.ActivationMode == "auto" then
        return true
    end
    if CameraSystem.ManualBehavior == "hold" then
        return CameraSystem.ManualHeld
    end
    return CameraSystem.ManualToggled
end

CameraSystem.isMouseButton = function(inputType)
    return inputType == Enum.UserInputType.MouseButton1
        or inputType == Enum.UserInputType.MouseButton2
        or inputType == Enum.UserInputType.MouseButton3
end

CameraSystem.matchesInput = function(input)
    if CameraSystem.Binding.EnumType == Enum.KeyCode then
        return input.KeyCode == CameraSystem.Binding
    end
    return input.UserInputType == CameraSystem.Binding
end

CameraSystem.pointerOverMenu = function(input)
    if not CameraSystem.isMouseButton(input.UserInputType) then return false end
    if not Main.Visible then
        if Compact.UI.Launcher and Compact.UI.Launcher.Visible then
            local pointer = UserInputService:GetMouseLocation()
            local pos, size = Compact.UI.Launcher.AbsolutePosition, Compact.UI.Launcher.AbsoluteSize
            return pointer.X >= pos.X and pointer.X <= pos.X + size.X
                and pointer.Y >= pos.Y and pointer.Y <= pos.Y + size.Y
        end
        return false
    end
    local pointer = UserInputService:GetMouseLocation()
    local position = Main.AbsolutePosition
    local size = Main.AbsoluteSize
    return pointer.X >= position.X
        and pointer.X <= position.X + size.X
        and pointer.Y >= position.Y
        and pointer.Y <= position.Y + size.Y
end

CameraSystem.syncControls = function()
    styleEspToggle(CameraSystem.UI.Master, CameraSystem.Enabled, "Desactivar", "Activar")
    styleEspToggle(
        CameraSystem.UI.TeamCheck,
        CameraSystem.TeamCheck,
        "TEAM CHECK: ON",
        "TEAM CHECK: OFF"
    )
    styleEspToggle(
        CameraSystem.UI.FovToggle,
        CameraSystem.FovVisible,
        "Visible",
        "Oculto"
    )
    CameraSystem.UI.FovValue.Text = tostring(CameraSystem.FovRadius) .. " PX"
    if not CameraSystem.UI.DistanceValue:IsFocused() then
        CameraSystem.UI.DistanceValue.Text = tostring(CameraSystem.MaxDistance)
    end
    if not CameraSystem.UI.IntensityValue:IsFocused() then
        CameraSystem.UI.IntensityValue.Text = tostring(CameraSystem.SmoothIntensity)
    end
    CameraSystem.styleChoice(CameraSystem.UI.Feet, CameraSystem.TargetZone == "feet")
    CameraSystem.styleChoice(CameraSystem.UI.Body, CameraSystem.TargetZone == "body")
    CameraSystem.styleChoice(CameraSystem.UI.Head, CameraSystem.TargetZone == "head")
    CameraSystem.styleChoice(CameraSystem.UI.Hard, CameraSystem.Mode == "hard")
    CameraSystem.styleChoice(CameraSystem.UI.Smooth, CameraSystem.Mode == "smooth")
    CameraSystem.styleChoice(CameraSystem.UI.Auto, CameraSystem.ActivationMode == "auto")
    CameraSystem.styleChoice(CameraSystem.UI.Manual, CameraSystem.ActivationMode == "manual")
    CameraSystem.styleChoice(CameraSystem.UI.Hold, CameraSystem.ManualBehavior == "hold")
    CameraSystem.styleChoice(CameraSystem.UI.Toggle, CameraSystem.ManualBehavior == "toggle")
    CameraSystem.UI.AimKey.Text = CameraSystem.IsBindingKey
        and "PRESIONA..." or ("TECLA: " .. keyLabel(CameraSystem.Binding))
    CameraSystem.UI.AimKey.BackgroundColor3 = CameraSystem.IsBindingKey
        and THEME.Accent or THEME.Input
    CameraSystem.UI.AimKey.TextColor3 = CameraSystem.IsBindingKey
        and THEME.White or THEME.Text
    CameraSystem.UI.CaptureShield.Visible = CameraSystem.IsBindingKey
    CameraSystem.UI.FovCircle.Size = UDim2.fromOffset(
        CameraSystem.FovRadius * 2,
        CameraSystem.FovRadius * 2
    )
    CameraSystem.UI.FovCircle.Visible = CameraSystem.Enabled and CameraSystem.FovVisible

    if not CameraSystem.Enabled then
        CameraSystem.UI.Support.Text = "Aim apagado. Configura el FOV y la activacion."
    elseif not CameraSystem.isEngaged() then
        local action = CameraSystem.ManualBehavior == "hold" and "manten" or "toca"
        CameraSystem.UI.Support.Text = string.upper(action)
            .. " " .. keyLabel(CameraSystem.Binding) .. " PARA APUNTAR"
    elseif CameraSystem.TargetPlayer then
        CameraSystem.UI.Support.Text = "OBJETIVO: "
            .. string.upper(CameraSystem.TargetPlayer.DisplayName)
    else
        CameraSystem.UI.Support.Text = CameraSystem.TeamCheck
            and "BUSCANDO ENEMIGO DENTRO DEL FOV..."
            or "BUSCANDO JUGADOR DENTRO DEL FOV..."
    end
    CameraSystem.UI.Support.TextColor3 = THEME.Muted
end

local function syncKeyLabels()
    local label = keyLabel(toggleKey)
    HeaderKey.Text = label
    CurrentKey.Text = label
    RuntimeKeyLabel.Text = "MINIMIZAR: " .. label
end

syncKeyLabels()
syncHitboxControls()
syncEspControls()
CameraSystem.syncControls()
AutoSave.syncWindowScaleControls()

local function addHover(button, normalColor, hoverColor)
    connect(button.MouseEnter, function()
        tween(button, 0.12, {BackgroundColor3 = hoverColor})
    end)
    connect(button.MouseLeave, function()
        tween(button, 0.12, {BackgroundColor3 = normalColor})
    end)
end

addHover(MinimizeButton, THEME.Panel, THEME.Hover)
addHover(ExecuteButton, THEME.Accent, THEME.AccentHover)
addHover(OpenTPButton, THEME.PanelAlt, THEME.Hover)
addHover(ShowCmdsButton, THEME.PanelAlt, THEME.Hover)
addHover(RefreshPlayersButton, THEME.PanelAlt, THEME.Hover)
addHover(ChangeKeyButton, THEME.Accent, THEME.AccentHover)
addHover(RearDistanceMinus, THEME.Input, THEME.Hover)
addHover(RearDistancePlus, THEME.Input, THEME.Hover)

connect(CloseTPTabButton.MouseEnter, function()
    tween(CloseTPTabButton, 0.12, {
        BackgroundTransparency = 0,
        TextColor3 = THEME.White,
    })
end)

connect(CloseTPTabButton.MouseLeave, function()
    tween(CloseTPTabButton, 0.12, {
        BackgroundTransparency = 1,
        TextColor3 = THEME.Muted,
    })
end)

connect(CloseHitboxTabButton.MouseEnter, function()
    tween(CloseHitboxTabButton, 0.12, {
        BackgroundTransparency = 0,
        TextColor3 = THEME.White,
    })
end)

connect(CloseHitboxTabButton.MouseLeave, function()
    tween(CloseHitboxTabButton, 0.12, {
        BackgroundTransparency = 1,
        TextColor3 = THEME.Muted,
    })
end)

connect(CloseEspTabButton.MouseEnter, function()
    tween(CloseEspTabButton, 0.12, {
        BackgroundTransparency = 0,
        TextColor3 = THEME.White,
    })
end)

connect(CloseEspTabButton.MouseLeave, function()
    tween(CloseEspTabButton, 0.12, {
        BackgroundTransparency = 1,
        TextColor3 = THEME.Muted,
    })
end)

connect(CameraSystem.UI.Close.MouseEnter, function()
    tween(CameraSystem.UI.Close, 0.12, {
        BackgroundTransparency = 0,
        TextColor3 = THEME.White,
    })
end)

connect(CameraSystem.UI.Close.MouseLeave, function()
    tween(CameraSystem.UI.Close, 0.12, {
        BackgroundTransparency = 1,
        TextColor3 = THEME.Muted,
    })
end)

local EDGE_MARGIN = 12

local function clampPositionToViewport(target, position)
    local camera = Workspace.CurrentCamera
    if not camera then
        return position
    end

    local viewport = camera.ViewportSize
    local scale = target == Main and MainScale.Scale or 1
    local renderedWidth = (
        target.Size.X.Scale * viewport.X + target.Size.X.Offset
    ) * scale
    local renderedHeight = (
        target.Size.Y.Scale * viewport.Y + target.Size.Y.Offset
    ) * scale

    local anchorX = target.AnchorPoint.X
    local anchorY = target.AnchorPoint.Y
    local desiredX = position.X.Scale * viewport.X + position.X.Offset
    local desiredY = position.Y.Scale * viewport.Y + position.Y.Offset

    local minimumX = EDGE_MARGIN + renderedWidth * anchorX
    local maximumX = viewport.X - EDGE_MARGIN - renderedWidth * (1 - anchorX)
    local minimumY = EDGE_MARGIN + renderedHeight * anchorY
    local maximumY = viewport.Y - EDGE_MARGIN - renderedHeight * (1 - anchorY)

    if minimumX > maximumX then
        desiredX = viewport.X * 0.5
    else
        desiredX = math.clamp(desiredX, minimumX, maximumX)
    end

    if minimumY > maximumY then
        desiredY = viewport.Y * 0.5
    else
        desiredY = math.clamp(desiredY, minimumY, maximumY)
    end

    return UDim2.new(
        position.X.Scale,
        desiredX - position.X.Scale * viewport.X,
        position.Y.Scale,
        desiredY - position.Y.Scale * viewport.Y
    )
end

local function keepMainOnScreen(animated)
    if not Main.Parent then
        return
    end

    local correctedPosition = clampPositionToViewport(Main, Main.Position)
    if animated then
        tween(Main, 0.2, {Position = correctedPosition})
    else
        Main.Position = correctedPosition
    end
end

local function makeDraggable(dragArea, target)
    local dragging = false
    local dragType = nil
    local dragStart = nil
    local startPosition = nil

    connect(dragArea.InputBegan, function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1
            or input.UserInputType == Enum.UserInputType.Touch then
            if menuAnimating then return end
            if dragArea == Header then
                local pointer = input.Position
                for _, control in ipairs({MinimizeButton, Compact.UI.SectionButton}) do
                    local p, size = control.AbsolutePosition, control.AbsoluteSize
                    if pointer.X >= p.X and pointer.X <= p.X + size.X
                        and pointer.Y >= p.Y and pointer.Y <= p.Y + size.Y then return end
                end
            end
            dragging = true
            dragType = input.UserInputType
            dragStart = input.Position
            startPosition = target.Position
        end
    end)

    connect(UserInputService.InputChanged, function(input)
        if menuAnimating or minimized then
            dragging = false
            dragType = nil
            return
        end
        if not dragging then
            return
        end

        local validMouse = dragType == Enum.UserInputType.MouseButton1
            and input.UserInputType == Enum.UserInputType.MouseMovement
        local validTouch = dragType == Enum.UserInputType.Touch
            and input.UserInputType == Enum.UserInputType.Touch

        if validMouse or validTouch then
            local delta = input.Position - dragStart
            local desiredPosition = UDim2.new(
                startPosition.X.Scale,
                startPosition.X.Offset + delta.X,
                startPosition.Y.Scale,
                startPosition.Y.Offset + delta.Y
            )
            target.Position = clampPositionToViewport(target, desiredPosition)
        end
    end)

    connect(UserInputService.InputEnded, function(input)
        if input.UserInputType == dragType
            or (dragType == Enum.UserInputType.MouseButton1
                and input.UserInputType == Enum.UserInputType.MouseButton1) then
            dragging = false
            dragType = nil
            if not menuAnimating and not minimized then keepMainOnScreen(true) end
        end
    end)
end

makeDraggable(Header, Main)

local function updateScale()
    local camera = Workspace.CurrentCamera
    if not camera then
        return
    end

    local viewport = camera.ViewportSize
    if Compact.resizeIntro then Compact.resizeIntro() end
    local fitted = math.min(
        1.25,
        (viewport.X - 24) / normalSize.X.Offset,
        (viewport.Y - 24) / normalSize.Y.Offset
    )
    responsiveScale = math.max(
        0.2,
        math.floor(math.min(AutoSave.WindowScale, fitted) * 100) / 100
    )

    if not menuAnimating then
        MainScale.Scale = responsiveScale
        task.defer(function()
            keepMainOnScreen(false)
            if Compact.UI.Launcher then
                Compact.UI.Launcher.Position = clampPositionToViewport(Compact.UI.Launcher, Compact.UI.Launcher.Position)
            end
        end)
    end
end

Compact.refreshViewport = function()
    updateScale()
    if menuAnimating then return end
    keepMainOnScreen(false)
end

local cameraConnection = nil
local function bindCamera()
    if cameraConnection then
        cameraConnection:Disconnect()
        cameraConnection = nil
    end

    if Workspace.CurrentCamera then
        cameraConnection = connect(
            Workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"),
            updateScale
        )
    end
    updateScale()
end

connect(Workspace:GetPropertyChangedSignal("CurrentCamera"), bindCamera)
bindCamera()

local function showToast(message)
    if destroyed then
        return
    end

    if currentToast then
        currentToast:Destroy()
        currentToast = nil
    end

    local toast = create("Frame", {
        AnchorPoint = Vector2.new(0.5, 1),
        Position = UDim2.new(0.5, 0, 1, 12),
        Size = UDim2.fromOffset(360, 44),
        BackgroundColor3 = THEME.Header,
        BorderSizePixel = 0,
        ZIndex = 50,
    }, ScreenGui)
    corner(toast, 4)
    stroke(toast, THEME.Accent, 0.2, 1)

    create("Frame", {
        Position = UDim2.fromOffset(0, 0),
        Size = UDim2.fromOffset(3, 44),
        BackgroundColor3 = THEME.Accent,
        BorderSizePixel = 0,
        ZIndex = 51,
    }, toast)

    create("TextLabel", {
        Position = UDim2.fromOffset(16, 0),
        Size = UDim2.new(1, -28, 1, 0),
        BackgroundTransparency = 1,
        Text = message,
        TextColor3 = THEME.Text,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
        ZIndex = 51,
    }, toast)

    currentToast = toast
    tween(toast, 0.22, {Position = UDim2.new(0.5, 0, 1, -18)})

    task.delay(2.2, function()
        if toast.Parent then
            tween(toast, 0.18, {Position = UDim2.new(0.5, 0, 1, 12)})
            task.wait(0.2)
            if toast.Parent then
                toast:Destroy()
            end
            if currentToast == toast then
                currentToast = nil
            end
        end
    end)
end

-- VISION: estados independientes del personaje y de la visibilidad del menu.
function VisionSystem.number(value, fallback, minimum, maximum)
    local result = tonumber(value)
    if not result or result ~= result or result == math.huge or result == -math.huge then
        result = fallback
    end
    return math.clamp(result, minimum, maximum)
end

function VisionSystem.sameValue(first, second)
    if type(first) == "number" and type(second) == "number" then
        return math.abs(first - second) <= 0.0001
    end
    return first == second
end

function VisionSystem.keyUsedByTP(binding)
    if not binding then return false end
    if playerKeybinds[binding] then return true end
    for _, stored in pairs(type(runtimeConfig.TPBindings) == "table" and runtimeConfig.TPBindings or {}) do
        if type(stored) == "table" and binding.EnumType == Enum.KeyCode and stored.Key == binding.Name then
            return true
        end
    end
    return false
end

function VisionSystem.validBinding(value)
    return typeof(value) == "EnumItem" and (
        (value.EnumType == Enum.KeyCode and value ~= Enum.KeyCode.Unknown
            and value ~= Enum.KeyCode.Escape)
        or CameraSystem.isMouseButton(value)
    )
end

VisionSystem.LightEnabled = false
VisionSystem.LightStrength = VisionSystem.number(runtimeConfig.VisionLightStrength, 2, 1, 5)
VisionSystem.LightStates = {}
VisionSystem.LightConnections = {}
VisionSystem.LightService = game:GetService("Lighting")
VisionSystem.LightEpoch = 0
VisionSystem.ZoomEnabled = runtimeConfig.ZoomEnabled ~= false
VisionSystem.ZoomFactor = VisionSystem.number(runtimeConfig.ZoomFactor, 4, 1.5, 15)
VisionSystem.ZoomBehavior = runtimeConfig.ZoomBehavior == "toggle" and "toggle" or "hold"
VisionSystem.ZoomBinding = VisionSystem.validBinding(runtimeConfig.ZoomBinding)
    and runtimeConfig.ZoomBinding or nil
VisionSystem.ZoomActive = false
VisionSystem.IsBindingKey = false

-- Una configuracion antigua nunca debe solapar el zoom con minimizar o CAM.
if not VisionSystem.ZoomBinding or VisionSystem.ZoomBinding == toggleKey
    or VisionSystem.ZoomBinding == CameraSystem.Binding
    or VisionSystem.keyUsedByTP(VisionSystem.ZoomBinding) then
    VisionSystem.ZoomBinding = nil
    if runtimeConfig.ZoomUnbound ~= true then
        for _, candidate in ipairs({Enum.KeyCode.C, Enum.KeyCode.Z, Enum.KeyCode.V, Enum.KeyCode.LeftAlt}) do
            if candidate ~= toggleKey and candidate ~= CameraSystem.Binding
                and not VisionSystem.keyUsedByTP(candidate) then
                VisionSystem.ZoomBinding = candidate
                break
            end
        end
    end
end

function VisionSystem.syncControls()
    styleEspToggle(VisionSystem.UI.LightToggle, VisionSystem.LightEnabled, "Desactivar", "Activar")
    styleEspToggle(VisionSystem.UI.ZoomToggle, VisionSystem.ZoomEnabled, "Activado", "Inactivo")
    CameraSystem.styleChoice(VisionSystem.UI.ZoomHold, VisionSystem.ZoomBehavior == "hold")
    CameraSystem.styleChoice(VisionSystem.UI.ZoomToggleMode, VisionSystem.ZoomBehavior == "toggle")
    VisionSystem.UI.LightValue.Text = string.format("%.1f / 5", VisionSystem.LightStrength)
    for _, entry in ipairs({
        {VisionSystem.UI.LightSlider, (VisionSystem.LightStrength - 1) / 4},
        {VisionSystem.UI.ZoomSlider, (VisionSystem.ZoomFactor - 1.5) / 13.5},
    }) do
        entry[1].Fill.Size = UDim2.fromScale(entry[2], 1)
        entry[1].Knob.Position = UDim2.fromScale(entry[2], 0.5)
    end
    if not VisionSystem.UI.ZoomValue:IsFocused() then
        VisionSystem.UI.ZoomValue.Text = string.format("%.1f", VisionSystem.ZoomFactor)
    end
    VisionSystem.UI.ZoomKey.Text = VisionSystem.IsBindingKey and "Pulsa una tecla..."
        or (VisionSystem.ZoomBinding and "TECLA: " .. keyLabel(VisionSystem.ZoomBinding) or "SIN TECLA: ASIGNAR")
    VisionSystem.UI.CaptureShield.Visible = VisionSystem.IsBindingKey
    VisionSystem.UI.ZoomStatus.Text = VisionSystem.ZoomActive and "Zoom activo"
        or (not VisionSystem.ZoomEnabled and "ZOOM APAGADO")
        or (VisionSystem.ZoomBehavior == "hold" and "Mantiene el zoom mientras presionas el control."
            or "Un toque acerca la imagen; el siguiente restaura la vista.")
end

function VisionSystem.lightTargets(object)
    if object == VisionSystem.LightService then
        local ambient = math.floor(150 + VisionSystem.LightStrength * 16)
        return {
            Brightness = VisionSystem.LightStrength,
            Ambient = Color3.fromRGB(ambient, ambient, ambient),
            OutdoorAmbient = Color3.fromRGB(ambient, ambient, ambient),
            GlobalShadows = false, ExposureCompensation = 0,
            EnvironmentDiffuseScale = 1, EnvironmentSpecularScale = 0,
            FogStart = 0, FogEnd = 1000000,
        }
    elseif object:IsA("Atmosphere") then
        return {Density = 0, Haze = 0, Glare = 0}
    elseif object:IsA("PostEffect") then
        return {Enabled = false}
    end
    return nil
end

function VisionSystem.inLightScope(object)
    local camera = Workspace.CurrentCamera
    return object == VisionSystem.LightService
        or object:IsDescendantOf(VisionSystem.LightService)
        or (camera and object:IsDescendantOf(camera))
end

function VisionSystem.applyLightState(object, state)
    if not VisionSystem.LightEnabled then return end
    local targets = VisionSystem.lightTargets(object)
    if not targets then return end
    for property, target in pairs(targets) do
        if state.Known[property] then
            pcall(function()
                local current = object[property]
                -- Guarda cambios nuevos del ambiente, nunca nuestras propias escrituras.
                if state.Applied[property] ~= nil and not VisionSystem.sameValue(current, state.Applied[property]) then
                    state.Original[property] = current
                end
                state.Applied[property] = target
                if not VisionSystem.sameValue(current, target) then object[property] = target end
            end)
        end
    end
end

function VisionSystem.restoreLightObject(object, state)
    disconnectPool(state.Connections)
    VisionSystem.LightStates[object] = nil
    for property, original in pairs(state.Original) do
        pcall(function()
            -- Si el juego cambio el valor justo antes de apagar, ya es el valor correcto.
            if VisionSystem.sameValue(object[property], state.Applied[property]) then object[property] = original end
        end)
    end
end

function VisionSystem.queueLightRefresh()
    if VisionSystem.LightQueued or not VisionSystem.LightEnabled then return end
    VisionSystem.LightQueued = true
    local epoch = VisionSystem.LightEpoch
    task.defer(function()
        if destroyed or epoch ~= VisionSystem.LightEpoch then return end
        VisionSystem.LightQueued = false
        if not VisionSystem.LightEnabled then return end
        for object, state in pairs(VisionSystem.LightStates) do
            if VisionSystem.inLightScope(object) then
                VisionSystem.applyLightState(object, state)
            else
                VisionSystem.restoreLightObject(object, state)
            end
        end
    end)
end

function VisionSystem.watchLightObject(object)
    if not VisionSystem.LightEnabled or VisionSystem.LightStates[object]
        or not VisionSystem.inLightScope(object) then return end
    local targets = VisionSystem.lightTargets(object)
    if not targets then return end
    local state = {Original = {}, Applied = {}, Known = {}, Connections = {}}
    VisionSystem.LightStates[object] = state
    for property in pairs(targets) do
        pcall(function()
            state.Original[property] = object[property]
            state.Known[property] = true
            connectPooled(state.Connections, object:GetPropertyChangedSignal(property), function()
                if VisionSystem.LightEnabled and not VisionSystem.sameValue(object[property], state.Applied[property]) then
                    state.Original[property] = object[property]
                    VisionSystem.queueLightRefresh()
                end
            end)
        end)
    end
    if object ~= VisionSystem.LightService then
        connectPooled(state.Connections, object.AncestryChanged, function()
            if not VisionSystem.inLightScope(object) then
                VisionSystem.restoreLightObject(object, state)
            end
        end)
    end
    VisionSystem.applyLightState(object, state)
end

function VisionSystem.watchLightRoot(root)
    if not root then return end
    for _, object in ipairs(root:GetDescendants()) do VisionSystem.watchLightObject(object) end
    connectPooled(VisionSystem.LightConnections, root.DescendantAdded, function(object)
        VisionSystem.watchLightObject(object)
    end)
end

function VisionSystem.refreshLightRoots()
    if not VisionSystem.LightEnabled then return end
    disconnectPool(VisionSystem.LightConnections)
    for object, state in pairs(VisionSystem.LightStates) do
        if not VisionSystem.inLightScope(object) then VisionSystem.restoreLightObject(object, state) end
    end
    VisionSystem.watchLightObject(VisionSystem.LightService)
    VisionSystem.watchLightRoot(VisionSystem.LightService)
    VisionSystem.watchLightRoot(Workspace.CurrentCamera)
    VisionSystem.queueLightRefresh()
end

function VisionSystem.setLightEnabled(enabled, quiet)
    enabled = enabled == true
    VisionSystem.LightEpoch = VisionSystem.LightEpoch + 1
    VisionSystem.LightQueued = false
    VisionSystem.LightEnabled = enabled
    if enabled then
        VisionSystem.refreshLightRoots()
    else
        disconnectPool(VisionSystem.LightConnections)
        for object, state in pairs(VisionSystem.LightStates) do
            VisionSystem.restoreLightObject(object, state)
        end
    end
    runtimeConfig.VisionLightEnabled = enabled
    AutoSave.queueConfigSave()
    VisionSystem.syncControls()
    if not quiet then
        showToast(enabled and "Iluminacion fija activada. Se mantiene al reaparecer."
            or "Iluminacion original restaurada.")
    end
end

function VisionSystem.setLightStrength(value)
    VisionSystem.LightStrength = math.floor(VisionSystem.number(value, VisionSystem.LightStrength, 1, 5) * 10 + 0.5) / 10
    runtimeConfig.VisionLightStrength = VisionSystem.LightStrength
    VisionSystem.queueLightRefresh()
    AutoSave.queueConfigSave()
    VisionSystem.syncControls()
end

function VisionSystem.zoomFov(base, factor)
    return math.clamp(math.deg(2 * math.atan(math.tan(math.rad(base) / 2) / factor)), 1, 120)
end

function VisionSystem.detachZoomCamera()
    local state = VisionSystem.ZoomCamera
    if not state then return end
    VisionSystem.ZoomCamera = nil
    disconnectPool(state.Connections)
    pcall(function()
        if VisionSystem.sameValue(state.Camera.FieldOfView, state.Applied) then
            state.Camera.FieldOfView = state.Base
        end
    end)
end

function VisionSystem.attachZoomCamera(camera)
    VisionSystem.detachZoomCamera()
    if not camera then return end
    local base = camera.FieldOfView
    local state = {Camera = camera, Base = base, Applied = base, Current = base, Connections = {}}
    VisionSystem.ZoomCamera = state
    connectPooled(state.Connections, camera:GetPropertyChangedSignal("FieldOfView"), function()
        if VisionSystem.ZoomCamera ~= state then return end
        local current = camera.FieldOfView
        if not VisionSystem.sameValue(current, state.Applied) then
            if VisionSystem.ZoomActive then
                -- Respeta el FOV nuevo que pide el juego (correr, ambiente, etc.).
                state.Base = current
            else
                -- Durante la salida, un cambio externo tiene prioridad.
                VisionSystem.detachZoomCamera()
            end
        end
    end)
end

function VisionSystem.releaseZoom(immediate)
    VisionSystem.ZoomActive = false
    if immediate then VisionSystem.detachZoomCamera() end
    VisionSystem.syncControls()
end

function VisionSystem.startZoom()
    if not VisionSystem.ZoomEnabled or not Workspace.CurrentCamera then return end
    local state = VisionSystem.ZoomCamera
    if not state or state.Camera ~= Workspace.CurrentCamera then
        VisionSystem.attachZoomCamera(Workspace.CurrentCamera)
    end
    VisionSystem.ZoomActive = true
    VisionSystem.syncControls()
end

function VisionSystem.updateZoom(deltaTime)
    if destroyed then return end
    local state = VisionSystem.ZoomCamera
    if not state then return end
    if state.Camera ~= Workspace.CurrentCamera then
        local wasActive = VisionSystem.ZoomActive
        VisionSystem.detachZoomCamera()
        if wasActive then VisionSystem.attachZoomCamera(Workspace.CurrentCamera) end
        return
    end
    local target = VisionSystem.ZoomActive and VisionSystem.zoomFov(state.Base, VisionSystem.ZoomFactor) or state.Base
    state.Current = state.Current + (target - state.Current) * (1 - math.exp(-18 * math.clamp(deltaTime, 0, 0.1)))
    if math.abs(state.Current - target) < 0.02 then state.Current = target end
    state.Applied = state.Current
    if not VisionSystem.sameValue(state.Camera.FieldOfView, state.Current) then state.Camera.FieldOfView = state.Current end
    if not VisionSystem.ZoomActive and state.Current == state.Base then VisionSystem.detachZoomCamera() end
end

function VisionSystem.setZoomEnabled(enabled)
    VisionSystem.ZoomEnabled = enabled == true
    if not VisionSystem.ZoomEnabled then VisionSystem.releaseZoom(true) end
    runtimeConfig.ZoomEnabled = VisionSystem.ZoomEnabled
    AutoSave.queueConfigSave()
    VisionSystem.syncControls()
end

function VisionSystem.setZoomFactor(value)
    VisionSystem.ZoomFactor = math.floor(VisionSystem.number(value, VisionSystem.ZoomFactor, 1.5, 15) * 10 + 0.5) / 10
    runtimeConfig.ZoomFactor = VisionSystem.ZoomFactor
    AutoSave.queueConfigSave()
    VisionSystem.syncControls()
end

function VisionSystem.setZoomBehavior(behavior)
    VisionSystem.releaseZoom(true)
    VisionSystem.ZoomBehavior = behavior == "toggle" and "toggle" or "hold"
    runtimeConfig.ZoomBehavior = VisionSystem.ZoomBehavior
    AutoSave.queueConfigSave()
    VisionSystem.syncControls()
end

function VisionSystem.matchesInput(input)
    local binding = VisionSystem.ZoomBinding
    if not binding then return false end
    if binding.EnumType == Enum.KeyCode then
        return input.UserInputType == Enum.UserInputType.Keyboard and input.KeyCode == binding
    end
    return input.UserInputType == binding
end

function VisionSystem.cancelCapture()
    VisionSystem.IsBindingKey = false
    VisionSystem.syncControls()
end

function VisionSystem.captureInput(input)
    local keyboard = input.UserInputType == Enum.UserInputType.Keyboard
    if not keyboard and not CameraSystem.isMouseButton(input.UserInputType) then return end
    if keyboard and input.KeyCode == Enum.KeyCode.Escape then
        VisionSystem.cancelCapture()
        return
    end
    local binding = keyboard and input.KeyCode or input.UserInputType
    local remove = keyboard and (binding == Enum.KeyCode.Backspace or binding == Enum.KeyCode.Delete)
    if not remove and not VisionSystem.validBinding(binding) then return end
    if binding == toggleKey or binding == CameraSystem.Binding or playerKeybinds[binding] then
        showToast("Ese control ya pertenece al menu, CAM o TP. Elige otro.")
        return
    end
    VisionSystem.ZoomBinding = not remove and binding or nil
    runtimeConfig.ZoomBinding = VisionSystem.ZoomBinding
    runtimeConfig.ZoomUnbound = remove
    AutoSave.queueConfigSave()
    VisionSystem.cancelCapture()
end

function VisionSystem.handleZoomInput(input, gameProcessed)
    if gameProcessed or not VisionSystem.ZoomEnabled or not VisionSystem.matchesInput(input)
        or UserInputService:GetFocusedTextBox() or CameraSystem.pointerOverMenu(input) then return false end
    if VisionSystem.ZoomBehavior == "toggle" and VisionSystem.ZoomActive then
        VisionSystem.releaseZoom(false)
    else
        VisionSystem.startZoom()
    end
    return true
end

function VisionSystem.cleanup()
    VisionSystem.IsBindingKey = false
    VisionSystem.LightEnabled = false
    VisionSystem.LightEpoch = VisionSystem.LightEpoch + 1
    disconnectPool(VisionSystem.LightConnections)
    for object, state in pairs(VisionSystem.LightStates) do VisionSystem.restoreLightObject(object, state) end
    VisionSystem.ZoomActive = false
    VisionSystem.detachZoomCamera()
    RunService:UnbindFromRenderStep("CDT_Optifine_Zoom")
end


local pageData = {
    vision = {Page = VisionSystem.UI.Page, Tab = VisionSystem.UI.Tab, X = 202, Width = 88},
    terminal = {Page = TerminalPage, Tab = TerminalTab, X = 0, Width = 106},
    settings = {Page = SettingsPage, Tab = SettingsTab, X = 106, Width = 96},
    players = {Page = PlayersPage, Tab = PlayersTab, X = 202, Width = 88},
    hitbox = {Page = HitboxPage, Tab = HitboxTab, X = 290, Width = 88},
    esp = {Page = EspPage, Tab = EspTab, X = 290, Width = 88},
    camera = {
        Page = CameraSystem.UI.Page,
        Tab = CameraSystem.UI.Tab,
        X = 290,
        Width = 88,
    },
}

Compact.NavOrder = {"vision", "esp", "camera", "players", "hitbox", "terminal", "settings"}
Compact.NavMeta = {
    vision = {Title = "Luz y zoom", Words = "vision luz iluminacion brillo zoom aumento"},
    esp = {Title = "Indicadores ESP", Words = "esp indicadores lineas cajas esqueleto alerta colores rueda pasos proximidad"},
    camera = {Title = "Camara", Words = "camara aim objetivo seguimiento fov suavidad"},
    players = {Title = "Jugadores", Words = "jugadores tp teletransporte buscar personas teclas"},
    hitbox = {Title = "Hitbox por zonas", Words = "hitbox zonas piernas pies cuerpo cabeza tamano"},
    terminal = {Title = "Consola", Words = "consola terminal comandos cmds"},
    settings = {Title = "Ajustes", Words = "ajustes configuracion apariencia transparencia opacidad escala menu minimizar tecla"},
}
Compact.normalizeSearch = function(text)
    text = string.lower(tostring(text or ""))
    for _, pair in ipairs({{"á", "a"}, {"é", "e"}, {"í", "i"}, {"ó", "o"}, {"ú", "u"},
        {"Á", "a"}, {"É", "e"}, {"Í", "i"}, {"Ó", "o"}, {"Ú", "u"}}) do
        text = string.gsub(text, pair[1], pair[2])
    end
    return string.match(text, "^%s*(.-)%s*$") or ""
end
Compact.updateNavAppearance = function()
    for name, data in pairs(pageData) do
        if data.NavAnimation then data.NavAnimation:Cancel() end
        local selected = name == activePage
        data.Tab.TextColor3 = selected and THEME.White or THEME.Muted
        if data.Label then data.Label.TextColor3 = data.Tab.TextColor3 end
        data.Tab.BackgroundColor3 = THEME.PanelAlt
        data.Tab.BackgroundTransparency = Compact.surfaceTarget(data.Tab, selected and 0 or 1)
        if data.Icon then Compact.tintIcon(data.Icon, selected and THEME.White or THEME.Dim) end
    end
end
Compact.filterNavigation = function()
    local query = Compact.normalizeSearch(Compact.UI.NavSearch.Text)
    local filtered = query ~= ""
    local shown = 0
    Compact.FirstNavMatch = nil
    Compact.UI.VisualGroup.Visible = not filtered
    Compact.UI.ActionGroup.Visible = not filtered
    Compact.UI.NavFooter.Visible = not filtered
    for _, name in ipairs(Compact.NavOrder) do
        local data = pageData[name]
        local match = not filtered
        if filtered then
            match = true
            for word in string.gmatch(query, "%S+") do
                if not string.find(Compact.NavMeta[name].Words, word, 1, true) then match = false; break end
            end
        end
        data.Tab.Visible = match
        if filtered then
            data.Tab.Parent = AutoSave.WindowTabs
            if match then
                data.Y = shown * 36
                data.Tab.Position = UDim2.fromOffset(0, data.Y)
                shown = shown + 1
                Compact.FirstNavMatch = Compact.FirstNavMatch or name
            end
        elseif name == "settings" then
            data.Tab.Parent = Compact.UI.NavFooter
            data.Tab.Position = UDim2.fromOffset(0, 8)
        else
            data.Tab.Parent = AutoSave.WindowTabs
            data.Tab.Position = UDim2.fromOffset(0, data.BaseY)
            shown = shown + 1
            Compact.FirstNavMatch = Compact.FirstNavMatch or name
        end
    end
    Compact.UI.EmptySearch.Visible = filtered and shown == 0
    AutoSave.WindowTabs.CanvasSize = UDim2.fromOffset(0, filtered and math.max(54, shown * 36) or 270)
    AutoSave.WindowTabs.CanvasPosition = Vector2.new(0, 0)
end
local function layoutVisualTabs()
    local positions = {vision = 22, esp = 58, camera = 94, players = 164, hitbox = 200, terminal = 236, settings = 8}
    for _, name in ipairs(Compact.NavOrder) do
        local data = pageData[name]
        data.X = 0
        data.Y = positions[name]
        data.BaseY = positions[name]
        data.Title = Compact.NavMeta[name].Title
        data.Tab.Size = UDim2.new(1, -4, 0, 32)
        data.Tab.Text = ""
        data.Tab.TextSize = 14
        data.Tab.Font = Enum.Font.BuilderSansMedium
        data.Tab.ZIndex = 62
        local inset = data.Tab:FindFirstChildOfClass("UIPadding")
        if inset then inset:Destroy() end
        if not data.Icon then data.Icon = Compact.makeIcon(data.Tab, name, 10, 8, 16, THEME.Muted) end
        if not data.Label then
            data.Label = create("TextLabel", {
                Name = "NavLabel", Position = UDim2.fromOffset(36, 0), Size = UDim2.new(1, -44, 1, 0),
                BackgroundTransparency = 1, Text = data.Title, TextColor3 = THEME.Muted,
                Font = Enum.Font.BuilderSansMedium, TextSize = 14, TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 63,
            }, data.Tab)
        end
    end
    TabIndicator.Visible = false
    for _, button in ipairs({CloseTPTabButton, CloseHitboxTabButton, CloseEspTabButton,
        CameraSystem.UI.Close, VisionSystem.UI.Close}) do button.Visible = false end
    Compact.UI.Breadcrumb.Text = "X.T.E.Y.X / " .. Compact.NavMeta[activePage].Title
    Compact.filterNavigation()
    Compact.updateNavAppearance()
end
Compact.setNavigationOpen = function(open, immediate)
    if menuAnimating and not immediate then return end
    open = open == true
    Compact.NavExpanded = open
    Compact.UI.ToggleOpenIcon.Visible = not open
    Compact.UI.ToggleCloseIcon.Visible = open
    -- El mismo boton permanece accesible con la barra abierta o plegada.
    Compact.UI.SectionButton.Parent = open and Compact.UI.Navigation or Header
    Compact.UI.SectionButton.Position = open and UDim2.fromOffset(178, 12) or UDim2.fromOffset(10, 8)
    Compact.UI.SectionButton.ZIndex = open and 64 or 40
    Compact.UI.Breadcrumb.Position = UDim2.fromOffset(open and 12 or 50, 10)
    Compact.UI.Breadcrumb.Size = UDim2.fromOffset(open and 262 or 224, 22)
    if not open then
        Compact.UI.NavSearch:ReleaseFocus()
        if Compact.UI.NavSearch.Text ~= "" then
            Compact.UI.NavSearch.Text = ""
            if pageData.vision.BaseY then Compact.filterNavigation() end
        end
    end
    local camera = Workspace.CurrentCamera
    local available = camera and camera.ViewportSize.X or 1920
    local overlay = open and available < 640 * AutoSave.WindowScale
    local offset = open and not overlay and 216 or 0
    local sidebarWidth = open and 216 or 0
    normalSize = UDim2.fromOffset(400 + offset, 454)
    if Compact.NavAnimations then
        for _, animation in ipairs(Compact.NavAnimations) do animation:Cancel() end
    end
    Compact.NavAnimations = {}
    local targets = {
        {Object = Main, Props = {Size = normalSize}},
        {Object = Compact.UI.Navigation, Props = {Size = UDim2.new(0, sidebarWidth, 1, 0)}},
        {Object = Header, Props = {Position = UDim2.fromOffset(offset, 0), Size = UDim2.new(1, -offset, 0, 44)}},
        {Object = Body, Props = {Position = UDim2.fromOffset(offset, 52), Size = UDim2.new(1, -offset, 1, Compact.UI.LicenseStatus.Visible and -104 or -60)}},
        {Object = Compact.UI.LicenseStatus, Props = {Position = UDim2.new(0, offset + 12, 1, -46), Size = UDim2.new(1, -offset - 24, 0, 38)}},
    }
    for _, entry in ipairs(targets) do
        if immediate or not Main.Visible then
            for key, value in pairs(entry.Props) do entry.Object[key] = value end
        else
            table.insert(Compact.NavAnimations, tween(entry.Object, 0.16, entry.Props))
        end
    end
    if Compact.refreshViewport then Compact.refreshViewport() end
    Compact.NavRevision = (Compact.NavRevision or 0) + 1
    local revision = Compact.NavRevision
    task.delay(0.17, function()
        if destroyed or revision ~= Compact.NavRevision then return end
        if Compact.refreshViewport then Compact.refreshViewport() end
    end)
end
connect(Compact.UI.NavSearch:GetPropertyChangedSignal("Text"), function()
    if not pageData.vision.BaseY then return end
    Compact.filterNavigation()
end)
connect(Compact.UI.NavSearch.FocusLost, function(enterPressed)
    if enterPressed and Compact.FirstNavMatch and Compact.selectPage then
        Compact.selectPage(Compact.FirstNavMatch)
    end
end)


AutoSave.setWindowScale = function(value)
    local numericValue = tonumber(value)
    if not numericValue then
        return
    end
    AutoSave.WindowScale = math.clamp(
        math.floor(numericValue * 20 + 0.5) / 20,
        1,
        1.25
    )
    runtimeConfig.WindowScale = AutoSave.WindowScale
    AutoSave.syncWindowScaleControls()
    updateScale()
    AutoSave.queueConfigSave()
end

local function scrollTabIntoView(tabData)
    -- La barra lateral usa su propia lista desplazable.
end

local function switchPage(pageName)
    local nextData = pageData[pageName]
    if not nextData or destroyed then return end
    if clearSuggestions then clearSuggestions() end
    Compact.UI.NavSearch:ReleaseFocus()
    if Compact.UI.NavSearch.Text ~= "" then
        Compact.UI.NavSearch.Text = ""
        Compact.filterNavigation()
    end
    Compact.UI.Breadcrumb.Text = "X.T.E.Y.X / " .. nextData.Title
    -- Cancel stale transitions before showing the next page.
    for name, data in pairs(pageData) do
        if data.Animation then data.Animation:Cancel() end
        if data.NavAnimation then data.NavAnimation:Cancel() end
        data.Page.Visible = name == pageName
        data.Page.Position = UDim2.fromOffset(0, 0)
        data.NavAnimation = tween(data.Tab, 0.14, {
            TextColor3 = name == pageName and THEME.White or THEME.Muted,
            BackgroundTransparency = Compact.surfaceTarget(data.Tab, name == pageName and 0 or 1),
        })
    end
    if AutoSave.IndicatorAnimation then AutoSave.IndicatorAnimation:Cancel() end
    AutoSave.IndicatorAnimation = tween(TabIndicator, 0.18, {
        Position = UDim2.fromOffset(0, nextData.Y + 10), Size = UDim2.fromOffset(3, 20),
    })
    if activePage ~= pageName then
        nextData.Page.Position = UDim2.fromOffset(8, 0)
        nextData.Animation = tween(nextData.Page, 0.18, {Position = UDim2.fromOffset(0, 0)})
    end
    activePage = pageName
    Compact.updateNavAppearance()
    runtimeConfig.ActivePage = pageName
    scrollTabIntoView(nextData)
    AutoSave.queueConfigSave()
    if pageName == "players" and refreshPlayerList then refreshPlayerList(PlayerSearch.Text) end
end

Compact.selectPage = switchPage

-- El hover no altera el estado de las funciones.
for name, data in pairs(pageData) do
    connect(data.Tab.MouseEnter, function()
        if name ~= activePage then
            if data.NavAnimation then data.NavAnimation:Cancel() end
            data.NavAnimation = tween(data.Tab, 0.12, {BackgroundTransparency = Compact.surfaceTarget(data.Tab, 0.45)})
        end
    end)
    connect(data.Tab.MouseLeave, function()
        if data.NavAnimation then data.NavAnimation:Cancel() end
        data.NavAnimation = tween(data.Tab, 0.12, {BackgroundTransparency = Compact.surfaceTarget(data.Tab, name == activePage and 0 or 1)})
    end)
end

local function openTPVisual()
    tpTabOpen = true
    runtimeConfig.TPTabOpen = true
    layoutVisualTabs()
    if not minimized then
        PlayersTab.Visible = true
        CloseTPTabButton.Visible = false
    end
    switchPage("players")
end

local function closeTPVisual()
    isBindingPlayerKey = false
    pendingBindingPlayer = nil
    switchPage("terminal")
end

local function openHitboxVisual()
    hitboxTabOpen = true
    runtimeConfig.HitboxTabOpen = true
    layoutVisualTabs()
    if not minimized then
        HitboxTab.Visible = true
        CloseHitboxTabButton.Visible = false
    end
    switchPage("hitbox")
end

local function closeHitboxVisual()
    switchPage("terminal")
end

local function openEspVisual()
    espTabOpen = true
    runtimeConfig.EspTabOpen = true
    layoutVisualTabs()
    if not minimized then
        EspTab.Visible = true
        CloseEspTabButton.Visible = false
    end
    switchPage("esp")
end

local function closeEspVisual()
    switchPage("terminal")
end

CameraSystem.openVisual = function()
    CameraSystem.TabOpen = true
    runtimeConfig.CameraTabOpen = true
    layoutVisualTabs()
    if not minimized then
        CameraSystem.UI.Tab.Visible = true
        CameraSystem.UI.Close.Visible = false
    end
    switchPage("camera")
end

CameraSystem.closeVisual = function()
    switchPage("terminal")
end

function VisionSystem.openVisual()
    VisionSystem.TabOpen = true
    runtimeConfig.VisionTabOpen = true
    layoutVisualTabs()
    VisionSystem.UI.Tab.Visible = not minimized
    VisionSystem.UI.Close.Visible = false
    switchPage("vision")
end

function VisionSystem.closeVisual()
    VisionSystem.cancelCapture()
    switchPage("terminal")
end

-- Minimizado animado: un unico estado controla panel, iconos y clics rapidos.
Compact.Motion = {Duration = 0.32, Token = 0, Tweens = {}}
Compact.makeMenuGlyph = function(button, open)
    local glyph = {Bars = {}, Tweens = {}}
    for index = 1, 3 do
        local bar = create("Frame", {
            Name = "MenuLine" .. index, AnchorPoint = Vector2.new(0.5, 0.5),
            Position = UDim2.new(0.5, 0, 0.5, (index - 2) * 7),
            Size = UDim2.fromOffset(18, 2), Rotation = 0,
            BackgroundColor3 = THEME.White, BorderSizePixel = 0,
            ZIndex = button.ZIndex + 1,
        }, button)
        corner(bar, 2)
        glyph.Bars[index] = bar
    end
    glyph.Set = function(expanded, immediate)
        for _, animation in ipairs(glyph.Tweens) do animation:Cancel() end
        glyph.Tweens = {}
        local angles = {315, 45, 135}
        for index, bar in ipairs(glyph.Bars) do
            local properties = {
                Position = UDim2.new(0.5, 0, 0.5, expanded and 0 or (index - 2) * 7),
                Rotation = expanded and angles[index] or 0,
            }
            if immediate then
                for key, value in pairs(properties) do bar[key] = value end
            else
                table.insert(glyph.Tweens, tween(bar, 0.3, properties, Enum.EasingStyle.Back))
            end
        end
        button:SetAttribute("Expanded", expanded)
    end
    glyph.Set(open, true)
    return glyph
end
Compact.UI.HeaderGlyph = Compact.makeMenuGlyph(MinimizeButton, true)
Compact.UI.Launcher = create("TextButton", {
    Name = "XTEYX_Restore", AnchorPoint = Vector2.new(1, 0),
    Position = UDim2.new(1, -20, 0, 70), Size = UDim2.fromOffset(40, 40),
    BackgroundColor3 = THEME.Header, BorderSizePixel = 0, Text = "",
    AutoButtonColor = false, Visible = false, Active = true, Selectable = true, ZIndex = 100,
}, ScreenGui)
corner(Compact.UI.Launcher, 10)
stroke(Compact.UI.Launcher, THEME.AccentText, 0.05, 1.5)
Compact.UI.LauncherScale = create("UIScale", {Scale = 1}, Compact.UI.Launcher)
Compact.UI.LauncherGlyph = Compact.makeMenuGlyph(Compact.UI.Launcher, false)
Compact.UI.LauncherHint = create("TextLabel", {
    Position = UDim2.fromOffset(-174, 5), Size = UDim2.fromOffset(166, 30),
    BackgroundColor3 = THEME.Header, BorderSizePixel = 0, Text = "X.T.E.Y.X · Abrir",
    TextColor3 = THEME.White, Font = Enum.Font.BuilderSansMedium, TextSize = 13,
    Visible = false, ZIndex = 102,
}, Compact.UI.Launcher)
corner(Compact.UI.LauncherHint, 6)
Compact.UI.MotionShield = create("TextButton", {
    Name = "TransitionShield", Size = UDim2.fromScale(1, 1), BackgroundTransparency = 1,
    BorderSizePixel = 0, Text = "", AutoButtonColor = false, Active = true,
    Visible = false, ZIndex = 200,
}, Main)
Compact.cancelMotion = function()
    Compact.Motion.Token = Compact.Motion.Token + 1
    for _, animation in ipairs(Compact.Motion.Tweens) do animation:Cancel() end
    Compact.Motion.Tweens = {}
    for _, glyph in ipairs({Compact.UI.HeaderGlyph, Compact.UI.LauncherGlyph}) do
        for _, animation in ipairs(glyph.Tweens) do animation:Cancel() end
        glyph.Tweens = {}
    end
end
Compact.motionTween = function(object, properties, duration, style)
    local animation = tween(object, duration or Compact.Motion.Duration, properties,
        style or Enum.EasingStyle.Cubic, style and Enum.EasingDirection.Out or Enum.EasingDirection.InOut)
    table.insert(Compact.Motion.Tweens, animation)
    return animation
end
Compact.clampWindowPosition = function(position)
    local camera = Workspace.CurrentCamera
    if not camera then return position end
    local viewport = camera.ViewportSize
    local width, height = normalSize.X.Offset * responsiveScale, normalSize.Y.Offset * responsiveScale
    local anchor = Main.AnchorPoint
    local x = position.X.Scale * viewport.X + position.X.Offset
    local y = position.Y.Scale * viewport.Y + position.Y.Offset
    x = math.clamp(x, 12 + width * anchor.X, math.max(12 + width * anchor.X, viewport.X - 12 - width * (1 - anchor.X)))
    y = math.clamp(y, 12 + height * anchor.Y, math.max(12 + height * anchor.Y, viewport.Y - 12 - height * (1 - anchor.Y)))
    return UDim2.new(position.X.Scale, x - position.X.Scale * viewport.X,
        position.Y.Scale, y - position.Y.Scale * viewport.Y)
end
local function setMinimized(state)
    if Compact.Intro and Compact.Intro.Active then Compact.finishIntro(); return end
    state = state == true
    if destroyed or minimized == state then return end
    local wasAnimating = menuAnimating
    if state and not wasAnimating then Compact.Motion.WindowPosition = Main.Position end
    Compact.cancelMotion()
    local token = Compact.Motion.Token
    minimized = state
    menuAnimating = true
    Compact.UI.MotionShield.Visible = true
    Compact.TransparencyInput = nil
    Compact.LauncherDrag = nil
    Compact.LauncherMoved = false
    if clearSuggestions then clearSuggestions() end
    -- Finish an in-flight sidebar resize, retaining its open/closed state.
    Compact.setNavigationOpen(Compact.NavExpanded, true)
    Compact.UI.Launcher.Position = clampPositionToViewport(Compact.UI.Launcher, Compact.UI.Launcher.Position)
    Compact.UI.LauncherHint.Visible = false
    Compact.UI.HeaderGlyph.Set(not state)
    Compact.UI.LauncherGlyph.Set(not state)
    local tinyScale = responsiveScale * 0.1
    if state then
        if not Compact.UI.Launcher.Visible then
            Compact.UI.LauncherGlyph.Set(true, true)
            Compact.UI.LauncherGlyph.Set(false)
            Compact.UI.Launcher.BackgroundTransparency = 1
            Compact.UI.LauncherScale.Scale = 0.7
        end
        Compact.UI.Launcher.Visible = true
        Compact.motionTween(Main, {Position = Compact.UI.Launcher.Position, GroupTransparency = 1})
        Compact.motionTween(MainScale, {Scale = tinyScale})
        Compact.motionTween(Compact.UI.Launcher, {BackgroundTransparency = 0})
        Compact.motionTween(Compact.UI.LauncherScale, {Scale = 1}, 0.3, Enum.EasingStyle.Back)
    else
        local destination = Compact.clampWindowPosition(Compact.Motion.WindowPosition or Main.Position)
        if not Main.Visible then
            Main.Position = Compact.UI.Launcher.Position
            MainScale.Scale = tinyScale
            Main.GroupTransparency = 1
        end
        Main.Visible = true
        Body.Visible = true
        Compact.motionTween(Main, {Position = destination, GroupTransparency = 0})
        Compact.motionTween(MainScale, {Scale = responsiveScale})
        Compact.motionTween(Compact.UI.Launcher, {BackgroundTransparency = 1})
        Compact.motionTween(Compact.UI.LauncherScale, {Scale = 0.7})
    end
    task.delay(Compact.Motion.Duration + 0.02, function()
        if destroyed or token ~= Compact.Motion.Token or not Main.Parent then return end
        Compact.Motion.Tweens = {}
        Main.Visible = not state
        Compact.UI.Launcher.Visible = state
        Compact.UI.MotionShield.Visible = false
        MainScale.Scale = responsiveScale
        Main.GroupTransparency = 0
        Compact.UI.Launcher.BackgroundTransparency = 0
        Compact.UI.LauncherScale.Scale = 1
        menuAnimating = false
        if not state then
            Main.Position = Compact.clampWindowPosition(Compact.Motion.WindowPosition or Main.Position)
            keepMainOnScreen(false)
        end
    end)
end
connect(Compact.UI.Launcher.MouseEnter, function()
    if menuAnimating then return end
    Compact.UI.LauncherHint.Visible = true
    tween(Compact.UI.Launcher, 0.12, {BackgroundColor3 = THEME.PanelAlt})
end)
connect(Compact.UI.Launcher.MouseLeave, function()
    Compact.UI.LauncherHint.Visible = false
    tween(Compact.UI.Launcher, 0.12, {BackgroundColor3 = THEME.Header})
end)
connect(Compact.UI.Launcher.InputBegan, function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        Compact.LauncherMoved = false
        if menuAnimating then return end
        Compact.LauncherDrag = {Input = input, Start = input.Position, Position = Compact.UI.Launcher.Position}
    end
end)
connect(UserInputService.InputChanged, function(input)
    local drag = Compact.LauncherDrag
    if not drag or menuAnimating then return end
    if input ~= drag.Input and not (drag.Input.UserInputType == Enum.UserInputType.MouseButton1
        and input.UserInputType == Enum.UserInputType.MouseMovement) then return end
    local dx, dy = input.Position.X - drag.Start.X, input.Position.Y - drag.Start.Y
    if dx * dx + dy * dy > 36 then Compact.LauncherMoved = true end
    if Compact.LauncherMoved then
        Compact.UI.LauncherHint.Visible = false
        Compact.UI.Launcher.Position = clampPositionToViewport(Compact.UI.Launcher,
            UDim2.new(drag.Position.X.Scale, drag.Position.X.Offset + dx, drag.Position.Y.Scale, drag.Position.Y.Offset + dy))
    end
end)
connect(UserInputService.InputEnded, function(input)
    if Compact.LauncherDrag and input == Compact.LauncherDrag.Input then Compact.LauncherDrag = nil end
end)
connect(UserInputService.WindowFocusReleased, function()
    Compact.LauncherDrag = nil
    Compact.LauncherMoved = true
end)
connect(Compact.UI.Launcher.Activated, function()
    if not Compact.LauncherMoved then setMinimized(not minimized) end
end)


-- Intro xTWENTYx: movimientos independientes inspirados en Dancing Letters.
-- https://chamaac.com/r/dancing-letters.json
Compact.Intro = {Played = false, Active = false, Token = 0, Tweens = {}}
Compact.introTween = function(object, duration, properties, style)
    local animation = tween(object, duration, properties, style or Enum.EasingStyle.Quad)
    table.insert(Compact.Intro.Tweens, animation)
    return animation
end
Compact.resizeIntro = function()
    local intro, camera = Compact.Intro, Workspace.CurrentCamera
    if intro.Active and intro.Scale and camera then
        intro.Scale.Scale = math.max(0.2, math.min(1,
            (camera.ViewportSize.X - 24) / 368, (camera.ViewportSize.Y - 24) / 156))
    end
end
Compact.stopIntro = function(reveal)
    local intro = Compact.Intro
    intro.Token = intro.Token + 1
    intro.Active = false
    intro.Finishing = false
    for _, animation in ipairs(intro.Tweens) do animation:Cancel() end
    intro.Tweens = {}
    if intro.Connection then intro.Connection:Disconnect(); intro.Connection = nil end
    if intro.Root then intro.Root:Destroy(); intro.Root = nil end
    intro.Scale = nil
    intro.Letters = nil
    if reveal and not destroyed and Main.Parent then
        minimized = false
        menuAnimating = false
        Main.Visible = true
        Body.Visible = true
        Main.GroupTransparency = 0
        MainScale.Scale = responsiveScale
        Compact.UI.MotionShield.Visible = false
        Compact.UI.Launcher.Visible = false
        Compact.setNavigationOpen(true, true)
        keepMainOnScreen(false)
    end
end
Compact.finishIntro = function()
    local intro = Compact.Intro
    if not intro.Active or intro.Finishing or destroyed then return end
    intro.Finishing = true
    intro.Token = intro.Token + 1
    local token = intro.Token
    for _, animation in ipairs(intro.Tweens) do animation:Cancel() end
    intro.Tweens = {}
    Main.Visible = true
    Main.GroupTransparency = 1
    MainScale.Scale = responsiveScale * 0.96
    Compact.UI.MotionShield.Visible = true
    Compact.introTween(Main, 0.3, {GroupTransparency = 0})
    Compact.introTween(MainScale, 0.3, {Scale = responsiveScale})
    Compact.introTween(intro.Root, 0.22, {GroupTransparency = 1})
    task.delay(0.32, function()
        if destroyed or not intro.Active or token ~= intro.Token or not ScreenGui.Parent then return end
        Compact.stopIntro(true)
    end)
end
Compact.startIntro = function()
    local intro = Compact.Intro
    if destroyed or intro.Played or not ScreenGui.Parent then return end
    intro.Played = true
    intro.Active = true
    intro.Finishing = false
    intro.Token = intro.Token + 1
    local token = intro.Token
    minimized = false
    menuAnimating = true
    Main.Visible = false
    Compact.UI.Launcher.Visible = false
    intro.Root = create("CanvasGroup", {
        Name = "XTWENTYx_Intro", AnchorPoint = Vector2.new(0.5, 0.5),
        Position = UDim2.fromScale(0.5, 0.5), Size = UDim2.fromOffset(368, 156),
        BackgroundColor3 = THEME.Header, BackgroundTransparency = 0.08,
        BorderSizePixel = 0, GroupTransparency = 1, ClipsDescendants = true, ZIndex = 250,
    }, ScreenGui)
    corner(intro.Root, 14)
    stroke(intro.Root, THEME.Border, 0.15, 1)
    intro.Scale = create("UIScale", {Scale = 1}, intro.Root)
    Compact.resizeIntro()
    local word = create("Frame", {
        Name = "DancingWord", AnchorPoint = Vector2.new(0.5, 0.5),
        Position = UDim2.new(0.5, 0, 0.5, -9), Size = UDim2.fromOffset(298, 88),
        BackgroundTransparency = 1, BorderSizePixel = 0, ZIndex = 251,
    }, intro.Root)
    create("TextLabel", {
        Name = "IntroHint", Position = UDim2.new(0, 12, 1, -36), Size = UDim2.new(1, -24, 0, 24),
        BackgroundTransparency = 1, Text = "Clic para continuar", TextColor3 = THEME.Muted,
        Font = Enum.Font.BuilderSansMedium, TextSize = 12, ZIndex = 251,
    }, intro.Root)
    local hitArea = create("TextButton", {
        Name = "SkipIntro", Size = UDim2.fromScale(1, 1), BackgroundTransparency = 1,
        BorderSizePixel = 0, Text = "", AutoButtonColor = false, Active = true, Selectable = true, ZIndex = 255,
    }, intro.Root)
    intro.Connection = hitArea.Activated:Connect(Compact.finishIntro)
    local function alive()
        return not destroyed and intro.Active and token == intro.Token
            and ScreenGui.Parent and intro.Root and intro.Root.Parent
    end
    -- Cada paso es una animacion finita: no quedan bucles activos tras la intro.
    local patterns = {
        {{0.12, 0, 0, 0, 1.18}, {0.12, 0, 0, 0, 0.88}, {0.14, 0, 0, 0, 1.07}, {0.16, 0, 0, 0, 1}},
        {{0.18, 0, 6, 35, 1}, {0.16, 0, -3, -14, 1}, {0.16, 0, 3, 18, 1}, {0.2, 0, 0, 0, 1}},
        {{0.13, 0, 8, 0, 0.84}, {0.2, 0, -20, 0, 1.12}, {0.22, 0, 0, 0, 1}},
        {{0.25, 0, -5, 160, 1.06}, {0.22, 0, -3, 220, 1}, {0.3, 0, 0, 360, 1}},
        {{0.13, -9, 0, 0, 1}, {0.13, 7, 0, 0, 1}, {0.13, -4, 0, 0, 1}, {0.18, 0, 0, 0, 1}},
        {{0.07, -3, -1, -5, 1}, {0.07, 3, 1, 5, 1}, {0.07, -2, -1, -3, 1}, {0.07, 2, 0, 3, 1}, {0.18, 0, 0, 0, 1}},
        {{0.2, 0, -2, 0, 1.22}, {0.16, 0, 0, 0, 0.96}, {0.16, 0, 0, 0, 1}},
        {{0.32, 0, -16, 0, 1.07}, {0.34, 0, 0, 0, 1}},
    }
    local widths = {24, 28, 40, 29, 33, 28, 28, 24}
    local cursor = 18
    intro.Letters = {}
    for index = 1, 8 do
        local x = cursor + widths[index] / 2
        cursor = cursor + widths[index] + 4
        local letter = create("TextLabel", {
            Name = "IntroLetter" .. index, AnchorPoint = Vector2.new(0.5, 0.5),
            Position = UDim2.fromOffset(x, 58), Size = UDim2.fromOffset(64, 72),
            BackgroundTransparency = 1, BorderSizePixel = 0,
            Text = string.sub("xTWENTYx", index, index), TextSize = 42,
            Font = Enum.Font.BuilderSansExtraBold, TextColor3 = (index == 1 or index == 8) and THEME.AccentText or THEME.White,
            TextTruncate = Enum.TextTruncate.None, Rotation = index % 2 == 0 and 6 or -6, ZIndex = 252,
        }, word)
        letter.TextTransparency = 1
        local scale = create("UIScale", {Scale = 0.8}, letter)
        intro.Letters[index] = letter
        task.delay(0.08 + (index - 1) * 0.035, function()
            if not alive() then return end
            Compact.introTween(letter, 0.22, {TextTransparency = 0})
            Compact.introTween(letter, 0.28, {Position = UDim2.fromOffset(x, 44), Rotation = 0}, Enum.EasingStyle.Back)
            Compact.introTween(scale, 0.28, {Scale = 1}, Enum.EasingStyle.Back)
        end)
        local function dance(step)
            if not alive() then return end
            local frame = patterns[index][step]
            if not frame then letter.Rotation = 0; return end
            Compact.introTween(letter, frame[1], {
                Position = UDim2.fromOffset(x + frame[2], 44 + frame[3]), Rotation = frame[4],
            })
            Compact.introTween(scale, frame[1], {Scale = frame[5]})
            task.delay(frame[1], function() dance(step + 1) end)
        end
        task.delay(0.7 + (index - 1) * 0.065, function() dance(1) end)
    end
    Compact.introTween(intro.Root, 0.2, {GroupTransparency = 0})
    task.delay(2.3, function()
        if alive() then Compact.finishIntro() end
    end)
end


-- La barra lateral no se cierra al usar los controles de la pagina.
connect(UserInputService.InputBegan, function(input)
    if not minimized and not menuAnimating and Compact.NavExpanded and input.KeyCode == Enum.KeyCode.Escape then
        Compact.setNavigationOpen(false)
    end
end)

local function logMessage(message, color)
    if destroyed then
        return
    end

    local textLines = {}
    for _, child in ipairs(Console:GetChildren()) do
        if child:IsA("TextLabel") then
            table.insert(textLines, child)
        end
    end

    if #textLines >= 70 then
        textLines[1]:Destroy()
    end

    local label = create("TextLabel", {
        Size = UDim2.new(1, -4, 0, 20),
        AutomaticSize = Enum.AutomaticSize.Y,
        BackgroundTransparency = 1,
        Text = message,
        TextColor3 = color or THEME.Text,
        Font = Enum.Font.BuilderSansMedium,
        TextSize = 13,
        TextWrapped = true,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextYAlignment = Enum.TextYAlignment.Top,
    }, Console)
    padding(label, 2, 2, 1, 1)

    task.defer(function()
        if Console.Parent then
            local bottom = math.max(0, ConsoleLayout.AbsoluteContentSize.Y - Console.AbsoluteSize.Y)
            Console.CanvasPosition = Vector2.new(0, bottom)
        end
    end)
end

local function getPlayer(query)
    if not query or query == "" then
        return nil
    end

    local search = string.lower(query)
    local partial = nil

    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer then
            local username = string.lower(player.Name)
            local displayName = string.lower(player.DisplayName)

            if username == search or displayName == search then
                return player
            end

            if not partial
                and (string.sub(username, 1, #search) == search
                    or string.sub(displayName, 1, #search) == search) then
                partial = player
            end
        end
    end

    return partial
end

local function teleportToPlayer(target)
    if not target or target.Parent ~= Players then
        return false, "El jugador ya no esta disponible."
    end

    local localCharacter = LocalPlayer.Character
    local localRoot = localCharacter and localCharacter:FindFirstChild("HumanoidRootPart")

    if not localRoot then
        return false, "Tu personaje aun no esta listo."
    end

    local targetCharacter = target.Character
    if not targetCharacter then
        return false, "El personaje de " .. target.DisplayName .. " no esta listo."
    end

    local targetRoot = targetCharacter:FindFirstChild("HumanoidRootPart")
    local targetCFrame = targetRoot and targetRoot.CFrame or nil

    if not targetCFrame then
        local pivotSuccess, pivot = pcall(function()
            return targetCharacter:GetPivot()
        end)
        if pivotSuccess and typeof(pivot) == "CFrame" then
            targetCFrame = pivot
        end
    end

    if not targetCFrame then
        return false, "No se pudo localizar a " .. target.DisplayName .. "."
    end

    local success = pcall(function()
        local destination = targetCFrame * CFrame.new(0, 0, 3)

        -- El primer salto acerca al cliente y fuerza la carga de zonas lejanas.
        localCharacter:PivotTo(destination)
        localRoot.CFrame = destination
        localRoot.AssemblyLinearVelocity = Vector3.zero
        localRoot.AssemblyAngularVelocity = Vector3.zero

        pcall(function()
            LocalPlayer:RequestStreamAroundAsync(targetCFrame.Position, 3)
        end)

        -- Cuando StreamingEnabled descarga al jugador lejano, esperamos su root
        -- y corregimos la posicion final para quedar exactamente junto a el.
        for _ = 1, 24 do
            if target.Parent ~= Players then
                error("target_left")
            end

            targetCharacter = target.Character
            targetRoot = targetCharacter
                and targetCharacter:FindFirstChild("HumanoidRootPart")
            if targetRoot then
                break
            end
            task.wait(0.1)
        end

        if targetRoot then
            for _ = 1, 3 do
                destination = targetRoot.CFrame * CFrame.new(0, 0, 3)
                localCharacter:PivotTo(destination)
                localRoot.CFrame = destination
                task.wait(0.05)
            end
            localRoot.AssemblyLinearVelocity = Vector3.zero
            localRoot.AssemblyAngularVelocity = Vector3.zero
        end
    end)

    if not success then
        if target.Parent ~= Players then
            return false, "El jugador se desconecto antes del teletransporte."
        end
        return false, "No se pudo completar el teletransporte."
    end

    return true, "Teletransportado a " .. target.DisplayName .. "."
end

HitboxSystem.PartRegions = {
    ["Left Leg"] = "legs",
    ["Right Leg"] = "legs",
    LeftUpperLeg = "legs",
    LeftLowerLeg = "legs",
    RightUpperLeg = "legs",
    RightLowerLeg = "legs",
    LeftFoot = "feet",
    RightFoot = "feet",
    Torso = "body",
    UpperTorso = "body",
    LowerTorso = "body",
    Head = "head",
}

local function getHitboxRegion(object)
    if not object:IsA("BasePart") then return nil end
    local character = object.Parent
    -- Solo piezas corporales directas: nunca accesorios llamados Head o Torso.
    if not character or not character:FindFirstChildOfClass("Humanoid")
        or character == LocalPlayer.Character then return nil end
    return HitboxSystem.PartRegions[object.Name]
end

HitboxSystem.Properties = {"Size", "Transparency", "Color", "Material", "CanCollide", "CanQuery", "Massless"}
HitboxSystem.Characters = {}
HitboxSystem.Epoch = 0
HitboxSystem.OwnerToken = {}
runtimeEnvironment.XTEYX_HitboxOwner = HitboxSystem.OwnerToken
HitboxSystem.RepairJobs = setmetatable({}, {__mode = "k"})
HitboxSystem.RepairQueue = {}
HitboxSystem.RepairRunning = 0

-- Una copia de una pieza ya azul/agrandada nunca cuenta como cuerpo original.
HitboxSystem.isLegacyVisual = function(value)
    local ok, result = pcall(function()
        local size = value.Size
        return value.Material == Enum.Material.Neon and value.Color == THEME.Accent
            and value.Transparency >= 0.5 and value.CanCollide == false and value.Massless == true
            and size.X >= 2 and math.abs(size.X - size.Y) < 0.3 and math.abs(size.X - size.Z) < 0.3
    end)
    return ok and result == true
end

HitboxSystem.isBadOriginal = function(state)
    if state.NeedsRecovery or HitboxSystem.isLegacyVisual(state) then return true end
    if state.CleanVersion == 3 then return false end
    local size = state.Size
    -- Los respaldos antiguos tambien podian guardar solo el tamano ampliado.
    return size and size.X >= 3 and math.abs(size.X - size.Y) < 0.3
        and math.abs(size.X - size.Z) < 0.3
end

HitboxSystem.snapshot = function(value, regionName)
    local state = {Region = regionName, CleanVersion = 3, Known = {}, Applied = {}}
    for _, property in ipairs(HitboxSystem.Properties) do
        local ok, saved = pcall(function() return value[property] end)
        if not ok or saved == nil then return nil end
        state[property] = saved
        state.Known[property] = true
    end
    return state
end

HitboxSystem.saveOriginal = function(part, state)
    if state.PersistenceSaved or HitboxSystem.isBadOriginal(state) then return end
    local ok = pcall(function()
        part:SetAttribute("XTEYX_OriginalVersion", nil)
        for _, property in ipairs(HitboxSystem.Properties) do
            local value = state[property]
            if property == "Material" then value = value.Name end
            part:SetAttribute("XTEYX_Original_" .. property, value)
        end
        part:SetAttribute("XTEYX_OriginalVersion", 3)
    end)
    state.PersistenceSaved = ok
end

HitboxSystem.readOriginal = function(part, regionName)
    local ok, state = pcall(function()
        if part:GetAttribute("XTEYX_OriginalVersion") ~= 3 then return nil end
        local values = {}
        for _, property in ipairs(HitboxSystem.Properties) do
            local value = part:GetAttribute("XTEYX_Original_" .. property)
            if value == nil then return nil end
            if property == "Material" then value = Enum.Material[value] end
            values[property] = value
        end
        if HitboxSystem.isLegacyVisual(values) then return nil end
        return HitboxSystem.snapshot(values, regionName)
    end)
    return ok and state or nil
end

HitboxSystem.updateRepairStatus = function()
    local pending, failed = 0, 0
    for _, state in pairs(originalHitboxStates) do
        if state.NeedsRecovery then pending = pending + 1 end
        if state.RecoveryFailed or state.RestoreFailed then failed = failed + 1 end
    end
    HitboxSystem.RepairMessage = failed > 0 and "No se pudo reparar todo. Reintenta Desactivar o cambia de servidor."
        or pending > 0 and "Recuperando cuerpos originales..." or nil
    if not destroyed then syncHitboxControls() end
end

HitboxSystem.queueRepair = function(character)
    if not character or not character.Parent then return end
    local previous = HitboxSystem.RepairJobs[character]
    if previous and (not previous.Finished or os.clock() < previous.RetryAt) then return end
    local job = {Character = character, Finished = false, RetryAt = math.huge}
    HitboxSystem.RepairJobs[character] = job
    table.insert(HitboxSystem.RepairQueue, job)
    HitboxSystem.pumpRepairs()
end

HitboxSystem.acquireOriginal = function(part, regionName)
    local state = originalHitboxStates[part]
    if state and not HitboxSystem.isBadOriginal(state) then
        state.CleanVersion = 3
        HitboxSystem.saveOriginal(part, state)
        return state
    end
    local clean
    if not state and not HitboxSystem.isLegacyVisual(part) then
        clean = HitboxSystem.snapshot(part, regionName)
    else
        clean = HitboxSystem.readOriginal(part, regionName)
    end
    if clean then
        clean.Owner = HitboxSystem.OwnerToken
        originalHitboxStates[part] = clean
        HitboxSystem.saveOriginal(part, clean)
        return clean
    end
    if not state or not state.NeedsRecovery then
        state = {Region = regionName, NeedsRecovery = true, Owner = HitboxSystem.OwnerToken}
        originalHitboxStates[part] = state
    end
    state.Owner = HitboxSystem.OwnerToken
    HitboxSystem.queueRepair(part.Parent)
    HitboxSystem.updateRepairStatus()
    return nil
end

local function applyHitboxPart(part)
    if destroyed or not hitboxEnabled or not hitboxVisible then return end
    local regionName = part.Parent and getHitboxRegion(part) or nil
    local region = regionName and HitboxSystem.Regions[regionName] or nil
    if not region or not region.Enabled then return end
    local state = HitboxSystem.acquireOriginal(part, regionName)
    if not state then return end
    state.Owner = HitboxSystem.OwnerToken
    -- Aplicar de nuevo invalida cualquier restauracion de un estado anterior.
    state.Revision = (state.Revision or 0) + 1
    state.RetryPending = false
    state.Applied = state.Applied or {}
    state.Known = state.Known or {}
    local targets = {Size = Vector3.new(region.Size, region.Size, region.Size),
        Transparency = 0.55, Color = THEME.Accent,
        Material = Enum.Material.Neon, CanCollide = false, CanQuery = true, Massless = true}
    for _, property in ipairs(HitboxSystem.Properties) do
        if state[property] ~= nil then
            state.Known[property] = true
            pcall(function()
                local current = part[property]
                -- El respaldo es inmutable mientras esta pieza este modificada.
                -- Un ajuste del motor no debe convertirse en su tamano original.
                if current ~= targets[property] then part[property] = targets[property] end
                state.Applied[property] = targets[property]
            end)
        end
    end
end

HitboxSystem.restorePart = function(part, state, attempt)
    if not part or originalHitboxStates[part] ~= state then return true end
    if HitboxSystem.isBadOriginal(state) then
        state = HitboxSystem.acquireOriginal(part, state.Region)
        if not state then return false end
    end
    if attempt == nil then
        state.Owner = HitboxSystem.OwnerToken
        state.Revision = (state.Revision or 0) + 1
        state.RetryPending = false
    end
    attempt = attempt or 0
    local restored = true
    for _, property in ipairs(HitboxSystem.Properties) do
        if state[property] ~= nil then
            local ok = pcall(function()
                -- Restaura tambien cuando el motor haya reajustado la pieza.
                if part[property] ~= state[property] then part[property] = state[property] end
                if part[property] ~= state[property] then error("Restauracion pendiente") end
            end)
            if not ok then restored = false end
        end
    end
    if restored and attempt >= 2 then
        originalHitboxStates[part] = nil
    elseif attempt < 3 and not state.RetryPending then
        -- Confirma el resultado en dos momentos posteriores. Corrige escrituras
        -- tardias sin mantener un bucle permanente sobre cuerpos restaurados.
        state.RetryPending = true
        local owner, revision = state.Owner, state.Revision
        task.delay(0.1 * (attempt + 1), function()
            if originalHitboxStates[part] ~= state or state.Owner ~= owner
                or state.Revision ~= revision then return end
            state.RetryPending = false
            HitboxSystem.restorePart(part, state, attempt + 1)
        end)
    end
    state.LastRestoreSucceeded = restored
    state.RestoreFailed = not restored and attempt >= 3
    if state.RestoreFailed or HitboxSystem.RepairMessage then HitboxSystem.updateRepairStatus() end
    return restored
end

HitboxSystem.pumpRepairs = function()
    while HitboxSystem.RepairRunning < 2 and #HitboxSystem.RepairQueue > 0 do
        local job = table.remove(HitboxSystem.RepairQueue, 1)
        HitboxSystem.RepairRunning = HitboxSystem.RepairRunning + 1
        local function finish(failed)
            if job.Finished then return end
            job.Finished = true
            job.RetryAt = os.clock() + 30
            HitboxSystem.RepairRunning = HitboxSystem.RepairRunning - 1
            if failed then
                for part, state in pairs(originalHitboxStates) do
                    if part.Parent == job.Character and state.NeedsRecovery then state.RecoveryFailed = true end
                end
            end
            HitboxSystem.updateRepairStatus()
            HitboxSystem.pumpRepairs()
        end
        task.delay(12, function() finish(true) end)
        task.spawn(function()
            local model, description
            local ok = pcall(function()
                if runtimeEnvironment.XTEYX_HitboxOwner ~= HitboxSystem.OwnerToken then return end
                local humanoid = job.Character:FindFirstChildOfClass("Humanoid")
                if not humanoid or not job.Character.Parent then error("Personaje no disponible") end
                description = humanoid:GetAppliedDescription()
                model = Players:CreateHumanoidModelFromDescriptionAsync(description, humanoid.RigType)
                if job.Finished or not job.Character.Parent
                    or runtimeEnvironment.XTEYX_HitboxOwner ~= HitboxSystem.OwnerToken then return end
                -- La plantilla permanece fuera de Workspace: no se muestra ni reemplaza al jugador.
                for _, part in ipairs(job.Character:GetChildren()) do
                    local previous = originalHitboxStates[part]
                    if previous and previous.NeedsRecovery and previous.Owner == HitboxSystem.OwnerToken then
                        local reference = model:FindFirstChild(part.Name)
                        if reference and reference:IsA("BasePart") and reference.ClassName == part.ClassName then
                            local state = HitboxSystem.snapshot(reference, previous.Region)
                            if state then
                                state.Owner = HitboxSystem.OwnerToken
                                originalHitboxStates[part] = state
                                HitboxSystem.saveOriginal(part, state)
                                local region = HitboxSystem.Regions[state.Region]
                                if not destroyed and hitboxEnabled and hitboxVisible and region and region.Enabled then
                                    applyHitboxPart(part)
                                else
                                    HitboxSystem.restorePart(part, state)
                                end
                            end
                        end
                    end
                end
            end)
            if model then pcall(function() model:Destroy() end) end
            if description then pcall(function() description:Destroy() end) end
            -- Una plantilla sin la pieza solicitada tambien se comunica como fallo.
            local missing = not ok
            for part, state in pairs(originalHitboxStates) do
                if part.Parent == job.Character and state.NeedsRecovery then missing = true end
            end
            finish(missing)
        end)
    end
end

HitboxSystem.auditInactive = function(regionName)
    for _, player in ipairs(Players:GetPlayers()) do
        local character = player ~= LocalPlayer and player.Character or nil
        if character and character.Parent then
            for _, part in ipairs(character:GetChildren()) do
                local name = getHitboxRegion(part)
                local region = name and HitboxSystem.Regions[name]
                if region and (not regionName or name == regionName)
                    and (destroyed or not hitboxEnabled or not hitboxVisible or not region.Enabled) then
                    local state = originalHitboxStates[part]
                    if state or HitboxSystem.isLegacyVisual(part) then
                        state = HitboxSystem.acquireOriginal(part, name)
                        if state and not state.RetryPending then HitboxSystem.restorePart(part, state) end
                    end
                end
            end
        end
    end
end

HitboxSystem.restoreRegion = function(regionName)
    for part, state in pairs(originalHitboxStates) do
        if state.Region == regionName then HitboxSystem.restorePart(part, state) end
    end
    HitboxSystem.auditInactive(regionName)
end

local function applyHitboxToCharacter(character)
    if destroyed or not hitboxEnabled or not hitboxVisible or not character or not character.Parent then return end
    for _, part in ipairs(character:GetChildren()) do
        if getHitboxRegion(part) then applyHitboxPart(part) end
    end
end

local function restoreAllHitboxes()
    for part, state in pairs(originalHitboxStates) do
        HitboxSystem.restorePart(part, state)
    end
    HitboxSystem.auditInactive()
    local pending = 0
    for _, state in pairs(originalHitboxStates) do
        if state.NeedsRecovery or state.LastRestoreSucceeded == false then pending = pending + 1 end
    end
    return pending
end

local function refreshHitboxes()
    if destroyed or not hitboxEnabled or not hitboxVisible then return end
    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer then applyHitboxToCharacter(player.Character) end
    end
end

HitboxSystem.setRegionSize = function(regionName, value)
    local region = HitboxSystem.Regions[regionName]
    local numericValue = tonumber(value)
    if not region or not numericValue or numericValue ~= numericValue
        or numericValue == math.huge or numericValue == -math.huge then
        syncHitboxControls()
        return
    end

    region.Size = math.clamp(math.floor(numericValue * 2 + 0.5) / 2, 1, 15)
    runtimeConfig[region.SizeKey] = region.Size
    AutoSave.queueConfigSave()
    syncHitboxControls()
    if hitboxEnabled and region.Enabled then
        refreshHitboxes()
    end
end

HitboxSystem.setRegionEnabled = function(regionName, state)
    local region = HitboxSystem.Regions[regionName]
    if not region then
        return
    end

    region.Enabled = state == true
    runtimeConfig[region.EnabledKey] = region.Enabled
    AutoSave.queueConfigSave()
    if region.Enabled then
        if hitboxEnabled then
            refreshHitboxes()
        end
        showToast(region.Label .. " activada.")
    else
        HitboxSystem.restoreRegion(regionName)
        showToast(region.Label .. " desactivada. Restaurando cuerpo.")
    end
    syncHitboxControls()
end

local function setHitboxEnabled(state)
    hitboxEnabled = state == true
    HitboxSystem.Epoch = HitboxSystem.Epoch + 1
    runtimeConfig.HitboxEnabled = hitboxEnabled
    AutoSave.queueConfigSave()
    if hitboxEnabled then
        refreshHitboxes()
        local message = hitboxVisible and "Hitbox por zonas activada."
            or "Hitbox en pausa. Pulsa Mostrar para aplicar los tamanos."
        logMessage(message, THEME.Accent)
        showToast(message)
    else
        local pending = restoreAllHitboxes()
        local message = pending == 0 and "Hitbox desactivada. Zonas restauradas."
            or "Hitbox desactivada. Reintentando restaurar " .. pending .. " piezas."
        logMessage(message, THEME.Muted)
        showToast(message)
    end
    syncHitboxControls()
end

local function setHitboxVisible(state)
    hitboxVisible = state == true
    HitboxSystem.Epoch = HitboxSystem.Epoch + 1
    runtimeConfig.HitboxVisible = hitboxVisible
    AutoSave.queueConfigSave()
    if hitboxVisible then
        refreshHitboxes()
        showToast(hitboxEnabled and "Hitbox visible. Tamanos aplicados."
            or "Visibilidad preparada. Pulsa Activar para usar la hitbox.")
    else
        local pending = restoreAllHitboxes()
        showToast(pending == 0 and "Hitbox oculta. Cuerpo restaurado; ampliacion en pausa."
            or "Hitbox en pausa. Reintentando restaurar " .. pending .. " piezas.")
    end
    syncHitboxControls()
end

HitboxSystem.releaseCharacter = function(character)
    local pool = HitboxSystem.Characters[character]
    if pool then disconnectPool(pool); HitboxSystem.Characters[character] = nil end
    for part, state in pairs(originalHitboxStates) do
        if part.Parent == character or part:IsDescendantOf(character) then HitboxSystem.restorePart(part, state) end
    end
end

local function bindHitboxCharacter(character)
    if destroyed or not character or HitboxSystem.Characters[character] then return end
    local pool = {}
    HitboxSystem.Characters[character] = pool
    connectPooled(pool, character.ChildAdded, function(part)
        local epoch = HitboxSystem.Epoch
        task.defer(function()
            if destroyed or epoch ~= HitboxSystem.Epoch or HitboxSystem.Characters[character] ~= pool
                or part.Parent ~= character then return end
            if getHitboxRegion(part) then
                applyHitboxPart(part)
                HitboxSystem.auditInactive()
            end
        end)
    end)
    connectPooled(pool, character.ChildRemoved, function(part)
        local state = originalHitboxStates[part]
        if state then HitboxSystem.restorePart(part, state) end
    end)
    local epoch = HitboxSystem.Epoch
    task.defer(function()
        if not destroyed and epoch == HitboxSystem.Epoch and HitboxSystem.Characters[character] == pool then
            applyHitboxToCharacter(character)
        end
    end)
end

HitboxSystem.unwatchPlayer = function(player)
    local record = watchedHitboxPlayers[player]
    if not record then return end
    disconnectPool(record.Connections)
    if record.Character then HitboxSystem.releaseCharacter(record.Character) end
    watchedHitboxPlayers[player] = nil
end

local function watchHitboxPlayer(player)
    if destroyed or player == LocalPlayer or watchedHitboxPlayers[player] then return end
    local record = {Connections = {}, Character = player.Character}
    watchedHitboxPlayers[player] = record
    connectPooled(record.Connections, player.CharacterAdded, function(character)
        if record.Character then HitboxSystem.releaseCharacter(record.Character) end
        record.Character = character
        bindHitboxCharacter(character)
    end)
    connectPooled(record.Connections, player.CharacterRemoving, function(character)
        HitboxSystem.releaseCharacter(character)
        if record.Character == character then record.Character = nil end
    end)
    if player.Character then bindHitboxCharacter(player.Character) end
end

HitboxSystem.stopWatching = function()
    HitboxSystem.Epoch = HitboxSystem.Epoch + 1
    for player in pairs(watchedHitboxPlayers) do HitboxSystem.unwatchPlayer(player) end
end

local R6_SKELETON = {
    {"Head", "Torso"},
    {"Torso", "Left Arm"},
    {"Torso", "Right Arm"},
    {"Torso", "Left Leg"},
    {"Torso", "Right Leg"},
}

local R15_SKELETON = {
    {"Head", "UpperTorso"},
    {"UpperTorso", "LowerTorso"},
    {"UpperTorso", "LeftUpperArm"},
    {"LeftUpperArm", "LeftLowerArm"},
    {"LeftLowerArm", "LeftHand"},
    {"UpperTorso", "RightUpperArm"},
    {"RightUpperArm", "RightLowerArm"},
    {"RightLowerArm", "RightHand"},
    {"LowerTorso", "LeftUpperLeg"},
    {"LeftUpperLeg", "LeftLowerLeg"},
    {"LeftLowerLeg", "LeftFoot"},
    {"LowerTorso", "RightUpperLeg"},
    {"RightUpperLeg", "RightLowerLeg"},
    {"RightLowerLeg", "RightFoot"},
}

function EspSystem.getPlayers()
    if not EspSystem.PlayerList or EspSystem.PlayersDirty then
        EspSystem.PlayerList = Players:GetPlayers()
        EspSystem.PlayersDirty = false
    end
    return EspSystem.PlayerList
end

function EspSystem.releaseRig(entry)
    if entry.RigConnections then disconnectPool(entry.RigConnections) end
    entry.Character, entry.Humanoid, entry.Root = nil, nil, nil
    entry.Parts, entry.NamedParts, entry.Points = {}, {}, {}
    entry.BoxCache = nil
    entry.RigConnections = {}
    entry.RigDirty = true
end

function EspSystem.getRig(entry, character)
    if entry.Character ~= character then
        EspSystem.releaseRig(entry)
        entry.Character = character
        if character then
            local function invalidate() entry.RigDirty = true end
            connectPooled(entry.RigConnections, character.ChildAdded, invalidate)
            connectPooled(entry.RigConnections, character.ChildRemoved, invalidate)
        end
    end
    if not character then return nil, nil end
    if entry.RigDirty or os.clock() >= (entry.RigRefreshAt or 0) then
        entry.Parts, entry.NamedParts, entry.Points = {}, {}, {}
        entry.BoxCache = nil
        entry.Humanoid, entry.Root = nil, nil
        for _, part in ipairs(character:GetChildren()) do
            if part:IsA("Humanoid") then entry.Humanoid = part end
            if part:IsA("BasePart") then
                entry.NamedParts[part.Name] = part
                if part.Name == "HumanoidRootPart" then entry.Root = part
                else table.insert(entry.Parts, part) end
            end
        end
        entry.RigDirty = false
        entry.RigRefreshAt = os.clock() + 2 + (entry.Player.UserId % 17) * 0.03
    end
    return entry.Humanoid, entry.Root
end

function EspSystem.prepareProjection(camera)
    local view, cf = camera.ViewportSize, camera.CFrame
    local data = EspSystem.Projection or {}
    -- Dos muestras por fotograma para todos los jugadores; si la proyeccion es
    -- especial se conserva la ruta nativa, sin suponer que sea una camara normal.
    local center = camera:WorldToViewportPoint(cf:PointToWorldSpace(Vector3.new(0, 0, -64)))
    local cornerPoint = camera:WorldToViewportPoint(cf:PointToWorldSpace(Vector3.new(64, 64, -64)))
    local scaleX, scaleY = cornerPoint.X - center.X, center.Y - cornerPoint.Y
    local fast = math.abs(center.Z - 64) < 0.02 and math.abs(cornerPoint.Z - 64) < 0.02
        and math.abs(center.X - view.X * 0.5) < 0.02 and math.abs(center.Y - view.Y * 0.5) < 0.02
        and scaleX > 0 and scaleY > 0 and scaleX < 1000000000 and scaleY < 1000000000
    if not fast or data.Camera ~= camera or data.CFrame ~= cf or data.View ~= view
        or data.CenterX ~= center.X or data.CenterY ~= center.Y or data.ScaleX ~= scaleX or data.ScaleY ~= scaleY then
        data.Revision = (data.Revision or 0) + 1
    end
    data.CenterX, data.CenterY, data.ScaleX, data.ScaleY, data.Fast = center.X, center.Y, scaleX, scaleY, fast
    data.Camera, data.View, data.Fov, data.FovMode = camera, view, camera.FieldOfView, camera.FieldOfViewMode
    data.CFrame = cf
    EspSystem.Projection = data
    return data
end

function EspSystem.projectPart(entry, part, camera)
    local saved = entry.Points[part]
    if not saved then saved = {}; entry.Points[part] = saved end
    local position = part.Position
    if saved.Position ~= position or saved.ProjectionRevision ~= EspSystem.Projection.Revision then
        local point, visible = camera:WorldToViewportPoint(position)
        saved.Position, saved.ProjectionRevision = position, EspSystem.Projection.Revision
        saved.Point, saved.Visible, saved.XY = point, visible, Vector2.new(point.X, point.Y)
    end
    return saved.Point, saved.Visible, saved.XY
end

function EspSystem.cachedPlayerColor(player)
    if not EspSystem.RelationColors then return EspSystem.Colors.Enemy end
    local friend = EspSystem.FriendCache[player]
    if friend and friend.Value then return EspSystem.Colors.Friend end
    local team = CameraSystem.TeamCache and CameraSystem.TeamCache[player]
    if team and team.Result then return EspSystem.Colors.Teammate end
    return EspSystem.Colors.Enemy
end

function EspSystem.maintainRelations()
    if destroyed or not espEnabled or not EspSystem.RelationColors
        or not (rearAlertEnabled or (drawingAvailable and (espLinesEnabled or espBoxesEnabled or espSkeletonEnabled))) then return end
    local list = EspSystem.getPlayers()
    if #list == 0 then return end
    local started = os.clock()
    for _ = 1, math.min(3, #list) do
        EspSystem.RelationCursor = (EspSystem.RelationCursor or 0) % #list + 1
        local player = list[EspSystem.RelationCursor]
        if player ~= LocalPlayer and player.Parent == Players then
            EspSystem.isFriend(player)
            CameraSystem.getTeammateStatus(player)
        end
        -- No hace todos los recorridos de equipos en el mismo fotograma.
        if os.clock() - started >= 0.001 then break end
    end
end

function EspSystem.makeDrawing(className, properties)
    if not drawingAvailable then
        return nil
    end
    if EspSystem.DrawingBudget then
        if EspSystem.DrawingBudget <= 0 then return nil end
        EspSystem.DrawingBudget = EspSystem.DrawingBudget - 1
    end

    local success, drawing = pcall(function()
        return Drawing.new(className)
    end)
    if not success or not drawing then
        drawingAvailable = false
        syncEspControls()
        return nil
    end

    EspSystem.DrawingStates = EspSystem.DrawingStates or setmetatable({}, {__mode = "k"})
    local state = {}
    EspSystem.DrawingStates[drawing] = state
    for property, value in pairs(properties or {}) do
        pcall(function()
            drawing[property] = value
            state[property] = value
        end)
    end

    return drawing
end

function EspSystem.setDrawingVisible(drawing, state)
    if drawing then
        local saved = EspSystem.DrawingStates and EspSystem.DrawingStates[drawing]
        if saved and saved.Visible == state then return true end
        local ok = pcall(EspSystem.commitVisibility, drawing, state)
        if ok and saved then saved.Visible = state end
        return ok
    end
    return true
end

function EspSystem.commitVisibility(drawing, visible)
    drawing.Visible = visible
end

function EspSystem.commitLine(drawing, saved, first, second, color)
    if saved.Color ~= color then drawing.Color = color; saved.Color = color end
    if saved.From ~= first then drawing.From = first; saved.From = first end
    if saved.To ~= second then drawing.To = second; saved.To = second end
    if not saved.Visible then drawing.Visible = true; saved.Visible = true end
end

function EspSystem.commitBox(drawing, saved, position, size, color)
    if saved.Color ~= color then drawing.Color = color; saved.Color = color end
    if saved.Position ~= position then drawing.Position = position; saved.Position = position end
    if saved.Size ~= size then drawing.Size = size; saved.Size = size end
    if not saved.Visible then drawing.Visible = true; saved.Visible = true end
end

function EspSystem.removeDrawing(drawing)
    if not drawing then
        return
    end
    pcall(function()
        drawing:Remove()
    end)
    if EspSystem.DrawingStates then EspSystem.DrawingStates[drawing] = nil end
end

function EspSystem.hideEntry(entry)
    if not entry or entry.Hidden then
        return
    end
    local hidden = true
    if not EspSystem.setDrawingVisible(entry.Line, false) then hidden = false end
    if not EspSystem.setDrawingVisible(entry.Box, false) then hidden = false end
    for _, line in ipairs(entry.Skeleton) do
        if not EspSystem.setDrawingVisible(line, false) then hidden = false end
    end
    entry.Hidden = hidden
end

function EspSystem.getEntry(player)
    local entry = espEntries[player]
    if entry then
        return entry
    end

    entry = {Player = player, Skeleton = {}, PlayerConnections = {}}
    EspSystem.releaseRig(entry)
    connectPooled(entry.PlayerConnections, player.CharacterRemoving, function(character)
        if entry.Character == character then
            EspSystem.hideEntry(entry)
            EspSystem.releaseRig(entry)
        end
    end)
    espEntries[player] = entry
    return entry
end

function EspSystem.ensureSkeletonLines(entry, amount)
    while #entry.Skeleton < amount do
        local line = EspSystem.makeDrawing("Line", {
            Color = THEME.Accent,
            Thickness = 1.2,
            Transparency = 1,
            Visible = false,
            ZIndex = 6,
        })
        if not line then
            break
        end
        table.insert(entry.Skeleton, line)
    end
end

function EspSystem.characterScreenBounds(character, camera, entry)
    local minimumX, minimumY = math.huge, math.huge
    local maximumX, maximumY = -math.huge, -math.huge
    local projectedCorners = 0

    local projection = EspSystem.Projection
    if not projection or projection.Camera ~= camera or projection.CFrame ~= camera.CFrame
        or projection.View ~= camera.ViewportSize or projection.Fov ~= camera.FieldOfView then
        projection = EspSystem.prepareProjection(camera)
    end
    local cache = entry and entry.BoxCache
    if cache and cache.Revision == projection.Revision then
        local unchanged = true
        for _, part in ipairs(entry.Parts) do
            local original = originalHitboxStates[part]
            local size = original and original.Size or part.Size
            local saved = cache.Parts[part]
            if not saved or saved.CFrame ~= part.CFrame or saved.Size ~= size then unchanged = false; break end
        end
        if unchanged then return cache.Position, cache.Size end
    end
    if entry and not cache then cache = {Parts = {}}; entry.BoxCache = cache end
    for _, part in ipairs(entry and entry.Parts or character:GetChildren()) do
        if part:IsA("BasePart") and part.Name ~= "HumanoidRootPart" then
            local originalState = originalHitboxStates[part]
            local partSize = originalState and originalState.Size or part.Size
            if cache then
                local saved = cache.Parts[part] or {}
                saved.CFrame, saved.Size = part.CFrame, partSize
                cache.Parts[part] = saved
            end

            local px, py, pz, r00, r01, r02, r10, r11, r12, r20, r21, r22 =
                projection.CFrame:ToObjectSpace(part.CFrame):GetComponents()
            local hx, hy, hz = partSize.X * 0.5, partSize.Y * 0.5, partSize.Z * 0.5
            r00, r10, r20 = r00 * hx, r10 * hx, r20 * hx
            r01, r11, r21 = r01 * hy, r11 * hy, r21 * hy
            r02, r12, r22 = r02 * hz, r12 * hz, r22 * hz
            for x = -1, 1, 2 do
                local xx, xy, xz = px + r00 * x, py + r10 * x, pz + r20 * x
                for y = -1, 1, 2 do
                    local yx, yy, yz = xx + r01 * y, xy + r11 * y, xz + r21 * y
                    for z = -1, 1, 2 do
                        local depth = -(yz + r22 * z)
                        local nativePoint
                        if not projection.Fast then
                            nativePoint = camera:WorldToViewportPoint(part.CFrame:PointToWorldSpace(
                                Vector3.new(hx * x, hy * y, hz * z)))
                            depth = nativePoint.Z
                        end
                        if depth > 0 then
                            local sx = nativePoint and nativePoint.X
                                or projection.CenterX + (yx + r02 * z) * projection.ScaleX / depth
                            local sy = nativePoint and nativePoint.Y
                                or projection.CenterY - (yy + r12 * z) * projection.ScaleY / depth
                            projectedCorners = projectedCorners + 1
                            minimumX = math.min(minimumX, sx)
                            minimumY = math.min(minimumY, sy)
                            maximumX = math.max(maximumX, sx)
                            maximumY = math.max(maximumY, sy)
                        end
                    end
                end
            end
        end
    end

    local position, size
    if projectedCorners >= 2 and maximumX > minimumX and maximumY > minimumY then
        position = Vector2.new(minimumX, minimumY)
        size = Vector2.new(maximumX - minimumX, maximumY - minimumY)
    end
    if cache then cache.Position, cache.Size, cache.Revision = position, size, projection.Revision end
    return position, size
end

function EspSystem.updateEntry(player, camera, lineOrigin)
    local entry = EspSystem.getEntry(player)
    local character = player.Character
    local humanoid, root = EspSystem.getRig(entry, character)

    if not character or not humanoid or humanoid.Health <= 0 or not root then
        EspSystem.hideEntry(entry)
        return
    end

    local rootPoint, rootOnScreen, rootXY = EspSystem.projectPart(entry, root, camera)
    if not rootOnScreen or rootPoint.Z <= 0 then
        EspSystem.hideEntry(entry)
        return
    end

    entry.Hidden = false
    EspSystem.AllHidden = false
    if espLinesEnabled and not entry.Line then
        entry.Line = EspSystem.makeDrawing("Line", {Color = THEME.Accent, Thickness = 1.5,
            Transparency = 1, Visible = false, ZIndex = 5})
    end
    if espBoxesEnabled and not entry.Box then
        entry.Box = EspSystem.makeDrawing("Square", {Color = THEME.White, Thickness = 1.4,
            Transparency = 1, Filled = false, Visible = false, ZIndex = 5})
    end
    local relationColor = EspSystem.cachedPlayerColor(player)
    if entry.Line then
        if espLinesEnabled then
            pcall(EspSystem.commitLine, entry.Line, EspSystem.DrawingStates[entry.Line], lineOrigin, rootXY, relationColor)
        else
            EspSystem.setDrawingVisible(entry.Line, false)
        end
    end

    if entry.Box then
        if espBoxesEnabled then
            local position, size = EspSystem.characterScreenBounds(character, camera, entry)
            if position and size then
                pcall(EspSystem.commitBox, entry.Box, EspSystem.DrawingStates[entry.Box], position, size, relationColor)
            else
                EspSystem.setDrawingVisible(entry.Box, false)
            end
        else
            EspSystem.setDrawingVisible(entry.Box, false)
        end
    end

    local skeletonMap = humanoid.RigType == Enum.HumanoidRigType.R6
        and R6_SKELETON or R15_SKELETON
    if espSkeletonEnabled then
        EspSystem.ensureSkeletonLines(entry, #skeletonMap)
    end

    for index, line in ipairs(entry.Skeleton) do
        local connection = skeletonMap[index]
        if espSkeletonEnabled and connection then
            local firstPart = entry.NamedParts[connection[1]]
            local secondPart = entry.NamedParts[connection[2]]
            if firstPart and secondPart then
                local firstPoint, firstVisible, firstXY = EspSystem.projectPart(entry, firstPart, camera)
                local secondPoint, secondVisible, secondXY = EspSystem.projectPart(entry, secondPart, camera)
                if firstVisible and secondVisible and firstPoint.Z > 0 and secondPoint.Z > 0 then
                    pcall(EspSystem.commitLine, line, EspSystem.DrawingStates[line], firstXY, secondXY, relationColor)
                else
                    EspSystem.setDrawingVisible(line, false)
                end
            else
                EspSystem.setDrawingVisible(line, false)
            end
        else
            EspSystem.setDrawingVisible(line, false)
        end
    end
end

function EspSystem.hideAll()
    if EspSystem.AllHidden then return end
    local allHidden = true
    for _, entry in pairs(espEntries) do
        EspSystem.hideEntry(entry)
        if not entry.Hidden then allHidden = false end
    end
    EspSystem.AllHidden = allHidden
end

function EspSystem.removeEntry(player)
    local entry = espEntries[player]
    if not entry then
        return
    end
    EspSystem.removeDrawing(entry.Line)
    EspSystem.removeDrawing(entry.Box)
    for _, line in ipairs(entry.Skeleton) do
        EspSystem.removeDrawing(line)
    end
    disconnectPool(entry.PlayerConnections)
    EspSystem.releaseRig(entry)
    espEntries[player] = nil
end

function EspSystem.removeAll()
    for player in pairs(espEntries) do
        EspSystem.removeEntry(player)
    end
    EspSystem.PlayerList, EspSystem.Projection = nil, nil
end

function EspSystem.hideRearAlert()
    if not RearAlertBanner.Visible then return end
    RearAlertBanner.Visible = false
    for _, marker in ipairs(EspSystem.RearMarkers or {}) do marker.Root.Visible = false end
end

function EspSystem.rearDirection(offset, look)
    local forward = Vector3.new(look.X, 0, look.Z)
    local flat = Vector3.new(offset.X, 0, offset.Z)
    if forward.Magnitude < 0.01 or flat.Magnitude < 0.1 then return nil end
    forward = forward.Unit
    local right = Vector3.new(-forward.Z, 0, forward.X)
    local angle = math.atan2(flat:Dot(right), flat:Dot(forward))
    return angle, math.floor((angle + math.pi / 12) / (math.pi / 6)) % 12 + 1
end

function EspSystem.rearIntensity(distance, maximum)
    return math.clamp(1 - distance / math.max(1, maximum), 0, 1)
end

function EspSystem.makeRearMarkers()
    if EspSystem.RearMarkers then return end
    EspSystem.RearMarkers = {}
    for index = 1, 12 do
        local root = create("Frame", {
            Name = "Direction" .. index, Size = UDim2.fromScale(1, 1),
            BackgroundTransparency = 1, Visible = false, ZIndex = 71,
        }, RearAlertBanner)
        local marker = {Root = root, Arcs = {}, Feet = {}}
        for segment = -1, 1 do
            local arc = create("Frame", {
                AnchorPoint = Vector2.new(0.5, 0.5), Size = UDim2.fromOffset(19, 3),
                BackgroundColor3 = THEME.White, BorderSizePixel = 0, ZIndex = 71,
            }, root)
            corner(arc, 3)
            table.insert(marker.Arcs, arc)
        end
        local steps = create("Frame", {
            AnchorPoint = Vector2.new(0.5, 0.5), Size = UDim2.fromOffset(24, 28),
            BackgroundTransparency = 1, ZIndex = 72,
        }, root)
        marker.Steps = steps
        for foot = 0, 1 do
            for piece = 0, 1 do
                local shape = create("Frame", {
                    Position = UDim2.fromOffset(3 + foot * 11, foot * 6 + piece * 13),
                    Size = UDim2.fromOffset(7, piece == 0 and 11 or 5),
                    BackgroundColor3 = THEME.White, BorderSizePixel = 0,
                    Rotation = foot == 0 and -12 or 12, ZIndex = 73,
                }, steps)
                corner(shape, 4)
                table.insert(marker.Feet, shape)
            end
        end
        EspSystem.RearMarkers[index] = marker
    end
end

-- Compatible con el punto de entrada anterior, ahora dibuja un sector.
function EspSystem.showRearAlert(player, distance, angle, index, moving)
    EspSystem.makeRearMarkers()
    index = index or 7
    angle = angle or math.pi
    local marker = EspSystem.RearMarkers[index]
    local intensity = EspSystem.rearIntensity(distance, rearAlertDistance)
    local pulse = moving and (0.5 + 0.5 * math.sin(os.clock() * (5 + intensity * 5))) or 0.5
    local opacity = math.clamp(0.24 + intensity * 0.68 + pulse * 0.08, 0, 1)
    local color = EspSystem.cachedPlayerColor(player)
    marker.Root.Visible = true
    for segment, arc in ipairs(marker.Arcs) do
        local bearing = angle + (segment - 2) * 0.14
        arc.Position = UDim2.fromScale(0.5 + math.sin(bearing) * 0.39, 0.5 - math.cos(bearing) * 0.39)
        arc.Rotation = math.deg(bearing)
        arc.Size = UDim2.fromOffset(18 + intensity * 3, 2 + intensity * 3)
        arc.BackgroundColor3 = color
        arc.BackgroundTransparency = 1 - opacity
    end
    marker.Steps.Position = UDim2.fromScale(0.5 + math.sin(angle) * 0.49, 0.5 - math.cos(angle) * 0.49)
    marker.Steps.Rotation = math.deg(angle)
    for _, foot in ipairs(marker.Feet) do
        foot.BackgroundColor3 = color
        foot.BackgroundTransparency = 1 - opacity
    end
    RearAlertBanner.Visible = true
end

function EspSystem.updateRearAlert(deltaTime)
    if destroyed or not espEnabled or not rearAlertEnabled then
        rearAlertElapsed = 0
        EspSystem.hideRearAlert()
        return
    end
    rearAlertElapsed = rearAlertElapsed + deltaTime
    if rearAlertElapsed < 0.08 then return end
    rearAlertElapsed = 0
    local camera = Workspace.CurrentCamera
    local character = LocalPlayer.Character
    local humanoid = character and character:FindFirstChildOfClass("Humanoid")
    local origin = character and character:FindFirstChild("HumanoidRootPart")
    if not camera or not origin or not humanoid or humanoid.Health <= 0 then
        EspSystem.hideRearAlert()
        return
    end
    EspSystem.hideRearAlert()
    local size = math.clamp(math.min(camera.ViewportSize.X, camera.ViewportSize.Y) * 0.42, 190, 290)
    RearAlertBanner.Size = UDim2.fromOffset(size, size)
    local sectors = {}
    for _, player in ipairs(EspSystem.getPlayers()) do
        if player ~= LocalPlayer then
            local target = player.Character
            local health = target and target:FindFirstChildOfClass("Humanoid")
            local root = target and target:FindFirstChild("HumanoidRootPart")
            if root and health and health.Health > 0 then
                local offset = root.Position - origin.Position
                local distance = offset.Magnitude
                if distance <= rearAlertDistance then
                    local angle, sector = EspSystem.rearDirection(offset, camera.CFrame.LookVector)
                    if not angle then angle, sector = EspSystem.rearDirection(offset, origin.CFrame.LookVector) end
                    if sector and (not sectors[sector] or distance < sectors[sector].Distance) then
                        sectors[sector] = {Player = player, Distance = distance, Angle = angle,
                            Moving = health.MoveDirection.Magnitude > 0.05}
                    end
                end
            end
        end
    end
    for index, target in pairs(sectors) do
        EspSystem.showRearAlert(target.Player, target.Distance, target.Angle, index, target.Moving)
    end
end

function EspSystem.updateFrame(deltaTime)
    if destroyed then return end
    EspSystem.updateRearAlert(deltaTime)

    if not espEnabled or not drawingAvailable or not (espLinesEnabled or espBoxesEnabled or espSkeletonEnabled) then
        EspSystem.hideAll()
        return
    end

    local camera = Workspace.CurrentCamera
    local localCharacter = LocalPlayer.Character
    local localRoot = localCharacter and localCharacter:FindFirstChild("HumanoidRootPart")
    if not camera or not localRoot then
        EspSystem.hideAll()
        return
    end

    EspSystem.prepareProjection(camera)
    local originPoint, originVisible = camera:WorldToViewportPoint(localRoot.Position)
    local lineOrigin = originVisible and Vector2.new(originPoint.X, originPoint.Y)
        or Vector2.new(camera.ViewportSize.X * 0.5, camera.ViewportSize.Y)

    EspSystem.DrawingBudget = 64
    for _, player in ipairs(EspSystem.getPlayers()) do
        if player ~= LocalPlayer then
            EspSystem.updateEntry(player, camera, lineOrigin)
        end
    end
    EspSystem.DrawingBudget = nil
end

function EspSystem.setEnabled(state)
    espEnabled = state == true
    runtimeConfig.EspEnabled = espEnabled
    AutoSave.queueConfigSave()
    if not espEnabled then
        EspSystem.hideAll()
        EspSystem.hideRearAlert()
    end
    syncEspControls()
    logMessage(espEnabled and "ESP visual activado." or "ESP visual desactivado.",
        espEnabled and THEME.Accent or THEME.Muted)
    if espEnabled and not drawingAvailable then
        showToast("Drawing no disponible; la rueda de proximidad si funciona.")
    else
        showToast(espEnabled and "ESP activado." or "ESP desactivado.")
    end
end

function EspSystem.setOption(optionName, state)
    if optionName == "lines" then
        espLinesEnabled = state
        runtimeConfig.EspLines = state
    elseif optionName == "boxes" then
        espBoxesEnabled = state
        runtimeConfig.EspBoxes = state
    elseif optionName == "skeleton" then
        espSkeletonEnabled = state
        runtimeConfig.EspSkeleton = state
    elseif optionName == "rear" then
        rearAlertEnabled = state
        runtimeConfig.RearAlert = state
        if not state then
            EspSystem.hideRearAlert()
        end
    end
    AutoSave.queueConfigSave()
    syncEspControls()
end

function EspSystem.setRearDistance(value)
    rearAlertDistance = math.clamp(math.floor(tonumber(value) or 15), 5, 50)
    runtimeConfig.RearAlertDistance = rearAlertDistance
    AutoSave.queueConfigSave()
    syncEspControls()
end

function CameraSystem.getTargetPosition(character)
    if not character then
        return nil
    end

    if CameraSystem.TargetZone == "head" then
        local head = character:FindFirstChild("Head")
        return head and head.Position or nil
    end

    if CameraSystem.TargetZone == "body" then
        local body = character:FindFirstChild("UpperTorso")
            or character:FindFirstChild("Torso")
            or character:FindFirstChild("HumanoidRootPart")
        return body and body.Position or nil
    end

    local leftFoot = character:FindFirstChild("LeftFoot")
        or character:FindFirstChild("Left Leg")
    local rightFoot = character:FindFirstChild("RightFoot")
        or character:FindFirstChild("Right Leg")
    if not leftFoot and not rightFoot then
        return nil
    end

    local function footPoint(part)
        if not part then
            return nil
        end
        if part.Name == "LeftFoot" or part.Name == "RightFoot" then
            return part.Position
        end
        local originalState = originalHitboxStates[part]
        local partSize = originalState and originalState.Size or part.Size
        return part.Position - part.CFrame.UpVector * (partSize.Y * 0.42)
    end

    local leftPoint = footPoint(leftFoot)
    local rightPoint = footPoint(rightFoot)
    if leftPoint and rightPoint then
        return (leftPoint + rightPoint) * 0.5
    end
    return leftPoint or rightPoint
end

-- Team Check con multiples senales: usa Teams nativos y senales replicadas comunes de
-- sistemas personalizados. La cache corta evita recorrer GUIs cada frame.
CameraSystem.TeamFamilies = {
    "team",
    "squad",
    "faction",
    "side",
    "crew",
    "clan",
    "party",
}

function CameraSystem.getTeamFamily(name)
    local normalizedName = string.lower(tostring(name or ""))
    normalizedName = string.gsub(normalizedName, "[^%w]", "")
    for _, family in ipairs(CameraSystem.TeamFamilies) do
        if string.find(normalizedName, family, 1, true) then
            return family
        end
    end
    return nil
end

function CameraSystem.normalizeTeamToken(value)
    local valueType = typeof(value)
    if valueType == "string" then
        local token = string.lower(string.match(value, "^%s*(.-)%s*$") or "")
        if token == "" or token == "none" or token == "neutral"
            or token == "noteam" or token == "nil" then
            return nil
        end
        return "text:" .. token
    end
    if valueType == "number" then
        if value == 0 or value == -1 then
            return nil
        end
        return "number:" .. tostring(value)
    end
    if valueType == "Color3" then
        return string.format(
            "color:%d:%d:%d",
            math.floor(value.R * 255 + 0.5),
            math.floor(value.G * 255 + 0.5),
            math.floor(value.B * 255 + 0.5)
        )
    end
    if valueType == "BrickColor" then
        return "brick:" .. tostring(value.Number)
    end
    if valueType == "Instance" then
        return "instance:" .. value:GetFullName()
    end
    if valueType == "EnumItem" then
        return "enum:" .. tostring(value)
    end
    return nil
end

function CameraSystem.collectTeamTokens(player)
    local tokens = {}

    local function addToken(name, value)
        local family = CameraSystem.getTeamFamily(name)
        if not family then
            return
        end
        local token = CameraSystem.normalizeTeamToken(value)
        if not token then
            return
        end
        tokens[family] = tokens[family] or {}
        tokens[family][token] = true
    end

    local function inspectAttributes(source)
        if not source then
            return
        end
        for name, value in pairs(source:GetAttributes()) do
            addToken(name, value)
        end
    end

    local function inspectObject(object)
        local family = CameraSystem.getTeamFamily(object.Name)
        if not family then
            return
        end
        if object:IsA("ValueBase") then
            local success, value = pcall(function()
                return object.Value
            end)
            if success then
                addToken(family, value)
            end
        elseif object:IsA("TextLabel") or object:IsA("TextButton") then
            addToken(family, object.Text)
        end
    end

    inspectAttributes(player)
    inspectAttributes(player and player.Character)

    -- En Player se revisan solo valores directos y carpetas relevantes para no
    -- recorrer PlayerGui/PlayerScripts completos. El personaje si se recorre
    -- porque ahi suelen estar los tags de nombre y sistemas de team custom.
    if player then
        for _, object in ipairs(player:GetChildren()) do
            inspectObject(object)
            local objectName = string.lower(object.Name)
            if objectName == "leaderstats" or CameraSystem.getTeamFamily(object.Name) then
                for _, descendant in ipairs(object:GetDescendants()) do
                    inspectObject(descendant)
                end
            end
        end
    end

    local character = player and player.Character
    if character then
        for _, object in ipairs(character:GetDescendants()) do
            inspectObject(object)
        end
    end

    return tokens
end

function CameraSystem.getTeamSignals(player)
    local now = os.clock()
    local cached = CameraSystem.TeamSignalCache[player]
    if cached and cached.ExpiresAt > now then
        return cached
    end

    local signals = {
        Tokens = CameraSystem.collectTeamTokens(player),
        NameColor = CameraSystem.getNameTagColor(player),
        ExpiresAt = now + 0.5,
    }
    CameraSystem.TeamSignalCache[player] = signals
    return signals
end

function CameraSystem.getNameTagColor(player)
    local character = player and player.Character
    if not character then
        return nil
    end

    local username = string.lower(player.Name)
    local displayName = string.lower(player.DisplayName)
    for _, object in ipairs(character:GetDescendants()) do
        if (object:IsA("TextLabel") or object:IsA("TextButton"))
            and object.Visible and object.TextTransparency < 0.5 then
            local text = string.lower(tostring(object.Text or ""))
            if string.find(text, username, 1, true)
                or string.find(text, displayName, 1, true) then
                local color = object.TextColor3
                local maximum = math.max(color.R, color.G, color.B)
                local minimum = math.min(color.R, color.G, color.B)
                if maximum - minimum >= 0.12 and maximum >= 0.18 then
                    return color
                end
            end
        end
    end
    return nil
end

function CameraSystem.colorsMatch(first, second)
    if not first or not second then
        return false
    end
    return math.abs(first.R - second.R) <= 0.035
        and math.abs(first.G - second.G) <= 0.035
        and math.abs(first.B - second.B) <= 0.035
end

function CameraSystem.detectTeammate(player)
    if not player or player == LocalPlayer then
        return player == LocalPlayer
    end

    local localTeam = LocalPlayer.Team
    local targetTeam = player.Team
    if localTeam and targetTeam and not LocalPlayer.Neutral and not player.Neutral then
        return localTeam == targetTeam
    end

    local sameTeamColor = LocalPlayer.TeamColor == player.TeamColor
    if sameTeamColor and not LocalPlayer.Neutral and not player.Neutral then
        return true
    end

    local localSignals = CameraSystem.getTeamSignals(LocalPlayer)
    local targetSignals = CameraSystem.getTeamSignals(player)
    local localTokens = localSignals.Tokens
    local targetTokens = targetSignals.Tokens
    for family, familyTokens in pairs(localTokens) do
        local otherTokens = targetTokens[family]
        if otherTokens then
            for token in pairs(familyTokens) do
                if otherTokens[token] then
                    return true
                end
            end
        end
    end

    return CameraSystem.colorsMatch(
        localSignals.NameColor,
        targetSignals.NameColor
    )
end

function CameraSystem.getTeammateStatus(player)
    local now = os.clock()
    local cached = CameraSystem.TeamCache[player]
    if cached and cached.ExpiresAt > now then
        return cached.Result
    end

    local success, result = pcall(CameraSystem.detectTeammate, player)
    result = success and result == true
    CameraSystem.TeamCache[player] = {
        Result = result,
        ExpiresAt = now + 0.5,
    }
    return result
end

function CameraSystem.isTeammate(player)
    return CameraSystem.TeamCheck and CameraSystem.getTeammateStatus(player)
end

-- Colores guardados como HEX: compatibles con el autoguardado JSON existente.
Compact.parseColor = function(value)
    if type(value) ~= "string" then return nil end
    local hex = value:match("^%s*#?(%x%x%x%x%x%x)%s*$")
    if not hex then return nil end
    return Color3.fromRGB(tonumber(hex:sub(1, 2), 16), tonumber(hex:sub(3, 4), 16), tonumber(hex:sub(5, 6), 16)), hex:upper()
end
Compact.colorHex = function(color)
    return string.format("%02X%02X%02X", math.floor(color.R * 255 + 0.5),
        math.floor(color.G * 255 + 0.5), math.floor(color.B * 255 + 0.5))
end
Compact.makeColorRow = function(parent, title, y, initial, callback)
    local row = create("Frame", {
        Name = "Color_" .. title, Position = UDim2.fromOffset(14, y),
        Size = UDim2.new(1, -28, 0, 70), BackgroundTransparency = 1,
    }, parent)
    local preview = create("Frame", {
        Position = UDim2.fromOffset(0, 6), Size = UDim2.fromOffset(14, 14),
        BackgroundColor3 = initial, BorderSizePixel = 0,
    }, row)
    corner(preview, 4)
    create("TextLabel", {
        Position = UDim2.fromOffset(22, 0), Size = UDim2.new(1, -146, 0, 26),
        BackgroundTransparency = 1, Text = title, TextSize = 14, Font = Enum.Font.BuilderSansMedium,
        TextColor3 = THEME.Text, TextXAlignment = Enum.TextXAlignment.Left,
    }, row)
    local input = create("TextBox", {
        Position = UDim2.new(1, -110, 0, 0), Size = UDim2.fromOffset(110, 26),
        BackgroundColor3 = THEME.Input, BorderSizePixel = 0, ClearTextOnFocus = false,
        Text = "#" .. Compact.colorHex(initial), TextSize = 13, Font = Enum.Font.RobotoMono,
        TextColor3 = THEME.White,
    }, row)
    corner(input, 5)
    local selection = initial
    local outlines = {}
    local function choose(color)
        selection = color
        preview.BackgroundColor3 = color
        input.Text = "#" .. Compact.colorHex(color)
        input.TextColor3 = THEME.White
        for hex, outline in pairs(outlines) do
            outline.Transparency = hex == Compact.colorHex(color) and 0 or 1
        end
        callback(color, Compact.colorHex(color))
    end
    for index, hex in ipairs({"FFFFFF", "40E180", "5AA5FF", "FF5C68", "FFC45C", "B794FF", "FF83CE", "50E2E9"}) do
        local color = Compact.parseColor(hex)
        local button = create("TextButton", {
            Name = "Swatch_" .. hex, Position = UDim2.fromOffset((index - 1) * 43, 36),
            Size = UDim2.fromOffset(34, 22), BackgroundColor3 = color, BorderSizePixel = 0,
            Text = "", AutoButtonColor = false,
        }, row)
        button:SetAttribute("ColorSwatch", true)
        corner(button, 5)
        outlines[hex] = stroke(button, THEME.White, hex == Compact.colorHex(initial) and 0 or 1, 2)
        connect(button.Activated, function() choose(color) end)
    end
    connect(input.FocusLost, function()
        local color = Compact.parseColor(input.Text)
        if color then choose(color) else
            input.Text = "#" .. Compact.colorHex(selection)
            showToast("Color no valido. Usa # y seis caracteres, por ejemplo #40E180.")
        end
    end)
    return row
end

EspSystem.RelationColors = runtimeConfig.EspRelationColors ~= false
EspSystem.FriendCache = {}
EspSystem.FriendStripes = setmetatable({}, {__mode = "k"})
EspSystem.Colors = {
    Teammate = Compact.parseColor(runtimeConfig.EspTeamColor) or Color3.fromRGB(90, 165, 255),
    Enemy = Compact.parseColor(runtimeConfig.EspEnemyColor) or Color3.fromRGB(255, 255, 255),
    Friend = Compact.parseColor(runtimeConfig.EspFriendColor) or Color3.fromRGB(64, 225, 128),
}
CameraSystem.FovColor = Compact.parseColor(runtimeConfig.CameraFovColor) or THEME.Accent
CameraSystem.UI.FovStroke.Color = CameraSystem.FovColor

function EspSystem.updateFriendStripe(player, isFriend)
    local stripe = EspSystem.FriendStripes[player]
    if stripe and stripe.Parent then stripe.Visible = isFriend == true end
end

function EspSystem.isFriend(player)
    local now = os.clock()
    local cached = EspSystem.FriendCache[player]
    if not cached then
        cached = {Value = false, ExpiresAt = 0, Pending = false}
        EspSystem.FriendCache[player] = cached
    end
    if not cached.Pending and cached.ExpiresAt <= now then
        cached.Pending = true
        -- Las consultas pueden ceder el hilo: nunca se ejecutan en RenderStepped.
        task.spawn(function()
            local success, result = pcall(function()
                return LocalPlayer:IsFriendsWithAsync(player.UserId)
            end)
            if not success then
                success, result = pcall(function() return LocalPlayer:IsFriendsWith(player.UserId) end)
            end
            if destroyed or EspSystem.FriendCache[player] ~= cached or player.Parent ~= Players then return end
            cached.Pending = false
            cached.ExpiresAt = os.clock() + (success and 60 or 10)
            if success then cached.Value = result == true end
            EspSystem.updateFriendStripe(player, cached.Value)
        end)
    end
    return cached.Value
end

function EspSystem.playerColor(player)
    if not EspSystem.RelationColors then return EspSystem.Colors.Enemy end
    if EspSystem.isFriend(player) then return EspSystem.Colors.Friend end
    if CameraSystem.getTeammateStatus(player) then return EspSystem.Colors.Teammate end
    return EspSystem.Colors.Enemy
end

function EspSystem.syncRelations()
    styleEspToggle(EspSystem.RelationsButton, EspSystem.RelationColors, "Colores activados", "Colores desactivados")
end

do
    local panel = create("Frame", {
        Name = "EspRelations", Position = UDim2.fromOffset(12, 572),
        Size = UDim2.fromOffset(376, 282), BackgroundColor3 = THEME.Panel, BorderSizePixel = 0,
    }, EspPage)
    corner(panel, 6)
    stroke(panel, THEME.BorderSoft, 0, 1)
    create("TextLabel", {
        Position = UDim2.fromOffset(14, 8), Size = UDim2.fromOffset(170, 28),
        BackgroundTransparency = 1, Text = "Colores ESP", TextColor3 = THEME.White,
        TextSize = 16, Font = Enum.Font.BuilderSansBold, TextXAlignment = Enum.TextXAlignment.Left,
    }, panel)
    EspSystem.RelationsButton = create("TextButton", {
        Position = UDim2.fromOffset(208, 8), Size = UDim2.fromOffset(154, 28),
        BackgroundColor3 = THEME.PanelAlt, BorderSizePixel = 0,
        Text = "Colores activados", TextColor3 = THEME.White, Font = Enum.Font.BuilderSansBold,
        TextSize = 13, AutoButtonColor = false,
    }, panel)
    corner(EspSystem.RelationsButton, 5)
    connect(EspSystem.RelationsButton.Activated, function()
        EspSystem.RelationColors = not EspSystem.RelationColors
        runtimeConfig.EspRelationColors = EspSystem.RelationColors
        AutoSave.queueConfigSave()
        EspSystem.syncRelations()
    end)
    for index, entry in ipairs({{"Amigos", "Friend", "EspFriendColor"},
        {"Enemigos", "Enemy", "EspEnemyColor"}, {"Equipo", "Teammate", "EspTeamColor"}}) do
        Compact.makeColorRow(panel, entry[1], 48 + (index - 1) * 76, EspSystem.Colors[entry[2]], function(color, hex)
            EspSystem.Colors[entry[2]] = color
            runtimeConfig[entry[3]] = hex
            AutoSave.queueConfigSave()
        end)
    end
    Compact.makeColorRow(CameraSystem.UI.FovCard, "Color del area", 98, CameraSystem.FovColor, function(color, hex)
        CameraSystem.FovColor = color
        CameraSystem.UI.FovStroke.Color = color
        runtimeConfig.CameraFovColor = hex
        AutoSave.queueConfigSave()
    end)
    EspSystem.syncRelations()
end

function CameraSystem.findTarget(camera)
    local center = Vector2.new(camera.ViewportSize.X * 0.5, camera.ViewportSize.Y * 0.5)
    local localCharacter = LocalPlayer.Character
    local localRoot = localCharacter and localCharacter:FindFirstChild("HumanoidRootPart")
    local distanceOrigin = localRoot and localRoot.Position or camera.CFrame.Position
    local nearestPlayer = nil
    local nearestPosition = nil
    local nearestScreenDistance = CameraSystem.FovRadius + 1

    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer and not CameraSystem.isTeammate(player) then
            local character = player.Character
            local humanoid = character and character:FindFirstChildOfClass("Humanoid")
            if humanoid and humanoid.Health > 0 then
                local targetPosition = CameraSystem.getTargetPosition(character)
                if targetPosition then
                    local targetRoot = character:FindFirstChild("HumanoidRootPart")
                    local distancePosition = targetRoot and targetRoot.Position or targetPosition
                    local worldDistance = (distancePosition - distanceOrigin).Magnitude
                    if worldDistance <= CameraSystem.MaxDistance then
                        local point, visible = camera:WorldToViewportPoint(targetPosition)
                        if visible and point.Z > 0 then
                            local screenDistance = (Vector2.new(point.X, point.Y) - center).Magnitude
                            if screenDistance <= CameraSystem.FovRadius
                                and screenDistance < nearestScreenDistance then
                                nearestPlayer = player
                                nearestPosition = targetPosition
                                nearestScreenDistance = screenDistance
                            end
                        end
                    end
                end
            end
        end
    end

    return nearestPlayer, nearestPosition
end

function CameraSystem.updateTargetLabel(player)
    local userId = player and player.UserId or nil
    if userId == CameraSystem.LastTargetUserId then
        return
    end

    CameraSystem.LastTargetUserId = userId
    CameraSystem.TargetPlayer = player
    CameraSystem.syncControls()
end

function CameraSystem.setEnabled(state)
    CameraSystem.Enabled = state == true
    runtimeConfig.CameraEnabled = CameraSystem.Enabled
    AutoSave.queueConfigSave()
    CameraSystem.ManualHeld = false
    CameraSystem.ManualToggled = false
    CameraSystem.LastTargetUserId = false
    CameraSystem.updateTargetLabel(nil)
    CameraSystem.syncControls()
    logMessage(
        CameraSystem.Enabled and "Aim de camara activado." or "Aim de camara desactivado.",
        CameraSystem.Enabled and THEME.Accent or THEME.Muted
    )
    showToast(CameraSystem.Enabled and "Aim activado." or "Aim desactivado.")
end

function CameraSystem.setActivationMode(mode)
    if mode ~= "auto" and mode ~= "manual" then
        return
    end
    CameraSystem.ActivationMode = mode
    CameraSystem.ManualHeld = false
    CameraSystem.ManualToggled = false
    CameraSystem.LastTargetUserId = false
    runtimeConfig.CameraActivationMode = mode
    AutoSave.queueConfigSave()
    CameraSystem.updateTargetLabel(nil)
    CameraSystem.syncControls()
    showToast(mode == "auto" and "Aim automatico." or "Aim manual por teclado.")
end

function CameraSystem.setManualBehavior(behavior)
    if behavior ~= "hold" and behavior ~= "toggle" then
        return
    end
    CameraSystem.ManualBehavior = behavior
    CameraSystem.ManualHeld = false
    CameraSystem.ManualToggled = false
    CameraSystem.LastTargetUserId = false
    runtimeConfig.CameraManualBehavior = behavior
    AutoSave.queueConfigSave()
    CameraSystem.updateTargetLabel(nil)
    CameraSystem.syncControls()
    showToast(behavior == "hold" and "Mantener tecla seleccionado."
        or "Tocar para alternar seleccionado.")
end

function CameraSystem.setKey(binding)
    CameraSystem.Binding = binding
    CameraSystem.IsBindingKey = false
    CameraSystem.ManualHeld = false
    CameraSystem.ManualToggled = false
    runtimeConfig.CameraAimKey = binding
    AutoSave.queueConfigSave()
    CameraSystem.syncControls()
    showToast("Control del aim: " .. keyLabel(binding))
end

function CameraSystem.setFovVisible(state)
    CameraSystem.FovVisible = state == true
    runtimeConfig.CameraFovVisible = CameraSystem.FovVisible
    AutoSave.queueConfigSave()
    CameraSystem.syncControls()
end

function CameraSystem.setFovRadius(value)
    CameraSystem.FovRadius = math.clamp(
        math.floor((tonumber(value) or CameraSystem.FovRadius) / 10 + 0.5) * 10,
        50,
        320
    )
    runtimeConfig.CameraFovRadius = CameraSystem.FovRadius
    AutoSave.queueConfigSave()
    CameraSystem.syncControls()
end

function CameraSystem.setMaxDistance(value)
    local numericValue = tonumber(value)
    if not numericValue then
        CameraSystem.syncControls()
        return
    end
    CameraSystem.MaxDistance = math.clamp(math.floor(numericValue + 0.5), 5, 5000)
    runtimeConfig.CameraMaxDistance = CameraSystem.MaxDistance
    AutoSave.queueConfigSave()
    CameraSystem.LastTargetUserId = false
    CameraSystem.updateTargetLabel(nil)
    CameraSystem.syncControls()
end

function CameraSystem.setSmoothIntensity(value)
    local numericValue = tonumber(value)
    if not numericValue then
        CameraSystem.syncControls()
        return
    end
    CameraSystem.SmoothIntensity = math.clamp(
        math.floor(numericValue + 0.5),
        1,
        100
    )
    runtimeConfig.CameraSmoothIntensity = CameraSystem.SmoothIntensity
    AutoSave.queueConfigSave()
    CameraSystem.syncControls()
end

function CameraSystem.setTargetZone(zone)
    if zone ~= "feet" and zone ~= "body" and zone ~= "head" then
        return
    end
    CameraSystem.TargetZone = zone
    runtimeConfig.CameraTargetZone = zone
    AutoSave.queueConfigSave()
    CameraSystem.LastTargetUserId = false
    CameraSystem.updateTargetLabel(nil)
    CameraSystem.syncControls()
end

function CameraSystem.setMode(mode)
    if mode ~= "hard" and mode ~= "smooth" then
        return
    end
    CameraSystem.Mode = mode
    runtimeConfig.CameraMode = mode
    AutoSave.queueConfigSave()
    CameraSystem.syncControls()
    showToast(mode == "hard" and "Aim brusco seleccionado." or "Aim suave seleccionado.")
end

function CameraSystem.updateFrame(deltaTime)
    local camera = Workspace.CurrentCamera
    if not camera then
        return
    end

    CameraSystem.UI.FovCircle.Position = UDim2.fromOffset(
        camera.ViewportSize.X * 0.5,
        camera.ViewportSize.Y * 0.5
    )
    if not CameraSystem.isEngaged() then
        if CameraSystem.TargetPlayer then
            CameraSystem.LastTargetUserId = false
            CameraSystem.updateTargetLabel(nil)
        end
        return
    end

    local player, targetPosition = CameraSystem.findTarget(camera)
    CameraSystem.updateTargetLabel(player)
    if not targetPosition then
        return
    end

    local current = camera.CFrame
    local desired = CFrame.lookAt(current.Position, targetPosition)
    if CameraSystem.Mode == "hard" then
        camera.CFrame = desired
    else
        local smoothSpeed = 1.5 + CameraSystem.SmoothIntensity * 0.243
        local alpha = 1 - math.exp(-smoothSpeed * math.clamp(deltaTime, 0, 0.1))
        camera.CFrame = current:Lerp(desired, alpha)
    end
end

local function updatePlayerKeyButton(userId)
    local button = playerKeyButtons[userId]
    if not button or not button.Parent then
        return
    end

    if isBindingPlayerKey
        and pendingBindingPlayer
        and pendingBindingPlayer.UserId == userId then
        button.Text = "..."
        button.BackgroundColor3 = THEME.Accent
        button.TextColor3 = THEME.White
        return
    end

    local assignedKey = boundKeyByUserId[userId]
    button.Text = assignedKey and keyLabel(assignedKey) or "KEY"
    button.BackgroundColor3 = assignedKey and THEME.Accent or THEME.PanelAlt
    button.TextColor3 = assignedKey and THEME.White or THEME.AccentText
end

function CameraSystem.setTeamCheck(state)
    CameraSystem.TeamCheck = state == true
    CameraSystem.TeamCache = setmetatable({}, {__mode = "k"})
    CameraSystem.TeamSignalCache = setmetatable({}, {__mode = "k"})
    runtimeConfig.CameraTeamCheck = CameraSystem.TeamCheck
    AutoSave.queueConfigSave()
    CameraSystem.LastTargetUserId = false
    CameraSystem.updateTargetLabel(nil)
    CameraSystem.syncControls()
    showToast(CameraSystem.TeamCheck
        and "Team Check activado: tus companeros seran ignorados."
        or "Team Check desactivado: se detectaran todos.")
end

AutoSave.storePlayerBindings = function()
    local storedBindings = {}
    for userId, keyCode in pairs(boundKeyByUserId) do
        local binding = playerKeybinds[keyCode]
        if binding then
            storedBindings[tostring(userId)] = {
                Key = keyCode.Name,
                DisplayName = binding.DisplayName,
            }
        end
    end
    runtimeConfig.TPBindings = storedBindings
    AutoSave.queueConfigSave()
end

local function clearPlayerBinding(userId)
    local removedKey = boundKeyByUserId[userId]

    for keyCode, binding in pairs(playerKeybinds) do
        if binding.UserId == userId then
            playerKeybinds[keyCode] = nil
            removedKey = removedKey or keyCode
        end
    end

    boundKeyByUserId[userId] = nil
    updatePlayerKeyButton(userId)
    AutoSave.storePlayerBindings()
    return removedKey
end

local function cancelPlayerKeyCapture(showMessage)
    local previousPlayer = pendingBindingPlayer
    isBindingPlayerKey = false
    pendingBindingPlayer = nil

    if previousPlayer then
        updatePlayerKeyButton(previousPlayer.UserId)
    end

    if showMessage then
        showToast("Asignacion de tecla cancelada.")
    end
end

local function startPlayerKeyCapture(target)
    if not target or target.Parent ~= Players then
        showToast("El jugador ya no esta disponible.")
        return
    end

    if isBindingKey then
        showToast("Termina primero el cambio de tecla del menu.")
        return
    end

    if CameraSystem.IsBindingKey or VisionSystem.IsBindingKey then
        showToast("Termina primero el cambio de control del aim o zoom.")
        return
    end

    local previousPlayer = pendingBindingPlayer
    isBindingPlayerKey = true
    pendingBindingPlayer = target

    if previousPlayer and previousPlayer.UserId ~= target.UserId then
        updatePlayerKeyButton(previousPlayer.UserId)
    end

    updatePlayerKeyButton(target.UserId)
    showToast("Presiona una tecla para " .. target.DisplayName .. ". ESC cancela.")
end

local function assignPlayerKey(target, keyCode)
    if not target or target.Parent ~= Players then
        cancelPlayerKeyCapture(false)
        showToast("El jugador se desconecto. No se guardo la tecla.")
        return
    end

    local displacedBinding = playerKeybinds[keyCode]
    local displacedName = nil
    if displacedBinding and displacedBinding.UserId ~= target.UserId then
        displacedName = displacedBinding.DisplayName
        clearPlayerBinding(displacedBinding.UserId)
    end

    clearPlayerBinding(target.UserId)
    playerKeybinds[keyCode] = {
        UserId = target.UserId,
        DisplayName = target.DisplayName,
    }
    boundKeyByUserId[target.UserId] = keyCode
    AutoSave.storePlayerBindings()

    isBindingPlayerKey = false
    pendingBindingPlayer = nil
    updatePlayerKeyButton(target.UserId)

    local message = keyLabel(keyCode) .. " asignada a " .. target.DisplayName .. "."
    if displacedName then
        message = message .. " Reemplazo a " .. displacedName .. "."
    end
    logMessage(message, THEME.Accent)
    showToast(message)
end

AutoSave.restorePlayerBindings = function()
    local storedBindings = runtimeConfig.TPBindings
    if type(storedBindings) ~= "table" then
        runtimeConfig.TPBindings = {}
        return
    end

    for userIdText, storedBinding in pairs(storedBindings) do
        local userId = tonumber(userIdText)
        local target = userId and Players:GetPlayerByUserId(userId) or nil
        local keyCode = nil
        if type(storedBinding) == "table" and type(storedBinding.Key) == "string" then
            pcall(function()
                keyCode = Enum.KeyCode[storedBinding.Key]
            end)
        end

        local keyAvailable = keyCode
            and keyCode ~= Enum.KeyCode.Unknown
            and keyCode ~= toggleKey
            and keyCode ~= VisionSystem.ZoomBinding
            and not (CameraSystem.Binding.EnumType == Enum.KeyCode
                and keyCode == CameraSystem.Binding)
            and playerKeybinds[keyCode] == nil

        if target and target ~= LocalPlayer and keyAvailable then
            playerKeybinds[keyCode] = {
                UserId = target.UserId,
                DisplayName = target.DisplayName,
            }
            boundKeyByUserId[target.UserId] = keyCode
        end
    end

    -- Descarta automaticamente jugadores que ya no estan en el servidor.
    AutoSave.storePlayerBindings()
end

local function playerMatches(player, filterText)
    local filter = string.lower(filterText or "")
    if filter == "" then
        return true
    end

    return string.find(string.lower(player.Name), filter, 1, true) ~= nil
        or string.find(string.lower(player.DisplayName), filter, 1, true) ~= nil
end

refreshPlayerList = function(filterText)
    disconnectPool(playerCardConnections)
    playerKeyButtons = {}
    EspSystem.FriendStripes = setmetatable({}, {__mode = "k"})

    for _, child in ipairs(PlayerList:GetChildren()) do
        if child:IsA("Frame") or child:IsA("TextLabel") then
            child:Destroy()
        end
    end

    local matches = {}
    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer and playerMatches(player, filterText) then
            table.insert(matches, player)
        end
    end

    table.sort(matches, function(a, b)
        return string.lower(a.DisplayName) < string.lower(b.DisplayName)
    end)

    local total = math.max(0, #Players:GetPlayers() - 1)
    if filterText and filterText ~= "" then
        PlayerCount.Text = string.format("%d DE %d JUGADORES", #matches, total)
    else
        PlayerCount.Text = string.format("%d JUGADORES DISPONIBLES", total)
    end

    if #matches == 0 then
        create("TextLabel", {
            Name = "EmptyState",
            Size = UDim2.fromOffset(350, 76),
            BackgroundColor3 = THEME.Panel,
            BorderSizePixel = 0,
            Text = total == 0
                and "No hay otros jugadores en el servidor."
                or "No se encontraron jugadores.",
            TextColor3 = THEME.Muted,
            Font = Enum.Font.BuilderSansMedium,
            TextSize = 13,
            TextWrapped = true,
        }, PlayerList)
        return
    end

    for index, player in ipairs(matches) do
        local targetPlayer = player
        local card = create("Frame", {
            Name = "PlayerCard",
            LayoutOrder = index,
            BackgroundColor3 = THEME.Panel,
            BorderSizePixel = 0,
        }, PlayerList)
        corner(card, 4)
        local cardStroke = stroke(card, THEME.BorderSoft, 0, 1)

        local friendStripe = create("Frame", {
            Name = "FriendStripe",
            Size = UDim2.fromOffset(3, 76),
            BackgroundColor3 = Color3.fromRGB(64, 225, 128),
            BorderSizePixel = 0, Visible = false,
        }, card)
        EspSystem.FriendStripes[targetPlayer] = friendStripe
        EspSystem.updateFriendStripe(targetPlayer, EspSystem.isFriend(targetPlayer))

        local avatar = create("ImageLabel", {
            Position = UDim2.fromOffset(13, 12),
            Size = UDim2.fromOffset(52, 52),
            BackgroundColor3 = THEME.Input,
            BorderSizePixel = 0,
            Image = "",
        }, card)
        corner(avatar, 3)

        create("TextLabel", {
            Position = UDim2.fromOffset(76, 13),
            Size = UDim2.new(1, -206, 0, 23),
            BackgroundTransparency = 1,
            Text = targetPlayer.DisplayName,
            TextColor3 = THEME.White,
            Font = Enum.Font.BuilderSansBold,
            TextSize = 13,
            TextTruncate = Enum.TextTruncate.AtEnd,
            TextXAlignment = Enum.TextXAlignment.Left,
        }, card)

        create("TextLabel", {
            Position = UDim2.fromOffset(76, 37),
            Size = UDim2.new(1, -206, 0, 20),
            BackgroundTransparency = 1,
            Text = "@" .. targetPlayer.Name,
            TextColor3 = THEME.Muted,
            Font = Enum.Font.BuilderSansMedium,
            TextSize = 12,
            TextTruncate = Enum.TextTruncate.AtEnd,
            TextXAlignment = Enum.TextXAlignment.Left,
        }, card)

        local tpButton = create("TextButton", {
            AnchorPoint = Vector2.new(1, 0.5),
            Position = UDim2.new(1, -12, 0.5, 0),
            Size = UDim2.fromOffset(48, 34),
            BackgroundColor3 = THEME.PanelAlt,
            BorderSizePixel = 0,
            Text = "TP",
            TextColor3 = THEME.AccentText,
            Font = Enum.Font.BuilderSansBold,
            TextSize = 13,
            AutoButtonColor = false,
        }, card)
        corner(tpButton, 3)
        stroke(tpButton, THEME.Border, 0, 1)

        local assignedKey = boundKeyByUserId[targetPlayer.UserId]
        local awaitingKey = isBindingPlayerKey
            and pendingBindingPlayer
            and pendingBindingPlayer.UserId == targetPlayer.UserId
        local keyButton = create("TextButton", {
            AnchorPoint = Vector2.new(1, 0.5),
            Position = UDim2.new(1, -68, 0.5, 0),
            Size = UDim2.fromOffset(48, 34),
            BackgroundColor3 = (assignedKey or awaitingKey) and THEME.Accent or THEME.PanelAlt,
            BorderSizePixel = 0,
            Text = awaitingKey and "..." or (assignedKey and keyLabel(assignedKey) or "KEY"),
            TextColor3 = (assignedKey or awaitingKey) and THEME.White or THEME.AccentText,
            Font = Enum.Font.BuilderSansBold,
            TextSize = 12,
            TextTruncate = Enum.TextTruncate.AtEnd,
            AutoButtonColor = false,
        }, card)
        corner(keyButton, 3)
        stroke(keyButton, THEME.Border, 0, 1)
        playerKeyButtons[targetPlayer.UserId] = keyButton

        connectPooled(playerCardConnections, card.MouseEnter, function()
            tween(card, 0.12, {BackgroundColor3 = THEME.PanelAlt})
            cardStroke.Color = THEME.Accent
        end)

        connectPooled(playerCardConnections, card.MouseLeave, function()
            tween(card, 0.12, {BackgroundColor3 = THEME.Panel})
            cardStroke.Color = THEME.BorderSoft
        end)

        connectPooled(playerCardConnections, tpButton.MouseEnter, function()
            tween(tpButton, 0.12, {
                BackgroundColor3 = THEME.Accent,
                TextColor3 = THEME.White,
            })
        end)

        connectPooled(playerCardConnections, tpButton.MouseLeave, function()
            tween(tpButton, 0.12, {
                BackgroundColor3 = THEME.PanelAlt,
                TextColor3 = THEME.AccentText,
            })
        end)

        connectPooled(playerCardConnections, keyButton.MouseEnter, function()
            tween(keyButton, 0.12, {
                BackgroundColor3 = THEME.AccentHover,
                TextColor3 = THEME.White,
            })
        end)

        connectPooled(playerCardConnections, keyButton.MouseLeave, function()
            updatePlayerKeyButton(targetPlayer.UserId)
        end)

        connectPooled(playerCardConnections, keyButton.MouseButton1Click, function()
            local existingKey = boundKeyByUserId[targetPlayer.UserId]
            if existingKey then
                clearPlayerBinding(targetPlayer.UserId)
                local message = keyLabel(existingKey) .. " eliminada de "
                    .. targetPlayer.DisplayName .. "."
                logMessage(message, THEME.Muted)
                showToast(message .. " Toca KEY otra vez para elegir otra.")
                return
            end

            startPlayerKeyCapture(targetPlayer)
        end)

        connectPooled(playerCardConnections, tpButton.MouseButton1Click, function()
            local success, message = teleportToPlayer(targetPlayer)
            logMessage(message, success and THEME.Accent or THEME.Text)
            showToast(message)
        end)

        task.spawn(function()
            local success, image = pcall(function()
                return Players:GetUserThumbnailAsync(
                    targetPlayer.UserId,
                    Enum.ThumbnailType.HeadShot,
                    Enum.ThumbnailSize.Size150x150
                )
            end)

            if success and avatar.Parent then
                avatar.Image = image
            end
        end)
    end
end

local commandOrder = {}
local commands = {}

local function addCommand(name, description, usage, callback)
    commands[name] = {
        Description = description,
        Usage = usage,
        Callback = callback,
    }
    table.insert(commandOrder, name)
end

addCommand("cmds", "Muestra los comandos disponibles.", "cmds", function()
    logMessage("-- COMANDOS DISPONIBLES --", THEME.Accent)
    for _, commandName in ipairs(commandOrder) do
        local command = commands[commandName]
        logMessage(command.Usage .. "  |  " .. command.Description, THEME.Text)
    end
end)

addCommand("to", "Teletransporte directo a un jugador.", "to <jugador>", function(arguments)
    if not arguments[1] then
        logMessage("Uso: to <jugador>", THEME.Muted)
        return
    end

    local target = getPlayer(arguments[1])
    if not target then
        logMessage("Jugador no encontrado.", THEME.Text)
        showToast("Jugador no encontrado.")
        return
    end

    local success, message = teleportToPlayer(target)
    logMessage(message, success and THEME.Accent or THEME.Text)
    showToast(message)
end)

addCommand("tpmenu", "Abre la lista visual de jugadores.", "tpmenu", function()
    openTPVisual()
    logMessage("TP Menu abierto en una nueva pestana.", THEME.Accent)
end)

addCommand("hitbox", "Abre el control de hitbox por zonas.", "hitbox", function()
    openHitboxVisual()
    logMessage("Hitbox abierto en una nueva pestana.", THEME.Accent)
end)

addCommand("esp", "Abre lineas, cajas, esqueleto y rueda de proximidad.", "esp", function()
    openEspVisual()
    logMessage("ESP abierto en una nueva pestana.", THEME.Accent)
end)

addCommand("cam", "Abre el aim de camara con circulo FOV.", "cam", function()
    CameraSystem.openVisual()
    logMessage("Aim de camara abierto en una nueva pestana.", THEME.Accent)
end)

for _, commandName in ipairs({"vision", "luz", "zoom"}) do
    addCommand(commandName, "Abre iluminacion persistente y zoom configurable.", commandName, function()
        VisionSystem.openVisual()
    end)
end

local function cleanup()
    if destroyed then
        return
    end

    if Compact.stopIntro then Compact.stopIntro(false) end
    if Compact.cancelMotion then Compact.cancelMotion() end
    AutoSave.saveConfigNow()
    destroyed = true
    hitboxEnabled = false
    HitboxSystem.stopWatching()
    VisionSystem.cleanup()
    EspSystem.FriendCache = {}

    restoreAllHitboxes()
    EspSystem.removeAll()
    EspSystem.hideRearAlert()
    CameraSystem.Enabled = false
    CameraSystem.UI.FovCircle.Visible = false
    pcall(function()
        RunService:UnbindFromRenderStep("CDT_Optifine_CameraAim")
    end)
    destroyed = true
    disconnectPool(playerCardConnections)
    disconnectPool(suggestionConnections)

    for _, connection in ipairs(mainConnections) do
        if connection and connection.Connected then
            connection:Disconnect()
        end
    end

    runtimeEnvironment.CDT_Optifine_Cleanup = nil
    if ScreenGui.Parent then
        ScreenGui:Destroy()
    end
    if CameraSystem.UI.OverlayGui.Parent then
        CameraSystem.UI.OverlayGui:Destroy()
    end
end

runtimeEnvironment.CDT_Optifine_Cleanup = cleanup

addCommand("destroy", "Cierra y elimina completamente el menu.", "destroy", function()
    logMessage("Cerrando X.T.E.Y.X...", THEME.Muted)
    task.delay(0.2, cleanup)
end)

clearSuggestions = function()
    disconnectPool(suggestionConnections)
    for _, child in ipairs(SuggestionFrame:GetChildren()) do
        if child:IsA("TextButton") then
            child:Destroy()
        end
    end
    SuggestionFrame.Visible = false
end

local function commandTokens(text)
    local tokens = {}
    for token in string.gmatch(text, "%S+") do
        table.insert(tokens, token)
    end
    return tokens
end

local function updateSuggestions()
    clearSuggestions()

    local loweredText = string.lower(CommandBox.Text)
    if loweredText == "" then
        return
    end

    local tokens = commandTokens(loweredText)
    local endsWithSpace = string.sub(loweredText, -1) == " "
    local suggestions = {}

    if #tokens <= 1 and not endsWithSpace then
        local prefix = tokens[1] or ""
        for _, commandName in ipairs(commandOrder) do
            if string.sub(commandName, 1, #prefix) == prefix then
                local command = commands[commandName]
                table.insert(suggestions, {
                    Display = command.Usage .. "  -  " .. command.Description,
                    Fill = commandName == "to" and "to " or commandName,
                })
            end
        end
    elseif tokens[1] == "to" and (#tokens == 1 or #tokens == 2) then
        local prefix = tokens[2] or ""
        for _, player in ipairs(Players:GetPlayers()) do
            if player ~= LocalPlayer then
                local username = string.lower(player.Name)
                local displayName = string.lower(player.DisplayName)
                if prefix == ""
                    or string.sub(username, 1, #prefix) == prefix
                    or string.sub(displayName, 1, #prefix) == prefix then
                    table.insert(suggestions, {
                        Display = player.DisplayName .. "  (@" .. player.Name .. ")",
                        Fill = "to " .. player.Name,
                    })
                end
            end
        end
    end

    local maximum = math.min(#suggestions, 4)
    if maximum == 0 then
        return
    end

    for index = 1, maximum do
        local suggestion = suggestions[index]
        local button = create("TextButton", {
            LayoutOrder = index,
            Size = UDim2.new(1, -4, 0, 30),
            BackgroundColor3 = THEME.PanelAlt,
            BackgroundTransparency = 1,
            BorderSizePixel = 0,
            Text = suggestion.Display,
            TextColor3 = THEME.Text,
            Font = Enum.Font.BuilderSansMedium,
            TextSize = 13,
            TextXAlignment = Enum.TextXAlignment.Left,
            AutoButtonColor = false,
            ZIndex = 31,
        }, SuggestionFrame)
        corner(button, 3)
        padding(button, 10, 5, 0, 0)
        button:SetAttribute("Fill", suggestion.Fill)

        connectPooled(suggestionConnections, button.MouseEnter, function()
            button.BackgroundTransparency = 0
            button.TextColor3 = THEME.AccentText
        end)

        connectPooled(suggestionConnections, button.MouseLeave, function()
            button.BackgroundTransparency = 1
            button.TextColor3 = THEME.Text
        end)

        connectPooled(suggestionConnections, button.MouseButton1Click, function()
            CommandBox.Text = suggestion.Fill
            CommandBox.CursorPosition = #suggestion.Fill + 1
            CommandBox:CaptureFocus()
            clearSuggestions()
        end)
    end

    local height = maximum * 33 + 10
    SuggestionFrame.Size = UDim2.fromOffset(376, height)
    SuggestionFrame.Position = UDim2.fromOffset(12, CommandBar.Position.Y.Offset - 8 - height)
    SuggestionFrame.CanvasSize = UDim2.fromOffset(0, maximum * 33)
    SuggestionFrame.Visible = true
end

local function runCommand(rawText)
    local trimmed = string.match(rawText or "", "^%s*(.-)%s*$")
    if not trimmed or trimmed == "" then
        return
    end

    local tokens = commandTokens(trimmed)
    local commandName = string.lower(tokens[1] or "")
    table.remove(tokens, 1)

    CommandBox.Text = ""
    clearSuggestions()
    logMessage("> " .. trimmed, THEME.Muted)

    local command = commands[commandName]
    if not command then
        logMessage("Comando desconocido. Escribe cmds para ver la lista.", THEME.Text)
        return
    end

    local success, errorMessage = pcall(command.Callback, tokens)
    if not success then
        logMessage("No se pudo ejecutar el comando.", THEME.Text)
        warn("[X.T.E.Y.X] " .. tostring(errorMessage))
    end
end

HitboxSystem.bindRegionControls = function(regionName)
    local controls = HitboxSystem.UI.Regions[regionName]
    local region = HitboxSystem.Regions[regionName]

    connect(controls.Toggle.MouseButton1Click, function()
        HitboxSystem.setRegionEnabled(regionName, not region.Enabled)
    end)
    connect(controls.Minus.MouseButton1Click, function()
        HitboxSystem.setRegionSize(regionName, region.Size - 0.5)
    end)
    connect(controls.Plus.MouseButton1Click, function()
        HitboxSystem.setRegionSize(regionName, region.Size + 0.5)
    end)
    connect(controls.Value.FocusLost, function()
        HitboxSystem.setRegionSize(regionName, controls.Value.Text)
    end)
    connect(controls.Toggle.MouseEnter, function()
        tween(controls.Toggle, 0.12, {
            BackgroundColor3 = region.Enabled and THEME.AccentHover or THEME.Hover,
        })
    end)
    connect(controls.Toggle.MouseLeave, syncHitboxControls)
    addHover(controls.Minus, THEME.Input, THEME.Hover)
    addHover(controls.Plus, THEME.Input, THEME.Hover)
end

HitboxSystem.bindRegionControls("legs")
HitboxSystem.bindRegionControls("feet")
HitboxSystem.bindRegionControls("body")
HitboxSystem.bindRegionControls("head")
HitboxSystem.bindRegionControls = nil

connect(TerminalTab.MouseButton1Click, function()
    switchPage("terminal")
end)

connect(PlayersTab.MouseButton1Click, function()
    if tpTabOpen then
        switchPage("players")
    end
end)

connect(HitboxTab.MouseButton1Click, function()
    if hitboxTabOpen then
        switchPage("hitbox")
    end
end)

connect(EspTab.MouseButton1Click, function()
    if espTabOpen then
        switchPage("esp")
    end
end)

connect(CameraSystem.UI.Tab.MouseButton1Click, function()
    if CameraSystem.TabOpen then
        switchPage("camera")
    end
end)

connect(SettingsTab.MouseButton1Click, function()
    switchPage("settings")
end)

connect(OpenTPButton.MouseButton1Click, function()
    openTPVisual()
end)

connect(CloseTPTabButton.MouseButton1Click, closeTPVisual)
connect(CloseHitboxTabButton.MouseButton1Click, closeHitboxVisual)
connect(CloseEspTabButton.MouseButton1Click, closeEspVisual)
connect(CameraSystem.UI.Close.MouseButton1Click, CameraSystem.closeVisual)

connect(ShowCmdsButton.MouseButton1Click, function()
    runCommand("cmds")
end)

connect(ExecuteButton.MouseButton1Click, function()
    runCommand(CommandBox.Text)
end)

connect(CommandBox.FocusLost, function(enterPressed)
    if enterPressed then
        runCommand(CommandBox.Text)
    end
end)

connect(CommandBox:GetPropertyChangedSignal("Text"), updateSuggestions)

connect(PlayerSearch:GetPropertyChangedSignal("Text"), function()
    runtimeConfig.TPSearch = PlayerSearch.Text
    AutoSave.queueConfigSave()
    refreshPlayerList(PlayerSearch.Text)
end)

connect(RefreshPlayersButton.MouseButton1Click, function()
    refreshPlayerList(PlayerSearch.Text)
    showToast("Lista de jugadores actualizada.")
end)

connect(HitboxToggleButton.MouseButton1Click, function()
    setHitboxEnabled(not hitboxEnabled)
end)

connect(HitboxVisualButton.MouseButton1Click, function()
    setHitboxVisible(not hitboxVisible)
end)

connect(HitboxToggleButton.MouseEnter, function()
    tween(HitboxToggleButton, 0.12, {
        BackgroundColor3 = hitboxEnabled and hitboxVisible and THEME.AccentHover or THEME.Hover,
    })
end)

connect(HitboxToggleButton.MouseLeave, syncHitboxControls)

connect(HitboxVisualButton.MouseEnter, function()
    tween(HitboxVisualButton, 0.12, {
        BackgroundColor3 = hitboxVisible and THEME.AccentHover or THEME.Hover,
    })
end)

connect(HitboxVisualButton.MouseLeave, syncHitboxControls)

connect(EspMasterButton.MouseButton1Click, function()
    EspSystem.setEnabled(not espEnabled)
end)

connect(EspLinesButton.MouseButton1Click, function()
    EspSystem.setOption("lines", not espLinesEnabled)
end)

connect(EspBoxesButton.MouseButton1Click, function()
    EspSystem.setOption("boxes", not espBoxesEnabled)
end)

connect(EspSkeletonButton.MouseButton1Click, function()
    EspSystem.setOption("skeleton", not espSkeletonEnabled)
end)

connect(RearAlertButton.MouseButton1Click, function()
    EspSystem.setOption("rear", not rearAlertEnabled)
end)

connect(RearDistanceMinus.MouseButton1Click, function()
    EspSystem.setRearDistance(rearAlertDistance - 5)
end)

connect(RearDistancePlus.MouseButton1Click, function()
    EspSystem.setRearDistance(rearAlertDistance + 5)
end)

connect(EspMasterButton.MouseEnter, function()
    tween(EspMasterButton, 0.12, {
        BackgroundColor3 = espEnabled and THEME.AccentHover or THEME.Hover,
    })
end)
connect(EspMasterButton.MouseLeave, syncEspControls)

connect(EspLinesButton.MouseEnter, function()
    tween(EspLinesButton, 0.12, {BackgroundColor3 = THEME.Hover})
end)
connect(EspLinesButton.MouseLeave, syncEspControls)

connect(EspBoxesButton.MouseEnter, function()
    tween(EspBoxesButton, 0.12, {BackgroundColor3 = THEME.Hover})
end)
connect(EspBoxesButton.MouseLeave, syncEspControls)

connect(EspSkeletonButton.MouseEnter, function()
    tween(EspSkeletonButton, 0.12, {BackgroundColor3 = THEME.Hover})
end)
connect(EspSkeletonButton.MouseLeave, syncEspControls)

connect(RearAlertButton.MouseEnter, function()
    tween(RearAlertButton, 0.12, {BackgroundColor3 = THEME.Hover})
end)
connect(RearAlertButton.MouseLeave, syncEspControls)

connect(CameraSystem.UI.Master.MouseButton1Click, function()
    CameraSystem.setEnabled(not CameraSystem.Enabled)
end)

connect(CameraSystem.UI.TeamCheck.MouseButton1Click, function()
    CameraSystem.setTeamCheck(not CameraSystem.TeamCheck)
end)

connect(CameraSystem.UI.FovToggle.MouseButton1Click, function()
    CameraSystem.setFovVisible(not CameraSystem.FovVisible)
end)

connect(CameraSystem.UI.FovMinus.MouseButton1Click, function()
    CameraSystem.setFovRadius(CameraSystem.FovRadius - 10)
end)

connect(CameraSystem.UI.FovPlus.MouseButton1Click, function()
    CameraSystem.setFovRadius(CameraSystem.FovRadius + 10)
end)

connect(CameraSystem.UI.DistanceMinus.MouseButton1Click, function()
    CameraSystem.setMaxDistance(CameraSystem.MaxDistance - 25)
end)

connect(CameraSystem.UI.DistancePlus.MouseButton1Click, function()
    CameraSystem.setMaxDistance(CameraSystem.MaxDistance + 25)
end)

connect(CameraSystem.UI.DistanceValue.FocusLost, function()
    CameraSystem.setMaxDistance(CameraSystem.UI.DistanceValue.Text)
end)

connect(CameraSystem.UI.IntensityMinus.MouseButton1Click, function()
    CameraSystem.setSmoothIntensity(CameraSystem.SmoothIntensity - 5)
end)

connect(CameraSystem.UI.IntensityPlus.MouseButton1Click, function()
    CameraSystem.setSmoothIntensity(CameraSystem.SmoothIntensity + 5)
end)

connect(CameraSystem.UI.IntensityValue.FocusLost, function()
    CameraSystem.setSmoothIntensity(CameraSystem.UI.IntensityValue.Text)
end)

connect(CameraSystem.UI.Feet.MouseButton1Click, function()
    CameraSystem.setTargetZone("feet")
end)

connect(CameraSystem.UI.Body.MouseButton1Click, function()
    CameraSystem.setTargetZone("body")
end)

connect(CameraSystem.UI.Head.MouseButton1Click, function()
    CameraSystem.setTargetZone("head")
end)

connect(CameraSystem.UI.Hard.MouseButton1Click, function()
    CameraSystem.setMode("hard")
end)

connect(CameraSystem.UI.Smooth.MouseButton1Click, function()
    CameraSystem.setMode("smooth")
end)

connect(CameraSystem.UI.Auto.MouseButton1Click, function()
    CameraSystem.setActivationMode("auto")
end)

connect(CameraSystem.UI.Manual.MouseButton1Click, function()
    CameraSystem.setActivationMode("manual")
end)

connect(CameraSystem.UI.Hold.MouseButton1Click, function()
    CameraSystem.setManualBehavior("hold")
end)

connect(CameraSystem.UI.Toggle.MouseButton1Click, function()
    CameraSystem.setManualBehavior("toggle")
end)

connect(CameraSystem.UI.AimKey.MouseButton1Click, function()
    if CameraSystem.IsBindingKey then
        return
    end
    if isBindingKey or isBindingPlayerKey or VisionSystem.IsBindingKey then
        showToast("Termina primero la otra asignacion de tecla.")
        return
    end
    CameraSystem.IsBindingKey = true
    CameraSystem.syncControls()
    showToast("Presiona una tecla o boton del mouse. ESC cancela.")
end)

CameraSystem.bindHover = function(button)
    connect(button.MouseEnter, function()
        tween(button, 0.12, {BackgroundColor3 = THEME.Hover})
    end)
    connect(button.MouseLeave, CameraSystem.syncControls)
end

CameraSystem.bindHover(CameraSystem.UI.Master)
CameraSystem.bindHover(CameraSystem.UI.TeamCheck)
CameraSystem.bindHover(CameraSystem.UI.FovToggle)
CameraSystem.bindHover(CameraSystem.UI.Feet)
CameraSystem.bindHover(CameraSystem.UI.Body)
CameraSystem.bindHover(CameraSystem.UI.Head)
CameraSystem.bindHover(CameraSystem.UI.Hard)
CameraSystem.bindHover(CameraSystem.UI.Smooth)
CameraSystem.bindHover(CameraSystem.UI.Auto)
CameraSystem.bindHover(CameraSystem.UI.Manual)
CameraSystem.bindHover(CameraSystem.UI.AimKey)
CameraSystem.bindHover(CameraSystem.UI.Hold)
CameraSystem.bindHover(CameraSystem.UI.Toggle)
CameraSystem.bindHover = nil
addHover(CameraSystem.UI.FovMinus, THEME.Input, THEME.Hover)
addHover(CameraSystem.UI.FovPlus, THEME.Input, THEME.Hover)
addHover(CameraSystem.UI.DistanceMinus, THEME.Input, THEME.Hover)
addHover(CameraSystem.UI.DistancePlus, THEME.Input, THEME.Hover)
addHover(CameraSystem.UI.IntensityMinus, THEME.Input, THEME.Hover)
addHover(CameraSystem.UI.IntensityPlus, THEME.Input, THEME.Hover)

connect(ChangeKeyButton.MouseButton1Click, function()
    if isBindingKey then
        return
    end

    if isBindingPlayerKey then
        showToast("Termina primero la tecla del jugador o cancela con ESC.")
        return
    end

    if CameraSystem.IsBindingKey or VisionSystem.IsBindingKey then
        showToast("Termina primero la tecla del aim o zoom, o cancela con ESC.")
        return
    end

    isBindingKey = true
    CurrentKey.Text = "..."
    ChangeKeyButton.Text = "Pulsa una tecla"
end)

connect(VisionSystem.UI.Tab.MouseButton1Click, VisionSystem.openVisual)
connect(VisionSystem.UI.Close.MouseButton1Click, VisionSystem.closeVisual)
connect(VisionSystem.UI.LightToggle.MouseButton1Click, function()
    VisionSystem.setLightEnabled(not VisionSystem.LightEnabled)
end)
connect(VisionSystem.UI.ZoomToggle.MouseButton1Click, function()
    VisionSystem.setZoomEnabled(not VisionSystem.ZoomEnabled)
end)
connect(VisionSystem.UI.ZoomHold.MouseButton1Click, function() VisionSystem.setZoomBehavior("hold") end)
connect(VisionSystem.UI.ZoomToggleMode.MouseButton1Click, function() VisionSystem.setZoomBehavior("toggle") end)
connect(VisionSystem.UI.ZoomValue.FocusLost, function()
    VisionSystem.setZoomFactor(string.gsub(VisionSystem.UI.ZoomValue.Text, ",", "."))
end)
connect(VisionSystem.UI.ZoomValue.MouseLeave, function()
    if not VisionSystem.UI.ZoomValue:IsFocused() then VisionSystem.syncControls() end
end)
connect(VisionSystem.UI.ZoomKey.MouseButton1Click, function()
    if isBindingKey or isBindingPlayerKey or CameraSystem.IsBindingKey then
        showToast("Termina primero la otra asignacion de tecla.")
        return
    end
    VisionSystem.releaseZoom(true)
    VisionSystem.IsBindingKey = true
    VisionSystem.syncControls()
end)

do
    local drag = nil
    local function updateSlider(input)
        if not drag then return end
        local track = drag.Controls.Track
        if track.AbsoluteSize.X <= 0 then return end
        local ratio = math.clamp((input.Position.X - track.AbsolutePosition.X) / track.AbsoluteSize.X, 0, 1)
        drag.Set(drag.Min + ratio * (drag.Max - drag.Min))
    end
    local function bindSlider(controls, minimum, maximum, setter)
        connect(controls.Track.InputBegan, function(input)
            if input.UserInputType == Enum.UserInputType.MouseButton1
                or input.UserInputType == Enum.UserInputType.Touch then
                drag = {Controls = controls, Min = minimum, Max = maximum, Set = setter, Input = input}
                updateSlider(input)
            end
        end)
    end
    bindSlider(VisionSystem.UI.LightSlider, 1, 5, VisionSystem.setLightStrength)
    bindSlider(VisionSystem.UI.ZoomSlider, 1.5, 15, VisionSystem.setZoomFactor)
    connect(UserInputService.InputChanged, function(input)
        if drag and (input == drag.Input or (drag.Input.UserInputType == Enum.UserInputType.MouseButton1
            and input.UserInputType == Enum.UserInputType.MouseMovement)) then updateSlider(input) end
    end)
    connect(UserInputService.InputEnded, function(input)
        if drag and (input == drag.Input or (input.UserInputType == Enum.UserInputType.MouseButton1
            and drag.Input.UserInputType == Enum.UserInputType.MouseButton1)) then drag = nil end
    end)
    connect(UserInputService.WindowFocusReleased, function()
        drag = nil
        VisionSystem.releaseZoom(true)
        VisionSystem.cancelCapture()
    end)
end

connect(UserInputService.TextBoxFocused, function() VisionSystem.releaseZoom(true) end)
connect(LocalPlayer.CharacterRemoving, function() VisionSystem.releaseZoom(true) end)
connect(LocalPlayer.CharacterAdded, function()
    -- No se apaga ni se reinicia la iluminacion al reaparecer.
    VisionSystem.queueLightRefresh()
end)
connect(Workspace:GetPropertyChangedSignal("CurrentCamera"), function()
    VisionSystem.refreshLightRoots()
    VisionSystem.detachZoomCamera()
    if VisionSystem.ZoomActive then VisionSystem.attachZoomCamera(Workspace.CurrentCamera) end
end)
RunService:BindToRenderStep("CDT_Optifine_Zoom", Enum.RenderPriority.Camera.Value + 1, VisionSystem.updateZoom)
VisionSystem.syncControls()


AutoSave.WindowScaleDragging = false
AutoSave.setWindowScaleFromPointer = function(pointerX)
    local trackWidth = AutoSave.UI.WindowScaleTrack.AbsoluteSize.X
    if trackWidth <= 0 then
        return
    end
    local ratio = math.clamp(
        (pointerX - AutoSave.UI.WindowScaleTrack.AbsolutePosition.X) / trackWidth,
        0,
        1
    )
    AutoSave.setWindowScale(1 + ratio * 0.25)
end

connect(AutoSave.UI.WindowScaleTrack.InputBegan, function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1
        or input.UserInputType == Enum.UserInputType.Touch then
        AutoSave.WindowScaleDragging = true
        AutoSave.setWindowScaleFromPointer(input.Position.X)
    end
end)

connect(UserInputService.InputChanged, function(input)
    if AutoSave.WindowScaleDragging
        and (input.UserInputType == Enum.UserInputType.MouseMovement
            or input.UserInputType == Enum.UserInputType.Touch) then
        AutoSave.setWindowScaleFromPointer(input.Position.X)
    end
end)

connect(UserInputService.InputEnded, function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1
        or input.UserInputType == Enum.UserInputType.Touch then
        AutoSave.WindowScaleDragging = false
    end
end)

connect(MinimizeButton.Activated, function()
    setMinimized(not minimized)
end)

connect(UserInputService.InputBegan, function(input, gameProcessed)
    if VisionSystem.IsBindingKey then
        VisionSystem.captureInput(input)
        return
    end
    if CameraSystem.IsBindingKey then
        local keyboardInput = input.UserInputType == Enum.UserInputType.Keyboard
        local mouseInput = CameraSystem.isMouseButton(input.UserInputType)
        if not keyboardInput and not mouseInput then
            return
        end

        if keyboardInput and input.KeyCode == Enum.KeyCode.Escape then
            CameraSystem.IsBindingKey = false
            CameraSystem.syncControls()
            showToast("Cambio de control del aim cancelado.")
            return
        end

        local selectedInput = keyboardInput and input.KeyCode or input.UserInputType
        if selectedInput == Enum.KeyCode.Unknown then
            return
        end

        if selectedInput == VisionSystem.ZoomBinding then
            showToast("Ese control esta reservado para el zoom.")
            return
        end
        if selectedInput == toggleKey then
            showToast(keyLabel(toggleKey) .. " esta reservada para minimizar.")
            return
        end

        if selectedInput.EnumType == Enum.KeyCode then
            local displacedBinding = playerKeybinds[selectedInput]
            if displacedBinding then
                clearPlayerBinding(displacedBinding.UserId)
                logMessage(
                    "Tecla de " .. displacedBinding.DisplayName
                        .. " liberada para el aim.",
                    THEME.Muted
                )
            end
        end
        CameraSystem.setKey(selectedInput)
        return
    end

    if isBindingPlayerKey then
        if input.UserInputType ~= Enum.UserInputType.Keyboard then
            return
        end

        local target = pendingBindingPlayer
        if not target or target.Parent ~= Players then
            cancelPlayerKeyCapture(false)
            showToast("El jugador se desconecto. Asignacion cancelada.")
            return
        end

        if input.KeyCode == Enum.KeyCode.Escape then
            cancelPlayerKeyCapture(true)
            return
        end

        if input.KeyCode == Enum.KeyCode.Backspace
            or input.KeyCode == Enum.KeyCode.Delete then
            local removedKey = clearPlayerBinding(target.UserId)
            cancelPlayerKeyCapture(false)
            if removedKey then
                local message = "Tecla eliminada de " .. target.DisplayName .. "."
                logMessage(message, THEME.Muted)
                showToast(message)
            else
                showToast(target.DisplayName .. " no tenia una tecla asignada.")
            end
            return
        end

        if input.KeyCode == toggleKey then
            showToast(keyLabel(toggleKey) .. " esta reservada para minimizar el menu.")
            return
        end


        if input.KeyCode == VisionSystem.ZoomBinding then
            showToast("Ese control esta reservado para el zoom.")
            return
        end
        if CameraSystem.Binding.EnumType == Enum.KeyCode
            and input.KeyCode == CameraSystem.Binding then
            showToast(keyLabel(CameraSystem.Binding) .. " esta reservada para el aim.")
            return
        end

        if input.KeyCode ~= Enum.KeyCode.Unknown then
            assignPlayerKey(target, input.KeyCode)
        end
        return
    end

    if isBindingKey then
        if input.UserInputType ~= Enum.UserInputType.Keyboard then
            return
        end

        if input.KeyCode == Enum.KeyCode.Escape then
            isBindingKey = false
            ChangeKeyButton.Text = "Cambiar tecla"
            syncKeyLabels()
            showToast("Cambio de tecla cancelado.")
            return
        end

        if input.KeyCode == VisionSystem.ZoomBinding then
            showToast("Ese control esta reservado para el zoom.")
            return
        end
        if CameraSystem.Binding.EnumType == Enum.KeyCode
            and input.KeyCode == CameraSystem.Binding then
            showToast(keyLabel(CameraSystem.Binding) .. " esta reservada para el aim.")
            return
        end

        if input.KeyCode ~= Enum.KeyCode.Unknown then
            local displacedBinding = playerKeybinds[input.KeyCode]
            if displacedBinding then
                clearPlayerBinding(displacedBinding.UserId)
                logMessage(
                    "Tecla de " .. displacedBinding.DisplayName
                        .. " eliminada: ahora minimiza el menu.",
                    THEME.Muted
                )
            end

            toggleKey = input.KeyCode
            runtimeConfig.ToggleKey = toggleKey
    AutoSave.queueConfigSave()
            isBindingKey = false
            ChangeKeyButton.Text = "Cambiar tecla"
            syncKeyLabels()
            showToast("Nueva tecla: " .. keyLabel(toggleKey))
        end
        return
    end

    if input.KeyCode == Enum.KeyCode.Tab
        and CommandBox:IsFocused()
        and SuggestionFrame.Visible then
        for _, child in ipairs(SuggestionFrame:GetChildren()) do
            if child:IsA("TextButton") then
                local fill = child:GetAttribute("Fill")
                if fill then
                    task.defer(function()
                        CommandBox.Text = fill
                        CommandBox.CursorPosition = #fill + 1
                        CommandBox:CaptureFocus()
                    end)
                    clearSuggestions()
                    return
                end
            end
        end
    end

    if not gameProcessed and input.KeyCode == toggleKey then
        setMinimized(not minimized)
        return
    end

    if VisionSystem.handleZoomInput(input, gameProcessed) then return end

    if CameraSystem.Enabled
        and CameraSystem.ActivationMode == "manual"
        and CameraSystem.matchesInput(input)
        and not CameraSystem.pointerOverMenu(input)
        and UserInputService:GetFocusedTextBox() == nil then
        if CameraSystem.ManualBehavior == "hold" then
            CameraSystem.ManualHeld = true
        else
            CameraSystem.ManualToggled = not CameraSystem.ManualToggled
            showToast(CameraSystem.ManualToggled and "Aim manual activado."
                or "Aim manual desactivado.")
        end
        CameraSystem.syncControls()
        return
    end

    if not gameProcessed
        and input.UserInputType == Enum.UserInputType.Keyboard
        and UserInputService:GetFocusedTextBox() == nil then
        local binding = playerKeybinds[input.KeyCode]
        if binding then
            local target = Players:GetPlayerByUserId(binding.UserId)
            if not target or target == LocalPlayer then
                clearPlayerBinding(binding.UserId)
                showToast("Keybind eliminado: el jugador ya no esta disponible.")
                return
            end

            local success, message = teleportToPlayer(target)
            logMessage(message, success and THEME.Accent or THEME.Text)
            showToast(message)
        end
    end
end)

connect(UserInputService.InputEnded, function(input)
    if VisionSystem.ZoomBehavior == "hold" and VisionSystem.matchesInput(input) then
        VisionSystem.releaseZoom(false)
    end
    if CameraSystem.ActivationMode == "manual"
        and CameraSystem.ManualBehavior == "hold"
        and CameraSystem.matchesInput(input) then
        CameraSystem.ManualHeld = false
        CameraSystem.LastTargetUserId = false
        CameraSystem.updateTargetLabel(nil)
        CameraSystem.syncControls()
    end
end)

connect(RunService.Heartbeat, function(deltaTime)
    if destroyed then return end
    EspSystem.maintainRelations()
    EspSystem.FriendRefreshElapsed = (EspSystem.FriendRefreshElapsed or 0) + deltaTime
    if EspSystem.FriendRefreshElapsed >= 5 then
        EspSystem.FriendRefreshElapsed = 0
        if activePage == "players" then
            for player in pairs(EspSystem.FriendStripes) do
                EspSystem.updateFriendStripe(player, EspSystem.isFriend(player))
            end
        end
    end
    hitboxRefreshElapsed = hitboxRefreshElapsed + deltaTime
    if hitboxRefreshElapsed >= 0.75 then
        hitboxRefreshElapsed = 0
        HitboxSystem.auditInactive()
        refreshHitboxes()
    end
end)

connect(RunService.RenderStepped, EspSystem.updateFrame)
RunService:BindToRenderStep(
    "CDT_Optifine_CameraAim",
    Enum.RenderPriority.Camera.Value + 2,
    CameraSystem.updateFrame
)

connect(Players.PlayerAdded, function(player)
    EspSystem.PlayersDirty = true
    watchHitboxPlayer(player)
    if activePage == "players" then
        refreshPlayerList(PlayerSearch.Text)
    end
end)

connect(Players.PlayerRemoving, function(player)
    EspSystem.PlayersDirty = true
    EspSystem.FriendCache[player] = nil
    CameraSystem.TeamCache[player] = nil
    CameraSystem.TeamSignalCache[player] = nil
    HitboxSystem.unwatchPlayer(player)
    EspSystem.FriendStripes[player] = nil
    EspSystem.removeEntry(player)
    if CameraSystem.TargetPlayer == player then
        CameraSystem.LastTargetUserId = false
        CameraSystem.updateTargetLabel(nil)
    end
    local removedKey = clearPlayerBinding(player.UserId)
    if removedKey then
        local message = keyLabel(removedKey) .. " liberada: "
            .. player.DisplayName .. " salio del servidor."
        logMessage(message, THEME.Muted)
        showToast(message)
    end

    if pendingBindingPlayer and pendingBindingPlayer.UserId == player.UserId then
        cancelPlayerKeyCapture(false)
        showToast("Asignacion cancelada: " .. player.DisplayName .. " se desconecto.")
    end

    if activePage == "players" then
        task.defer(function()
            refreshPlayerList(PlayerSearch.Text)
        end)
    end
end)

runtimeConfig.VisionTabOpen = VisionSystem.TabOpen
runtimeConfig.VisionLightStrength = VisionSystem.LightStrength
runtimeConfig.ZoomEnabled = VisionSystem.ZoomEnabled
runtimeConfig.ZoomFactor = VisionSystem.ZoomFactor
runtimeConfig.ZoomBehavior = VisionSystem.ZoomBehavior
runtimeConfig.ZoomBinding = VisionSystem.ZoomBinding
runtimeConfig.ZoomUnbound = VisionSystem.ZoomBinding == nil
runtimeConfig.EspRelationColors = EspSystem.RelationColors
VisionSystem.setLightEnabled(runtimeConfig.VisionLightEnabled == true, true)
runtimeConfig.ActivePage = activePage
runtimeConfig.TPTabOpen = tpTabOpen
runtimeConfig.HitboxTabOpen = hitboxTabOpen
runtimeConfig.EspTabOpen = espTabOpen
runtimeConfig.CameraTabOpen = CameraSystem.TabOpen
runtimeConfig.ToggleKey = toggleKey
runtimeConfig.WindowScale = AutoSave.WindowScale
runtimeConfig.TPSearch = PlayerSearch.Text
runtimeConfig.HitboxEnabled = hitboxEnabled
runtimeConfig.HitboxVisible = hitboxVisible
for _, region in pairs(HitboxSystem.Regions) do
    runtimeConfig[region.EnabledKey] = region.Enabled
    runtimeConfig[region.SizeKey] = region.Size
end
runtimeConfig.EspEnabled = espEnabled
runtimeConfig.EspLines = espLinesEnabled
runtimeConfig.EspBoxes = espBoxesEnabled
runtimeConfig.EspSkeleton = espSkeletonEnabled
runtimeConfig.RearAlert = rearAlertEnabled
runtimeConfig.RearAlertDistance = rearAlertDistance
runtimeConfig.CameraEnabled = CameraSystem.Enabled
runtimeConfig.CameraTeamCheck = CameraSystem.TeamCheck
runtimeConfig.CameraFovVisible = CameraSystem.FovVisible
runtimeConfig.CameraFovRadius = CameraSystem.FovRadius
runtimeConfig.CameraMaxDistance = CameraSystem.MaxDistance
runtimeConfig.CameraSmoothIntensity = CameraSystem.SmoothIntensity
runtimeConfig.CameraTargetZone = CameraSystem.TargetZone
runtimeConfig.CameraMode = CameraSystem.Mode
runtimeConfig.CameraActivationMode = CameraSystem.ActivationMode
runtimeConfig.CameraManualBehavior = CameraSystem.ManualBehavior
runtimeConfig.CameraAimKey = CameraSystem.Binding

Compact.applyLayout()
Compact.applyReadableLayout()
Compact.initializeTransparency()
Main.Visible = false
Compact.setNavigationOpen(true, true)
AutoSave.restorePlayerBindings()
VisionSystem.UI.Tab.Visible = VisionSystem.TabOpen
VisionSystem.UI.Close.Visible = false
layoutVisualTabs()
AutoSave.WindowTabs.Visible = true
TerminalTab.Visible = true
SettingsTab.Visible = true
PlayersTab.Visible = tpTabOpen
CloseTPTabButton.Visible = false
HitboxTab.Visible = hitboxTabOpen
CloseHitboxTabButton.Visible = false
EspTab.Visible = espTabOpen
CloseEspTabButton.Visible = false
CameraSystem.UI.Tab.Visible = CameraSystem.TabOpen
CameraSystem.UI.Close.Visible = false
for pageName, data in pairs(pageData) do
    data.Page.Visible = pageName == activePage
    data.Tab.TextColor3 = pageName == activePage and THEME.White or THEME.Muted
end
AutoSave.InitialPageData = pageData[activePage]
if AutoSave.InitialPageData then
    TabIndicator.Position = UDim2.fromOffset(0, AutoSave.InitialPageData.Y + 10)
    TabIndicator.Size = UDim2.fromOffset(3, 20)
    TabIndicator.Visible = false
    scrollTabIntoView(AutoSave.InitialPageData)
end

task.defer(function()
    for _, player in ipairs(Players:GetPlayers()) do
        watchHitboxPlayer(player)
    end
    HitboxSystem.auditInactive()
    if hitboxEnabled then
        refreshHitboxes()
    end
end)
refreshPlayerList(PlayerSearch.Text)
AutoSave.queueConfigSave()
logMessage("X.T.E.Y.X cargado.", THEME.Accent)
logMessage(
    AutoSave.PersistentSaveAvailable
        and "Autoguardado activo. Configuracion restaurada."
        or "Autoguardado de sesion activo (sin acceso a archivos).",
    THEME.Muted
)
logMessage("VISION: luz persistente y zoom. C por defecto para acercar.", THEME.Muted)
Compact.startIntro()

return cleanup, runtimeEnvironment, Compact.updateLicense
end

LicenseGate.run(startAuthorizedMenu)
