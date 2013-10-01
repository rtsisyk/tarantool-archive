-- box.http

(function(box)
    local function errorf(fmt, ...)
        error(string.format(fmt, ...))
    end

    local function retcode(code, reason)
        return nil, {
            Status  = code,
            Reason  = reason
        }
    end

    local function connect(host, port)
        local s = box.socket.tcp()
        if s == nil then
            return nil, "Can't create socket"
        end
        local res = { s:connect(host, port) }
        if res[1] == nil then
            return nil, res[4]
        end
        return s
    end



    box.http = {
        request = function(method, url, hdrs, body)
            if hdrs == nil then
                hdrs = {}
            end
            method = string.upper(method)

            if method ~= 'GET' and method ~= 'POST' then
                return retcode(599, "Unknown request method: " .. method)
            end

            local scheme, host, port, path, query = box.http.split_url( url )

            if scheme ~= 'http' then
                return retcode(599, "Unknown scheme: " .. scheme)
            end

            if string.len(host) < 1 then
                return retcode(595, "Can't route host")
            end

            if port == nil then
                port = 80
            elseif string.match(port, '^%d+$') ~= nil then
                    port = tonumber(port)
            else
                return retcode(599, "Wrong port number: " .. port)
            end

            local s, err = connect(host, port)
            if s == nil then
                return retcode(595, err)
            end


            if body == nil then
                body = ''
            end

            local hdr = ''
            for i, v in pairs(hdrs) do
                if i ~= 'Content-Length' then
                    hdr = hdr .. string.format("%s: %s\r\n", i, v)
                end
            end

            if string.len(body) > 0 then
                hdr = hdr .. "Content-Length: 0\r\n"
            end

            hdr = hdr .. "User-Agent: Tarantool box.http agent\r\n"

            local pquery = ''

            if string.len(query) > 0 then
                pquery = '?' .. query
            end


            local req = string.format(
                "%s %s%s HTTP/1.1\r\n" ..
                "Host: %s\r\n" ..
                "%s\r\n" ..
                "%s",

                    method,
                    path,
                    pquery,
                    host,
                    hdr,
                    body
            )


            local res = { s:send(req) }

            if #res > 1 then
                return retcode(595, res[4])
            end
            if res[1] ~= string.len(req) then
                return retcode(595, "Can't send request")
            end
                

            return req, res


        end
    }
end)(box)

