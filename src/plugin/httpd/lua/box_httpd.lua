-- box.httpd

(function(box)
    print("Plugin box.httpd init...")

    local ffi = require("ffi")

    local function errorf(fmt, ...)
        error(string.format(fmt, ...))
    end
    local function printf(fmt, ...)
        print(string.format(fmt, ...))
    end

    local function extend(tbl, tblu)
        local res = {}
        for k, v in pairs(tbl) do
            res[ k ] = v
        end
        for k, v in pairs(tblu) do
            if res[ k ] == nil then
                errorf("Unknown option '%s'", k)
            end
            res[ k ] = v
        end
        return res
    end


    function log(peer, code, req, len)
        if req == nil then
            len = 0
            req = '-'
        else
            if len == nil then
                len = 0
            end
        end

        printf("%s - - \"%s\" %s %s\n", peer, req, code, len)
    end

    function hlog(peer, code, hdr)
        if string.len(hdr) == 0 then
            return log(peer, code)
        end
        local rs = string.match(hdr, "^(.-)[\r\n]")
        if rs == nil then
            return log(peer, code, hdr)
        else
            return log(peer, code, rs)
        end
    end


    local function process_client(self, s, peer)
        box.fiber.wrap(function()

            printf('box.httpd: accepted connection %s', peer)

            local hdrs = {
                s:readline(
                    self.options.max_header_size,
                    { "\n\n", "\r\n\r\n" }
--                     self.options.header_timeout
                )
            }

            if hdrs[2] == 'limit' then
                hlog(peer, 400, hdrs[1])
                s:close()
                return
            end
            if hdrs[2] ~= nil then
                printf("Error while reading headers: %s, %s", hdrs[4], hdrs[2])
                s:close()
                return
            end

            hlog(peer, 222, hdrs[1])

            s:send("aaaaaaaaaaaaa\n")
            s:send("aaaaaaaaaaaaa\n")
            s:close()
        end)
    end


    local function httpd_start(self)
        if type(self) ~= 'table' then
            error("box.httpd: usage: httpd:start()")
        end
        local s = box.socket.tcp()
        if s == nil then
            error("Can't create new tcp socket")
        end


        local res = { s:bind(self.host, self.port) }
        if res[1] == 'error' then
            errorf("Can't bind socket: %s", res[3])
        end

        res = { s:listen() }
        if res[1] == 'error' then
            errorf("Can't listen socket: %s", res[3])
        end

        rawset(self, 'is_run', true)
        rawset(self, 's', s)

        box.fiber.wrap(function()
            printf('box.httpd: started at host=%s, port=%s',
                self.host, self.port)
            while self.is_run do
                local cs, status, es = s:accept(.5)
                if cs == 'error' then
                    printf("Can't accept socket: %s", es)
                    break
                elseif cs ~= 'timeout' then
                    process_client(self, cs, es)
                    cs = nil
                end
            end
            self.s:close()
            rawset(self, 's', nil)
            rawset(self, 'is_run', false)
        end)

    end


    box.httpd = {
        new = function(host, port, options)
            if options == nil then
                options = {}
            end
            if type(options) ~= 'table' then
                errorf("options must be table not '%s'", type(options))
            end
            local default = {
                max_header_size     = 4096,
                max_headers         = 128,

                max_fibers          = 1024,
                header_timeout      = 100
            }
            local self = {
                host    = host,
                port    = port,
                is_run  = false,
                stop    = function() error("http server is not started") end,
                start   = httpd_start,
                options = extend(default, options)
            }

            return self
        end
    }


end)(box)

