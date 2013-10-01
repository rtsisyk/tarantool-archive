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

    local function process_client(self, s)
        box.fiber.wrap(function()
            printf('box.httpd: accepted connection %s', s)
            s:send("aaaaaaaaaaaaa\n")
            s:send("aaaaaaaaaaaaa\n")
            s:shutdown( box.socket.SHUT_RDWR )
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
                local cs, status, errstr = s:accept(.5)
                if cs == 'error' then
                    printf("Can't accept socket: %s", cs, errstr)
                    break
                elseif cs ~= 'timeout' then
                    process_client(self, cs)
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
            local self = {
                host    = host,
                port    = port,
                is_run  = false,
                stop    = function() error("http server is not started") end,
                start   = httpd_start,
                options = options
            }

            return self
        end
    }


end)(box)

