-- box.httpd

(function(box, io)
    print("Plugin box.httpd init...")

    local ffi = require("ffi")

    local function errorf(fmt, ...)
        error(string.format(fmt, ...))
    end
    local function printf(fmt, ...)
        print(string.format(fmt, ...))
    end

    local function sprintf(fmt, ...)
        return string.format(fmt, ...)
    end

    local server_title =
        sprintf('Tarantool/%s box.httpd server', box.info.version)

    local codes = {
        [200] = 'Ok',
        [201] = 'Created',
        [202] = 'Accepted',
        [203] = 'Non authoritative information',
        [204] = 'No content',
        [205] = 'Reset content',
        [206] = 'Partial content',
        [207] = 'Multi status',
        [208] = 'Already reported',
        [226] = 'IM used',
        [300] = 'Multiple choises',
        [301] = 'Moved permanently',
        [302] = 'Found',
        [303] = 'See other',
        [304] = 'Not modified',
        [305] = 'Use proxy',
        [307] = 'Temporary redirect',
        [400] = 'Bad request',
        [401] = 'Unauthorized',
        [402] = 'Payment required',
        [403] = 'Forbidden',
        [404] = 'Not found',
        [405] = 'Method not allowed',
        [406] = 'Not acceptable',
        [407] = 'Proxy authentification required',
        [408] = 'Request timeout',
        [409] = 'Conflict',
        [410] = 'Gone',
        [411] = 'Length required',
        [412] = 'Precondition failed',
        [413] = 'Request entity too large',
        [414] = 'Request uri too large',
        [415] = 'Unsupported media type',
        [416] = 'Request range not satisfiable',
        [417] = 'Expectation failed',
        [418] = 'I am a teapot',
        [422] = 'Unprocessable entity',
        [423] = 'Locked',
        [424] = 'Failed dependency',
        [425] = 'No code',
        [426] = 'Upgrade required',
        [428] = 'Precondition required',
        [429] = 'Too many requests',
        [431] = 'Request header fields too large',
        [449] = 'Retry with',
        [451] = 'Unavailable for legal reasons',
        [456] = 'Unrecoverable error',
        [500] = 'Internal server error',
        [501] = 'Not implemented',
        [502] = 'Bad gateway',
        [503] = 'Service unavailable',
        [504] = 'Gateway timeout',
        [505] = 'Http version not supported',
        [506] = 'Variant also negotiates',
        [507] = 'Insufficient storage',
        [509] = 'Bandwidth limit exceeded',
        [510] = 'Not extended',
        [511] = 'Network authentication required',
    }
    local function reason_by_code(code)
        code = tonumber(code)
        if codes[code] ~= nil then
            return codes[code]
        end
        return sprintf('Unknown code %d', code)
    end

    local function ucfirst(str)
        return str:gsub("^%l", string.upper, 1)
    end


    local mrequest = {
        __index = {
            to_string = function(self)
                local res = self:request_line() .. "\r\n"

                for hn, hv in pairs(self.headers) do
                    res = sprintf("%s%s: %s\r\n", res, ucfirst(hn), hv)
                end

                return sprintf("%s\r\n%s", res, self.body)
            end,

            request_line = function(self)
                local rstr = self.path
                if string.len(self.query) then
                    rstr = rstr .. '?' .. self.query
                end
                return sprintf("%s %s HTTP/%d.%d",
                    self.method, rstr, self.proto[1], self.proto[2])
            end,
        }
    }

    local function catfile(...)
        local sp = { ... }

        local path

        if #sp == 0 then
            return
        end

        for i, pe in pairs(sp) do
            if path == nil then
                path = pe
            elseif string.match(path, '.$') ~= '/' then
                if string.match(pe, '^.') ~= '/' then
                    path = path .. '/' .. pe
                else
                    path = path .. pe
                end
            else
                if string.match(pe, '^.') == '/' then
                    path = path .. string.gsub(pe, '^/', '', 1)
                else
                    path = path .. pe
                end
            end
        end

        return path
    end


    local function extend(tbl, tblu, raise)
        local res = {}
        for k, v in pairs(tbl) do
            res[ k ] = v
        end
        for k, v in pairs(tblu) do
            if raise then
                if res[ k ] == nil then
                    errorf("Unknown option '%s'", k)
                end
            end
            res[ k ] = v
        end
        return res
    end


    local function log(peer, code, req, len)
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

    local function hlog(peer, code, hdr)
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


    local function render(tx, opts)
        if tx == nil then
            error("Usage: self:render({ ... })")
        end

        local tpl
        if tx.endpoint.template ~= nil then
            tpl = tx.endpoint.template
        else
            errorf('template is not defined for the route')
        end

        local vars = {}
        for hname, sub in pairs(tx.httpd.helpers) do
            vars[hname] = function(...) return sub(tx, ...) end
        end
        if opts ~= nil then
            vars = extend(tx.tstash, opts, false)
        end

        tx.resp.body, a = box.httpd.template(tpl, vars)
    end

    local function redirect_to(tx)
        if tx == nil then
            error("Usage: self:redirect_to({ ... })")
        end
    end

    local function access_stash(tx, name, ...)
        if type(tx) ~= 'table' then
            error("usage: ctx:stash('name'[, 'value'])")
        end
        if select('#', ...) > 0 then
            tx.tstash[ name ] = select(1, ...)
        end

        return tx.tstash[ name ]
    end

    local function handler(self, request)

        if self.hooks.before_routes ~= nil then
            self.hooks.before_dispatch(self, request)
        end

        local r = self:match(request.path)
        if r == nil then
            return { 404 }
        end


        local tx = {
            req         = request,
            resp        = { headers = {}, body = '', code = 200 },
            endpoint    = r.endpoint,
            tstash      = r.stash,
            render      = render,
            redirect_to = redirect_to,
            httpd       = self,
            stash       = access_stash
        }


        r.endpoint.sub( tx )

        local res = { tx.resp.code, tx.resp.headers, tx.resp.body }

        if self.hooks.after_dispatch ~= nil then
            self.hooks.after_dispatch(tx, res)
        end

        return res
    end

    local function normalize_headers(hdrs)
        local res = {}
        for h, v in pairs(hdrs) do
            res[ string.lower(h) ] = v
        end
        return res
    end


    local function process_client(self, s, peer)

        while true do

            local hdrs = {
                s:readline(
                    self.options.max_header_size,
                    { "\n\n", "\r\n\r\n" }
                    -- TODO: broken socket uncomment after it is fixed
--                     ,self.options.header_timeout
                )
            }

            if hdrs[2] == 'limit' then
                hlog(peer, 400, hdrs[1])
                break
            end
            if hdrs[2] ~= nil then
                printf("Error while reading headers: %s, %s", hdrs[4], hdrs[2])
                break
            end

            local p = box.httpd.parse_request(hdrs[1])
            if p['error'] ~= nil then
                if p.method ~= nil then
                    log(peer, 400, p:request_line())
                else
                    hlog(peer, 400, hdrs[1])
                end
                s:send(sprintf("HTTP/1.0 400 Bad request\r\n\r\n%s", p.error))
                break
            end

            local res = { pcall(self.options.handler, self, p) }
            local code, hdrs, body

            if res[1] == false then
                code = 500
                hdrs = {}
                body =
                      "Unhandled error:\n"
                    .. debug.traceback(res[2]) .. "\n\n"

                    .. "\n\nRequest:\n"
                    .. p:to_string()

            else
                code = res[2][1]
                hdrs = res[2][2]
                body = res[2][3]

                if type(body) == 'table' then
                    body = table.concat(body)
                else
                    if body == nil then
                        body = ''
                    end
                end

                if hdrs == nil then
                    hdrs = {}
                elseif type(hdrs) ~= 'table' then
                    code = 500
                    hdrs = {}
                    body = sprintf(
                        'Handler returned non-table headers: %s',
                        type(hdrs)
                    )
                end
            end

            hdrs = normalize_headers(hdrs)

            if hdrs.server == nil then
                hdrs.server = server_title
            end

            if p.proto[1] ~= 1 then
                hdrs.connection = 'close'
            elseif p.proto[2] == 1 then
                if p.headers.connection == nil then
                    hdrs.connection = 'keep-alive'
                elseif string.lower(p.headers.connection) ~= 'keep-alive' then
                    hdrs.connection = 'close'
                else
                    hdrs.connection = 'keep-alive'
                end
            elseif p.proto[2] == 0 then
                if p.headers.connection == nil then
                    hdrs.connection = 'close'
                elseif string.lower(p.headers.connection) == 'keep-alive' then
                    hdrs.connection = 'keep-alive'
                else
                    hdrs.connection = 'close'
                end
            end

            hdrs['content-length'] = string.len(body)

            local hdr = ''
            for k, v in pairs(hdrs) do
                hdr = hdr .. sprintf("%s: %s\r\n", ucfirst(k), v)
            end

            s:send(sprintf(
                "HTTP/1.1 %s %s\r\n%s\r\n%s",
                code,
                reason_by_code(code),
                hdr,
                body
            ))

            if p.proto[1] ~= 1 then
                break
            end

            if hdrs.connection ~= 'keep-alive' then
                break
            end
        end
        s:close()
    end

    local function httpd_stop(self)
       if type(self) ~= 'table' then
           error("box.httpd: usage: httpd:stop()")
        end
        if self.is_run then
            self.is_run = false
        else
            error("server is already stopped")
        end
        return self
    end

    local function match_route(self, route)
        if string.match(route, '.$') ~= '/' then
            route = route .. '/'
        end
        if string.match(route, '^.') ~= '/' then
            route = '/' .. route
        end

        local fit
        local stash = {}

        for k, r in pairs(self.routes) do
            local m = { string.match(route, r.match)  }
            local nfit
            if #m > 0 then
                if #r.stash > 0 then
                    if #r.stash == #m then
                        nfit = r
                    end
                else
                    nfit = r
                end

                if nfit ~= nil then
                    if fit == nil then
                        fit = nfit
                        stash = m
                    else
                        if #fit.stash > #nfit.stash then
                            fit = nfit
                            stash = m
                        end
                    end
                end
            end
        end

        if fit == nil then
            return fit
        end
        local resstash = {}
        for i = 1, #fit.stash do
            resstash[ fit.stash[ i ] ] = stash[ i ]
        end
        return  { endpoint = fit, stash = resstash }
    end

    local function load_template(self, r)
        if r.template ~= nil then
            return
        end

        if r.file == nil then
            return
        end

        local tpl = catfile(self.options.templates, r.file)
        local fh = io.input(tpl)
        r.template = fh:read('*a')
        fh:close()

    end

    local function set_helper(self, name, sub)
        if sub == nil or type(sub) == 'function' then
            self.helpers[ name ] = sub
            return self
        end
        errorf("Wrong type for helper function: %s", type(sub))
    end

    local function set_hook(self, name, sub)
        if sub == nil or type(sub) == 'function' then
            self.hooks[ name ] = sub
        end
        errorf("Wrong type for hook function: %s", type(sub))
    end

    local function add_route(self, opts, sub)
        if type(opts) ~= 'table' or type(self) ~= 'table' then
            error("Usage: httpd:route({ ... }, function(cx) ... end)")
        end
        if sub == nil then
            sub = function(cx) cx:render() end
        elseif type(sub) ~= 'function' then
            errorf("wrong argument: expected function, but received %s",
                type(sub))
        end

        opts = extend({method = 'any'}, opts, false)

        if opts.method ~= 'get' and opts.method ~= 'post' then
            opts.method = 'any'
        end


        if opts.path == nil then
            error("path is not defined")
        end

        opts.match = opts.path
        opts.match = string.gsub(opts.match, '[-]', "[-]")

        local estash = {  }
        local stash = {  }
        while true do
            local name = string.match(opts.match, ':([%a_][%w_]*)')
            if name == nil then
                break
            end
            if estash[name] then
                errorf("duplicate stash: %s", name)
            end
            estash[name] = true
            opts.match = string.gsub(opts.match, ':[%a_][%w_]*', '([^/]-)', 1)

            table.insert(stash, name)
        end
        while true do
            local name = string.match(opts.match, '[*]([%a_][%w_]*)')
            if name == nil then
                break
            end
            if estash[name] then
                errorf("duplicate stash: %s", name)
            end
            estash[name] = true
            opts.match = string.gsub(opts.match, '[*][%a_][%w_]*', '(.-)', 1)

            table.insert(stash, name)
        end

        if string.match(opts.match, '.$') ~= '/' then
            opts.match = opts.match .. '/'
        end
        if string.match(opts.match, '^.') ~= '/' then
            opts.match = '/' .. opts.match
        end

        opts.match = '^' .. opts.match .. '$'

        estash = nil

        opts.stash = stash
        opts.sub = sub

        load_template(self, opts)

        table.insert(self.routes, opts)
        return self
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
        rawset(self, 'stop', httpd_stop)

        box.fiber.wrap(function()
            printf('box.httpd: started at host=%s, port=%s',
                self.host, self.port)
            while self.is_run do
                local cs, status, es = s:accept(.1)
                if cs == 'error' then
                    printf("Can't accept socket: %s", es)
                    break
                elseif cs ~= 'timeout' then
                    box.fiber.wrap(function() process_client(self, cs, es) end)
                    cs = nil
                end
            end
            self.s:close()
            rawset(self, 's', nil)
            rawset(self, 'is_run', false)
        end)

        return self
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
                header_timeout      = 100,
                handler             = handler,
                templates           = '.',
            }

            local self = {
                host    = host,
                port    = port,
                is_run  = false,
                stop    = httpd_stop,
                start   = httpd_start,
                options = extend(default, options, true),

                routes  = {  },
                helpers = {  },
                hooks   = {  },

                -- methods
                route   = add_route,
                match   = match_route,
                catfile = catfile,
                helper  = set_helper,
                hook    = set_hook,
            }

            return self
        end,

        parse_request = function(str)
            local req = box.httpd._parse_request(str)
            if req.error ~= nil then
                return req
            end

            setmetatable(req, mrequest)

            return req
        end
    }


end)(box, io)

