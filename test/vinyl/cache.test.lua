#!/usr/bin/env tarantool

test_run = require('test_run').new()

test_run:cmd("setopt delimiter ';'")
stat = {
    run_step_count = 0,
    run_lookup_count = 0,
    mem_step_count = 0,
}
function stat_changed()
    local old_stat = stat
    local new_stat = box.info.vinyl().performance["iterator"]
    stat = {
        run_step_count=new_stat.run.step_count,
        run_lookup_count=new_stat.run.lookup_count,
        mem_step_count=new_stat.mem.step_count,
    }
    for k,v in pairs(stat) do
        if old_stat[k] ~= v then
            return true
        end
    end
    return false
end;
test_run:cmd("setopt delimiter ''");

s = box.schema.space.create('test', {engine = 'vinyl'})
i = s:create_index('test')

str = string.rep('!', 100)

for i = 1,1000 do s:insert{i, str} end

box.begin()
t = s:select{}
box.commit()

#t

t = s:replace{100, str}

for i = 1,10 do box.begin() t = s:select{} box.commit() end

t = s:replace{200, str}

s:drop()

s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

str = ''

s:replace{0, 0, 0}
s:replace{1, 1, 1, str}
s:replace{1, 2, 1, str}
s:replace{1, 3, 1, str}
s:replace{1, 4, 1, str}
s:replace{2, 1, 2, str}
s:replace{2, 2, 2, str}
s:replace{2, 3, 2, str}
s:replace{2, 4, 2, str}
s:replace{3, 3, 4}

box.snapshot()
a = stat_changed() -- init

box.begin()
s:get{1, 2}
box.commit()
stat_changed()  -- cache miss, true

s:get{1, 2}
stat_changed() -- cache hit, false

box.begin()
s:select{1}
box.commit()
stat_changed()  -- cache miss, true

s:select{1}
stat_changed() -- cache hit, false

box.begin()
s:select{}
box.commit()
stat_changed()  -- cache miss, true

s:select{}
stat_changed() -- cache hit, false

s:drop()

s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

str = ''

s:replace{0, 0, 0}
s:replace{1, 1, 1, str}
s:replace{1, 2, 1, str}
s:replace{1, 3, 1, str}
s:replace{1, 4, 1, str}
s:replace{2, 1, 2, str}
s:replace{2, 2, 2, str}
s:replace{2, 3, 2, str}
s:replace{2, 4, 2, str}
s:replace{3, 3, 4}

box.snapshot()
a = stat_changed() -- init

box.begin()
s:select{}
box.commit()
stat_changed()  -- cache miss, true

s:get{1, 2}
stat_changed() -- cache hit, false

s:select{1}
stat_changed() -- cache hit, false

s:select{}
stat_changed() -- cache hit, false

s:drop()

s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

str = ''

s:replace{0, 0, 0}
s:replace{1, 2, 1, str}
s:replace{1, 3, 1, str}
s:replace{1, 4, 1, str}
s:replace{2, 1, 2, str}
s:replace{2, 2, 2, str}
s:replace{2, 3, 2, str}
s:replace{2, 4, 2, str}
s:replace{3, 3, 4}

box.begin()
s:select{1}
box.commit()

s:replace{1, 1, 1, str}

s:select{1}

s:drop()


s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

s:replace{1, 1, 1}
s:replace{2, 2, 2}
s:replace{3, 3, 3}
s:replace{4, 4, 4}
s:replace{5, 5, 5}

box.begin()
i1:min()
i1:max()
box.commit()

s:replace{0, 0, 0}
s:replace{6, 6, 6}

i1:min()
i1:max()

s:drop()

-- Same test w/o begin/end

s = box.schema.space.create('test', {engine = 'vinyl'})
i = s:create_index('test')

str = string.rep('!', 100)

for i = 1,1000 do s:insert{i, str} end
box.snapshot()

t = s:select{}

#t

t = s:replace{100, str}

for i = 1,10 do t = s:select{} end

t = s:replace{200, str}

s:drop()

s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

str = ''

s:replace{0, 0, 0}
s:replace{1, 1, 1, str}
s:replace{1, 2, 1, str}
s:replace{1, 3, 1, str}
s:replace{1, 4, 1, str}
s:replace{2, 1, 2, str}
s:replace{2, 2, 2, str}
s:replace{2, 3, 2, str}
s:replace{2, 4, 2, str}
s:replace{3, 3, 4}

box.snapshot()
a = stat_changed() -- init

s:get{1, 2}
stat_changed()  -- cache miss, true

s:get{1, 2}
stat_changed() -- cache hit, false

s:select{1}
stat_changed()  -- cache miss, true

s:select{1}
stat_changed() -- cache hit, false

s:select{}
stat_changed()  -- cache miss, true

s:select{}
stat_changed() -- cache hit, false

s:drop()

s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

str = ''

s:replace{0, 0, 0}
s:replace{1, 1, 1, str}
s:replace{1, 2, 1, str}
s:replace{1, 3, 1, str}
s:replace{1, 4, 1, str}
s:replace{2, 1, 2, str}
s:replace{2, 2, 2, str}
s:replace{2, 3, 2, str}
s:replace{2, 4, 2, str}
s:replace{3, 3, 4}

box.snapshot()
a = stat_changed() -- init

s:select{}
stat_changed()  -- cache miss, true

s:get{1, 2}
stat_changed() -- cache hit, false

s:select{1}
stat_changed() -- cache hit, false

s:select{}
stat_changed() -- cache hit, false

s:drop()

s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

str = ''

s:replace{0, 0, 0}
s:replace{1, 2, 1, str}
s:replace{1, 3, 1, str}
s:replace{1, 4, 1, str}
s:replace{2, 1, 2, str}
s:replace{2, 2, 2, str}
s:replace{2, 3, 2, str}
s:replace{2, 4, 2, str}
s:replace{3, 3, 4}

s:select{1}

s:replace{1, 1, 1, str}

s:select{1}

s:drop()


s = box.schema.space.create('test', {engine = 'vinyl'})
i1 = s:create_index('test1', {parts = {1, 'uint', 2, 'uint'}})

s:replace{1, 1, 1}
s:replace{2, 2, 2}
s:replace{3, 3, 3}
s:replace{4, 4, 4}
s:replace{5, 5, 5}

i1:min()
i1:max()

s:replace{0, 0, 0}
s:replace{6, 6, 6}

i1:min()
i1:max()

s:drop()

-- https://github.com/tarantool/tarantool/issues/2189

local_space = box.schema.space.create('test', {engine='vinyl'})
pk = local_space:create_index('primary')
local_space:replace({1, 1})
local_space:replace({2, 2})
local_space:select{}
box.begin()
local_space:replace({1})
local_space:select{}
box.commit()
local_space:select{}
local_space:drop()
