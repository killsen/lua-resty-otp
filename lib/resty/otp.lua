
-- lua-resty-otp - Lua OTP lib for OpenResty
-- https://github.com/leslie-tsang/lua-resty-otp

-- 加密与安全：动态密码图解：HOTP 与 TOTP 算法
-- https://blog.csdn.net/liwei16611/article/details/90547933

-- 动态令牌是怎么生成的？（OTP & TOTP 简单介绍）
-- https://zhuanlan.zhihu.com/p/484991482

-- 阮一峰 - 双因素认证（2FA）教程
-- https://ruanyifeng.com/blog/2017/11/2fa-tutorial.html

local hmac_sha1         = ngx.hmac_sha1
local escape_uri        = ngx.escape_uri
local ngx_now           = ngx.now
local ngx_time          = ngx.time
local bit_band          = bit.band
local bit_lshift        = bit.lshift
local bit_rshift        = bit.rshift
local math_floor        = math.floor
local math_random       = math.random
local math_randomseed   = math.randomseed
local str_byte          = string.byte
local str_char          = string.char
local str_format        = string.format
local str_reverse       = string.reverse
local str_upper         = string.upper
local tbl_new           = table.new
local tbl_clear         = table.clear
local tbl_insert        = table.insert
local tbl_concat        = table.concat
local tbl_unpack        = table.unpack or unpack  -- 5.1 compatibility

local _M = { _VERSION = '1.0.0' }
local mt = { __index = _M       }

local BASE32_HASH = {  --> number[]
    [0 ] = 65, [1 ] = 66, [2 ] = 67, [3 ] = 68, [4 ] = 69, [5 ] = 70,
    [6 ] = 71, [7 ] = 72, [8 ] = 73, [9 ] = 74, [10] = 75, [11] = 76,
    [12] = 77, [13] = 78, [14] = 79, [15] = 80, [16] = 81, [17] = 82,
    [18] = 83, [19] = 84, [20] = 85, [21] = 86, [22] = 87, [23] = 88,
    [24] = 89, [25] = 90,
    [26] = 50, [27] = 51, [28] = 52, [29] = 53, [30] = 54, [31] = 55,

    [50] = 26, [51] = 27, [52] = 28, [53] = 29, [54] = 30, [55] = 31,
    [65] = 0,  [66] = 1,  [67] = 2,  [68] = 3,  [69] = 4,  [70] = 5,
    [71] = 6,  [72] = 7,  [73] = 8,  [74] = 9,  [75] = 10, [76] = 11,
    [77] = 12, [78] = 13, [79] = 14, [80] = 15, [81] = 16, [82] = 17,
    [83] = 18, [84] = 19, [85] = 20, [86] = 21, [87] = 22, [88] = 23,
    [89] = 24, [90] = 25,
}

local t_base32 = tbl_new(10, 0)  --> number[]

-- base32 解码
local function base32_decode(str)
-- @str     : string
-- @return  : string

    tbl_clear(t_base32)

    local n, bs = 0, 0

    for i = 1, #str do
        local v = str_byte(str, i)
        n = bit_lshift(n, 5)
        n = n + BASE32_HASH[v]
        bs = (bs + 5) % 8
        if (bs < 5) then
            tbl_insert(t_base32, bit_rshift(bit_band(n, bit_lshift(0xFF, bs)), bs))
        end
    end

    return str_char(tbl_unpack(t_base32))
end

-- base32 编码
local function base32_encode(str)
-- @str     : string
-- @return  : string

    tbl_clear(t_base32)

    local c, n = 0, 0

    for i = 1, #str do
        local v = str_byte(str, i)

        n = bit_lshift(n, 8)
        n = n + v
        c = c + 8

        local bs = c % 5
        local tmp_n = bit_rshift(n, bs)

        for j = c - bs - 5, 0, -5 do
            local tmp_char = bit_rshift(bit_band(tmp_n, bit_lshift(0x1F, j)), j)
            tbl_insert(t_base32, BASE32_HASH[tmp_char])
        end

        c = bs
        n = bit_band(n, bit_rshift(0xFF, 8 - bs))
    end

    return str_char(tbl_unpack(t_base32))
end

local t_time = tbl_new(8, 0)  --> number[]

local function totp_time_calc(time)
-- @time    : number
-- @return  : string

    for i = 1, 8 do
        t_time[i] = bit_band(time, 0xFF)
        time = bit_rshift(time, 8)
    end

    return str_reverse(str_char(tbl_unpack(t_time)))
end

local t_key = tbl_new(10, 0)  --> string[]

-- 生成秘钥
local function totp_new_key()
-- @return  : string

    math_randomseed(ngx_now() * 1000)

    for i = 1, 10 do
        t_key[i] = str_char(math_random(0, 255))
    end

    return base32_encode(tbl_concat(t_key))
end

-- 创建对象
function _M.new(key)
-- @key ? : string
    key = key and str_upper(key) or totp_new_key()
    local t = {
        type        = "totp",
        key         = key,
        key_decoded = base32_decode(key),
    }
    return setmetatable(t, mt)
end

-- 创建秘钥
function _M:new_key(key)
-- @key   ? : string
-- @return  : void
    key = key and str_upper(key) or totp_new_key()
    self.key = key
    self.key_decoded = base32_decode(key)
end

-- 计算令牌
function _M:calc_token(time)
-- @time  ? : number
-- @return  : string

    time = time or ngx_time()
    time = math_floor(time / 30)

    local digest = hmac_sha1(self.key_decoded, totp_time_calc(time))
    local buffer = { str_byte(digest, 1, -1) }
    local offset = bit_band(buffer[20], 0xF)
    local token  = 0

    for i = 1, 4 do
        token = token + bit_lshift(buffer[offset + i], (4 - i) * 8)
    end

    token = bit_band(token, 0x7FFFFFFF)
    token = token % 1000000

    return str_format("%06d", token)
end

-- 验证令牌
function _M:verify_token(token)
-- @token   : string    // 待验证的令牌
-- @return  : boolean
    return token == self:calc_token()
end

-- 生成链接
function _M:get_url(issuer, account)
-- @issuer  : string    // 发行方
-- @account : string    // 账户名
-- @return  : string

    return tbl_concat {
        "otpauth://totp/", account,
        "?secret=", self.key,
        "&issuer=", issuer,
    }
end

-- 生成链接二维码
function _M:get_qr_url(issuer, account)
-- @issuer  : string    // 发行方
-- @account : string    // 账户名
-- @return  : string

    return tbl_concat {
        "https://chart.googleapis.com/chart",
        "?chs=", "200x200",
        "&cht=qr",
        "&chl=200x200",
        "&chld=M|0",
        "&chl=", escape_uri(self:get_url(issuer, account)),
    }
end

-- 测试
_M._TESTING = function()

    -- 在线测试
    -- https://moyuscript.github.io/2fa-test/
    -- otpauth://totp/Passkou?secret=6shyg3uens2sh5slhey3dmh47skvgq5y&issuer=Test

    local key = "6shyg3uens2sh5slhey3dmh47skvgq5y"
    local otp = _M.new(key)

    ngx.say("now   : ", ngx.now())
    ngx.say("token : ", otp:calc_token())
    ngx.say("url   : ", otp:get_url("Test", "Passkou"))
    ngx.say("token : ", otp:calc_token())

    ngx.update_time()
    local t1 = ngx.now() * 1000

    for _=1, 10000 do
        otp:calc_token()
    end

    ngx.update_time()
    local t2 = ngx.now() * 1000

    ngx.say("time  : ", t2-t1, " ms / 10000")

end

return _M
