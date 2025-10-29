-- jwt.lua - JWT dissector

--local log_file = io.open("C:\\Users\\hhruszka\\Desktop\\jwt_debug.log", "w")
local log_file = nil

function log_debug(msg)
    if log_file then
        log_file:write(os.date("%H:%M:%S") .. " - " .. msg .. "\n")
        log_file:flush()
    end
end

-- Get the directory of the current Lua script
local function get_script_dir()
    local str = debug.getinfo(2, "S").source:sub(2)
    local script_path = str:match("(.*[/\\])")
    if script_path then
        return script_path
    end
    local path_sep = package.config:sub(1,1)
    return "." .. path_sep
end

local script_dir = get_script_dir()
local so_path = script_dir .. "jwt.dll"
print("Plugin is located in:")
print(script_dir)
--local so_path = script_dir .. "jwt.dylib"

print("Loading jwt_utils from: " .. so_path)

local loader, err = package.loadlib(so_path, "luaopen_jwt_utils")
if not loader then
    error("Failed to load jwt_utils: " .. tostring(err))
end

local jwt_utils = loader()

local jwt_proto = Proto("JWT", "JSON Web Token")

-- Preferences
jwt_proto.prefs.public_key_file = Pref.string("Public Key File", "",
    "Path to public key (PEM format)")

-- Fields for display
local f_token = ProtoField.string("jwt.token", "JWT Token")
local f_algorithm = ProtoField.string("jwt.algorithm", "Algorithm")
local f_valid = ProtoField.bool("jwt.valid", "Signature Valid")
local f_issuer = ProtoField.string("jwt.issuer", "Issuer")
local f_subject = ProtoField.string("jwt.subject", "Subject")
local f_audience = ProtoField.string("jwt.audience", "Audience")
local f_expiration = ProtoField.absolute_time("jwt.expiration", "Expiration", base.UTC)
local f_packet_capture_time = ProtoField.absolute_time("jwt.packetct", "Packet capture time", base.UTC)
local f_issued_at = ProtoField.absolute_time("jwt.issued_at", "Issued At", base.UTC)
local f_not_before = ProtoField.absolute_time("jwt.not_before", "Not Before", base.UTC)
local f_warnings = ProtoField.string("jwt.warnings", "Warnings")
local f_error = ProtoField.string("jwt.error", "Error")
local f_jwt_present = ProtoField.none("jwt.present", "JWT Present")

-- Field extractors for HTTP2 and HTTP headers
local http2_field = Field.new("http2")
local http2_header_name = Field.new("http2.header.name")
local http2_header_value = Field.new("http2.header.value")
local http2_data = Field.new("http2.data.data")
local http_auth = Field.new("http.authorization")
local http_body = Field.new("http.file_data")

-- public key cache
local cached_pubkey = nil
local cached_path = nil

jwt_proto.fields = {
    f_token, f_algorithm, f_valid, f_issuer, f_subject, f_audience,
    f_expiration, f_issued_at, f_not_before, f_warnings,
    f_error, f_jwt_present, f_packet_capture_time
}

local token_headers = {
    ["authorization"] = true,
    ["3gpp-sbi-access-token"] = true,
    ["3gpp-sbi-client-credentials"] = true,
    ["3gpp-sbi-source-nf-client-credentials"] = true,
}

local token_pattern = '(ey[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_+%/-]*)'

local function get_token_from_header()
    local jwt_string = nil
    local jwt_source = nil
    local jwt_tvbrange = nil

    local header_values = { http2_header_value() }
    local header_names = { http2_header_name() }

    log_debug("Found " .. #header_names .. " header names " .. #header_values .. " header values")

    if #header_names ~= #header_values then return end

    for i, name_finfo in ipairs(header_names) do
        local key = tostring(name_finfo.value)

        log_debug("Header[" .. i .. "]: " .. key)

        if token_headers[string.lower(key)] then
            local value_finfo = header_values[i]
            local value_str   = tostring(value_finfo.value)
            local value_tvb = value_finfo.range

            local token = value_str
            -- Special handling for Authorization header
            if string.lower(key) == "authorization" then
                token = token:match("Bearer%s+(.*)") or token
            end

            local jwt_match = token:match(token_pattern)

            if jwt_match then
                jwt_source = key .. " Header  (HTTP/2)"
                jwt_string = jwt_match

                -- Find exact position of the JWT token
                local jwt_start = value_str:find(jwt_match, 1, true)
                if jwt_start then
                    local jwt_length = #jwt_string
                    local jwt_offset = jwt_start - 1
                    -- Create TVBRange (Lua strings are 1-indexed, TVB is 0-indexed)
                    jwt_tvbrange = value_tvb:range(jwt_offset, jwt_length)

                    --print("Found JWT in header '" .. key .. "' at offset: " .. jwt_offset .. " length: " .. jwt_length)
                    log_debug("Found JWT in header '" .. key .. "' at offset: " .. jwt_offset .. " length: " .. jwt_length)
                    break
                end
            end
        end
    end

    return jwt_string, jwt_source,jwt_tvbrange
end

local function get_token_from_body()
    local jwt_string = nil
    local jwt_source = nil
    local jwt_tvbrange = nil
    log_debug("Checking body for JWT...")

    local body_values = { http2_data() }

    -- Check if we got any body data
    if body_values[1] == nil then
        log_debug("No body data in this packet")
    else
        log_debug("Found " .. #body_values .. " body locations")

        for _, body_finfo in ipairs(body_values) do
            local body_data = body_finfo.range:bytes():raw()

            log_debug("Body length: " .. #body_data)

            pattern_start, pattern_end, jwt_match = body_data:find(
                '"access_token\"%s*:%s*\"' .. token_pattern)
                --'"access_token\"%s*:%s*\"(ey[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_+%/-]*)"')
            if not jwt_match then
                pattern_start, pattern_end, jwt_match = body_data:find(
                    '"token\"%s*:%s*\"' .. token_pattern)
                    --'"token\"%s*:%s*\"(ey[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_+%/-]*)"')
            end
            if not jwt_match then
                pattern_start, pattern_end, jwt_match = body_data:find(
                    token_pattern)
            end

            if jwt_match then
                jwt_string = jwt_match
                jwt_source = "Response Body (HTTP/2)"

                -- Find exact position of the JWT token
                local jwt_start = body_data:find(jwt_match, pattern_start, true)
                local jwt_length = #jwt_string

                -- Create TVBRange (Lua strings are 1-indexed, TVB is 0-indexed)
                jwt_tvbrange = body_finfo.range(jwt_start - 1, jwt_length)

                log_debug("Found JWT in body at offset: " .. (jwt_start - 1))
                break
            end
        end
    end

    return jwt_string, jwt_source, jwt_tvbrange
end

function split_jwt(jwt)
    local parts = {}

    for part in string.gmatch(jwt, "[^.]+") do
        table.insert(parts, part)
    end

    if #parts ~= 3 then
        return nil, nil, nil, "Invalid JWT format"
    end

    return parts[1], parts[2], parts[3]
end

-- Function to add dynamic fields to tree
local function add_dynamic_fields(tree, buffer, offset, parsed_table, prefix)
    if not parsed_table then
        return nil
    end

    local tree_dict = {}

    for key, value in pairs(parsed_table) do
        local field_name = key
        if prefix ~= "" then
            field_name = prefix and (prefix .. "." .. key) or key
        end

        local value_type = type(value)

        if value_type == "table" then
            local subtree = tree:add(buffer(offset, 0), field_name .. ": {...}")
            tree_dict[field_name] = add_dynamic_fields(subtree, buffer, offset, value, field_name)
        elseif value_type == "string" then
            tree_dict[field_name] = tree:add(buffer(offset, 0), field_name .. ": " .. value)
        elseif value_type == "number" then
            tree_dict[field_name] = tree:add(buffer(offset, 0), field_name .. ": " .. tostring(value))
        elseif value_type == "boolean" then
            tree_dict[field_name] = tree:add(buffer(offset, 0), field_name .. ": " .. tostring(value))
        end
    end
    return tree_dict
end

local function get_pubkey(filepath)
    if filepath ~= cached_path then
        cached_path = filepath
        if filepath ~= "" then
            local file = io.open(filepath, "r")
            if file then
                cached_pubkey = file:read("*all")
                file:close()
            else
                cached_pubkey = nil
            end
        else
            cached_pubkey = nil
        end
    end
    return cached_pubkey
end

local function analyze_jwt(pinfo, buffer, tree, jwt_source, jwt_string, jwt_tvbrange)
    --local warnings = "⚠️ Signature uses RawStdEncoding instead of base64url!"

    local jwt_header_table = {}
    local jwt_payload_table = {}
    local jwt_error
    local headerbase64, payloadbase64, signature = split_jwt(jwt_string)

    if headerbase64 then
        jwt_header_table, jwt_error = jwt_utils.base64_json_unmarshall(headerbase64)
        if #jwt_header_table == 0 and jwt_error then
            print("Header unmarshaling error: " .. jwt_error)
        end
    end

    if payloadbase64 then
        jwt_payload_table, jwt_error = jwt_utils.base64_json_unmarshall(payloadbase64)
        if #jwt_payload_table == 0 and jwt_error then
            print("Payload unmarshaling error: " .. jwt_error)
        end
    end

    local signature_verification = 0
    local public_key = nil
    if jwt_proto.prefs.public_key_file then
        public_key = get_pubkey(jwt_proto.prefs.public_key_file)
        if public_key then
            signature_verification = jwt_utils.verify_jwt(jwt_source, public_key)
        end
    end

    local subtree = tree:add(jwt_proto, buffer(), "JSON Web Token")
    log_debug("Subtree created: " .. tostring(subtree))
    ---- Add raw token
    subtree:add(buffer(), "JWT Source: " .. jwt_source):set_generated()
    if jwt_tvbrange then
        subtree:add(f_token, jwt_tvbrange, jwt_string):set_generated()
    else
        subtree:add(f_token, buffer(), jwt_string):set_generated()
    end
    valid_tree = subtree:add(f_valid, signature_verification == 1):set_generated()
    if public_key == nil then
        valid_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "⚠️ Missing public key for signature verification")
    end
    if public_key and not signature_verification then
       valid_tree:add_expert_info(PI_PROTOCOL, PI_ERROR, "⚠️ Signature verification failed")
    end

    local header_tree = subtree:add(jwt_proto, buffer(), "HEADER"):set_generated()
    local payload_tree = subtree:add(jwt_proto, buffer(), "CLAIMS"):set_generated()

    local header_fields = add_dynamic_fields(header_tree, buffer, 0, jwt_header_table, "")
    local payload_fields = add_dynamic_fields(payload_tree, buffer, 0, jwt_payload_table, "")

    ---- Display results

    if header_fields.alg and jwt_header_table.alg then
        pinfo.cols.info:append(", JWT Token (Alg: " .. jwt_header_table.alg .. ")")
    else
        pinfo.cols.info:append(", JWT Token")
    end

    local exp_tree_item = payload_fields.exp
    if exp_tree_item and jwt_payload_table.exp then
        --local exp_time = jwt_payload_table.exp
        --exp_tree_item:set_text(string.format("exp: %s pct: %s", format_date(exp_time), format_date(pinfo.abs_ts)))
        --print("exp " .. type(jwt_payload_table.exp))
        --print("pinfo.abs_ts " .. type(pinfo.abs_ts))
        local abs_ts = pinfo.abs_ts
        local seconds = math.floor(abs_ts)
        local nanoseconds = math.floor((abs_ts - seconds) * 1e9)

        if jwt_payload_table.exp < abs_ts then
            exp_tree_item:add_expert_info(PI_PROTOCOL, PI_ERROR, "⚠️ Token expired!")
        end

        exp_tree_item:add(f_expiration, NSTime.new(jwt_payload_table.exp))
        exp_tree_item:add(f_packet_capture_time, NSTime.new(seconds, nanoseconds))
    end
    if payload_fields.iat and jwt_payload_table.iat then
        local iat_tree_item = payload_fields.iat
        local iat_time = jwt_payload_table.iat
        iat_tree_item:set_text(string.format("iat: %s", format_date(iat_time)))
    end

    if payload_fields.nbf and jwt_payload_table.nbf then
        local nbf_tree_item = payload_fields.nbf
        local nbf_time = jwt_payload_table.nbf
        nbf_tree_item:set_text(string.format("nbf: %s", format_date(nbf_time)))
    end
end

function jwt_proto.dissector(buffer, pinfo, tree)
    local jwt_string = nil
    local jwt_source = nil
    local jwt_tvbrange = nil

    -- Handle HTTP/2
    if http2_field then
        log_debug("===> Processing HTTP2 packet")

        jwt_string, jwt_source,jwt_tvbrange = get_token_from_header()

        if not jwt_string then
            jwt_string, jwt_source, jwt_tvbrange = get_token_from_body()
        end
    end

    if not jwt_string or #jwt_string == 0 then
        log_debug("No JWT found")
        return
    end

    -- JWT found! Now add EVERYTHING to the tree once:
    log_debug("[+] JWT FOUND in Frame #" .. pinfo.number .. "! Source: " .. jwt_source)
    log_debug("[+] JWT: " .. jwt_string)
    log_debug("Creating subtree...")

    pinfo.cols.protocol:append(" (JWT)")


    analyze_jwt(pinfo, buffer, tree, jwt_source, jwt_string, jwt_tvbrange)
end

-- Register
-- Register as post-dissector (handles both HTTP and HTTP/2)
register_postdissector(jwt_proto)

print("JWT Utils version:", jwt_utils.version())
print("JWT postdissector loaded")
