local jwt_utils = require("jwt_utils")

-- JWT postdissector
local jwt_proto = Proto("jwt", "JSON Web Token")
local f_token = ProtoField.string("jwt.token", "JWT Token")
local f_header = ProtoField.string("jwt.header", "Header")
local f_payload = ProtoField.string("jwt.payload", "Payload")
local f_signature = ProtoField.string("jwt.signature", "Signature")
local f_valid = ProtoField.bool("jwt.valid", "Signature Valid")

jwt_proto.fields = {f_token, f_header, f_payload, f_signature, f_valid}

-- Your public key (configure as needed)
local PUBLIC_KEY = [[-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----]]

function jwt_proto.dissector(buffer, pinfo, tree)
    -- Extract JWT from HTTP Authorization header or other field
    -- This is a simplified example

    local jwt_tree = tree:add(jwt_proto, buffer())

    -- Parse and verify JWT
    local token = "..." -- Extract from packet
    local valid = jwt_utils.verify_jwt(token, PUBLIC_KEY, "ES256")

    jwt_tree:add(f_valid, valid)
end

register_postdissector(jwt_proto)