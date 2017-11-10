local cjson = require "cjson"
local json = cjson.new()
local http = require "resty.http"
local httpc = http.new()
local ip_utils = require "lua_ip"
local jwt = require "resty.jwt"

local url,postargs,user,passwd,file1,str,strjson,jsonStr,requestip --获取url、获取poset请求、获取用户名、获取密码、获取io、获取文件中的内容、将内容转换json、传递admin的json、路径
local retTable = {};    --最终拼接log的json
ngx.req.read_body()
postargs = ngx.req.get_post_args()
requestip=ngx.var.requesturl
user = postargs["user"]
passwd = postargs["pwd"]

file1 = io.open("/usr/local/gateway/nginx/rule.txt", "r")
str = file1:read("*a")
file1:close()
strjson = json.decode(str)


--日志方法
function logs(results,user,passwd)
    retTable["action"] = "authentication" ;
    retTable["path"] = "/" ;
    retTable["pluginIp"] = ip_utils.get_ipv4();
    retTable["clientType"] =  "gateway";
    retTable["user"] = user ;
    retTable["clientIPAddress"] = ngx.var.remote_addr ;
    retTable["accessType"] = "/" ;
    retTable["isAllowed"] = results ;
    retTable["accessTime"] = os.date("%Y-%m-%d %H:%M:%S");
	jsonStr = cjson.encode(retTable);
	if user ~= nil then
		local res, err = httpc:request_uri("http://"..requestip..":8085/api/audits", {
	                method = "POST",
	                body = jsonStr,
	                headers = {
	                ["Content-Type"] = "application/json",
	                      }
	                })
	end
end

function Authority(txt1,txt3,var2)
   for userkeyid,userkey in pairs(var2) do
      if(type(userkey)=="table") then
          for userkeys,passwdval in pairs(userkey) do
		  local _ , _ , txt2 = string.find(userkeys,'^'.."(.-)"..':')
	          local _ , _ , txt4 = string.find(userkeys,':'.."(.-)"..'$')
		  if(txt1==txt2) then
	                  if(txt3==txt4) then
	                  return true
	                  end
	          end
          end
      else
      
      end
   end
      return false
end

function jwts()
	local jwt_token = jwt:sign(
                    "lua-resty-jwt",
                    {
                        header={typ="JWT", alg="HS256"},
                        payload={jwt="true"}
                    }
                )
	 return jwt_token
end

function jwtboolean()
    ngx.log(ngx.ERR,ngx.var.cookie_token)
    if(ngx.var.cookie_token ~= nil) then
	local jwt_obj = jwt:verify("lua-resty-jwt", ngx.var.cookie_token)
	local jwtson =jwt_obj["payload"]["jwt"]
	if(jwtson == "true") then
	   return true
	else
	   return false
	end
    end
    return false
end

if  (jwtboolean()) then
else
	ngx.log(ngx.ERR,ngx.var.cookie_token)
	if Authority(user,passwd,strjson) then
	   ngx.header["Set-Cookie"] = "token="..jwts().."; Path=/; Expires=" .. ngx.cookie_time(ngx.time() + 86400)
	   logs("success",user,passwd)
	else
	   logs("failure",user,passwd)
	   ngx.redirect("http://"..ip_utils.get_ipv4()..":8003/")  
	end
end
