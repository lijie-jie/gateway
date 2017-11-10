local cjson = require "cjson"  
local json = cjson.new()  
local http = require "resty.http"
local httpc = http.new()
local ip_utils = require "lua_ip"
local aes = require "resty.aes"

local action,path,user,ip,uri,result,url,base64user,users,headers,permissions,file,file1,str,strjson,jsonStr,numbers,requesturl,encryption,iv,keys,aes_128_cbc_with_iv,a2
--日志动作、请求路径、用户名、请求地址、请求操作、返回结果、请求链接、base用户名密码、解密用户名密码、请求头、权限校验、加密io流、权限io流、权限json、转换json、发送admin的json、判断是否成功、请求日志url、输出加密串、加密iv、加密key、解密串、解密信息
local res = {} --用于装去重后的权限
local flags = {} --去重数组
local b ={} --用于匹配权限的table
local retTable = {};    --最终拼接log的json
local intDatas = {};    --单条log日志
requesturl=ngx.var.requesturl
numbers=0 --初始为正确
--获取请求头取出basic用户名密码
headers = ngx.req.get_headers()
base64user = headers["authorization"]
    if (base64user == nil) then
       ngx.say("您的用户名密码为空")
       numbers=1
    else
    users=ngx.decode_base64(string.sub(base64user,7,string.len(base64user)))
    end

function replaces(bases)
      bases = string.gsub(bases, ":", "+")
      bases = string.gsub(bases, ";", "/")
      bases = string.gsub(bases, "_", "=")
      return bases
end

url = ngx.var.request_uri --获取请求并解析

file = io.open("/usr/local/gateway/nginx/key.txt", "r")
encryption = string.gsub(file:read("*a"), "\n", "")
file:close()
iv = encryption
keys = encryption
aes_128_cbc_with_iv = assert(aes:new(keys, nil, aes.cipher(128, "cbc"), {iv=iv, method=nil}))
local _ , _ , a1 = string.find(url,"?_=".."(.-)".."$")
a2 = aes_128_cbc_with_iv:decrypt(ngx.decode_base64(replaces(a1)))

local _ , _ , txt = string.find(a2,'/webhdfs/v1'.."(.-)"..'?')
if (numbers==0) then --账号密码为空时
   local _ , _ , txt1 = string.find(users,'^'.."(.-)"..':')
   user = txt1 --用户填入
else
   user = "账号密码为空"
end
local _ , _ , txt2 = string.find(a2,'op='.."(.-)"..'$')


uri = "op="..txt2 --操作填入

if string.match(txt2, "&") then
    _ , _ , txt2 = string.find(txt2,'^'.."(.-)"..'&')
end
permissions = txt..":"..txt2 --拼接路径与权限
--读取本地文件转换json
file1 = io.open("/usr/local/gateway/nginx/rule.txt", "r") --打开io流
str = file1:read("*a") --用io流读取文件全部内容
file1:close()
strjson = json.decode(str) --转换从文本中取得的json

path = txt --路径填入
ip = ngx.var.remote_addr --请求ip填入

--日志方法
function logs(actions,results)
    retTable["action"] = actions ;
    retTable["path"] = path ;
    retTable["pluginIp"] = ip_utils.get_ipv4();
    retTable["clientType"] =  "gateway";
    retTable["user"] = user ;
    retTable["clientIPAddress"] = ip ;
    retTable["accessType"] = uri ;
    retTable["isAllowed"] = results ;
    retTable["accessTime"] = os.date("%Y-%m-%d %H:%M:%S");

    jsonStr = cjson.encode(retTable);
    local res, err = httpc:request_uri("http://"..requesturl..":8085/api/audits", {
                method = "POST",
                body = jsonStr,
                headers = {
                ["Content-Type"] = "application/json",
                      }
                })
end

logs("access","success") --访问成功


--进行用户认证
function fors3(var1,var2,var3)
  for userkeyid,userkey in pairs(var1) do
    --ngx.say("rolekeyid")
    if(type(userkey)=="table") then
      for userkeys,role in pairs(userkey) do
          if(userkeys==var3) then
              --ngx.say("用户认证成功")
              --ngx.say("key:  ",userkey)
              if(type(role)=="table") then
              for rolekeyid,rolekey in pairs(role) do
                --ngx.say("rolekeyid")
                if(type(rolekey)=="table") then
                   for rolekeys,permission in pairs(rolekey) do
                      --ngx.say("rolekeys")
                      if(type(permission)=="table") then
                         for perkeyid,perkey in pairs(permission) do
                              --ngx.say("perkeyid")
                          if(type(perkey)=="table") then
                              for perkeys,path in pairs(perkey) do
                                 --ngx.say("perkeys"..perkeys)
                                 if(type(path)=="table") then
				      for pathkey,pathval in pairs(path) do
                                        --ngx.say("pathkey"..pathkey)
                                            if(type(pathval)=="table") then
                                               for opkeyid,opkey in pairs(pathval) do
                                                  --ngx.say("opkeyid")
                                                  table.insert( var2, pathkey..":"..opkey)
                                               end
                                            else
                                             --ngx.say("val:  ",pathval)
                                            end
                                      end
                                 else
                                  --ngx.say("val:  ",path)
                                 end
                              end
                          else
                          --ngx.say("val:  ",perkey)
                          end
                         end
                      else
                      --ngx.say("val:  ",permission)
                      end
                    end
                else
                --ngx.say("val:  ",rolekey)
                end
              end
              else
              --ngx.say("val:  ",role)
              end
                  return true
          end
      end
      
      else
      --ngx.say("val:  ",var1)
      end
    end
    ngx.say("账号密码错误")
    ngx.exit(0)
    return false
end

--打印权限table
--for tablek,tablev in pairs(b) do
--	if  (tablek==nil) then
--	ngx.say("为空")
--	else
--	ngx.say("tablev: ",tablev)
--	ngx.say("tablev: ",tablev)
--	end
--end

--替换所有特殊符号
local function lregQuote(s)
    s = (string.gsub(s, '[%-%.%+%[%]%(%)%$%^%%%?%*]','%%%1'))
    return s
end

function ResourceMatcher(s, pattern)
      if pattern == s then
      return true
      end
          pattern = lregQuote(pattern)
          pattern = string.gsub(pattern, '%%%*', '.*')
          
      local i, j = string.find(s, pattern)
      if i == 1 and j == string.len(s) then
      return true
      end
      return false
end

function Authority(var1,var2,var3)

      for  i=1,table.getn(var1)  do
      if not flags[var1[i]] then
            table.insert(var2,var1[i])
            flags[var1[i]] = true
         end
      end
      --进行验证的方法
      function verification(res)
         for k,v in pairs(res) do
         local _ , _ , txts1 = string.find(var3,'^'.."(.-)"..':')
         local _ , _ , txts2 = string.find(v,'^'.."(.-)"..':')
         local _ , _ , txts3 = string.find(var3,':'.."(.-)"..'$')
         local _ , _ , txts4 = string.find(v,':'.."(.-)"..'$')
             if ResourceMatcher(txts1,txts2) then
              	if(txts3==txts4) then
              	  return true
              	end
             end
         end
         return false
      end

      if verification(var2) then
         logs("authorization","success") --授权成功
	 ngx.var.query_url=a2
      else
         ngx.say("权限验证失败")
         logs("authorization","failure") --授权失败
	 ngx.var.query_url=""
	 ngx.exit(0)
      end

end

if(numbers==0)then
    --调用认证方法
    if fors3(strjson,b,users) then
        logs("authentication","success") --认证成功
    --调用授权方法
        Authority(b,res,permissions)
    else
        logs("authentication","failure") --认证失败
	ngx.var.query_url=""
	ngx.exit(0)
    end
else
    logs("authentication","failure") --认证失败
    ngx.var.query_url=""
    ngx.exit(0)
end


