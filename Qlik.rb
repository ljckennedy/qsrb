require 'securerandom'
require 'HTTPClient'
require 'json'
gem "rubyntlm", ">= 0.6.1" #I don't know for sure the minimum required, but the default is no good..
require 'rubyntlm'

#require 'tempfile'
#require './qsrb/NetHttpStream'
##
#This Class provides a wrapper to the Qlik Sense APIs.
#It is a work in progress so not all APIs or endpoints are covered
class QlikSense

  def initialize( name: nil, ignore_ssl: false, root: nil, user: nil, pass: nil, cert: nil, key:nil, log: nil)
    @servername=name
    @base_uri_qrs = "https://"+@servername+":4242"
    @base_uri_qps = "https://"+@servername
    @xrf = SecureRandom.hex(16)[0..15] #'acbdefghijklmnop'
    @extheader = {
      "X-Qlik-XrfKey" => @xrf,
      "Accept" => "application/json",
      "User-Agent" => 'Mozilla/2.0 (compatible; MSIE 1.0; Windows 95)',
      "X-Qlik-User" => "UserDirectory=Internal;UserID=sa_repository",
      "Content-Type" => "application/json"}
    certs(ignore_ssl, cert, key, root)
    @log = log
    @user = user
    @pass = pass
  end


  def certs(ignore_ssl, cert, key, root)
    #puts cert, key, root
    @cert = cert
    @key = key
    @root = root
    @ignore_ssl =ignore_ssl

  end
  private :certs

  def qsConn()
    client = HTTPClient.new()
    if !@root.nil?  then
      client.ssl_config.set_trust_ca(@root)
    end
    if !@cert.nil? then
      client.ssl_config.set_client_cert_file(@cert, @key)
    end
    if !@ignore_ssl then
      client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_PEER
    else
      client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    if !@user.nil? then
      #We need to use windows auth, so do this
      @base_uri = @base_uri_qps
      client.set_auth(nil, @user, @pass)
      path = '/qrs/about'
      query = {'xrfkey' => @xrf}
      https_url = @base_uri+path
      t = client.get(https_url, query, @extheader, :follow_redirect => true)
      #pp @user, @pass, https_url
      redirect = t.http_header.request_uri.to_s
      r = client.get(redirect, query, @extheader, :follow_redirect => true)
      #pp "CONNECTED: ", t.status_code, t.body, r.status_code, r.body, redirect
    else
      @base_uri = @base_uri_qrs
    end
    #puts @base_uri+' BASE'
    client.receive_timeout = 30000
    client.send_timeout = 30000
    client.connect_timeout = 30000
    client.keep_alive_timeout = 30000
    client.ssl_config.timeout = 30000

    return client
  end
  private :qsConn



  #Will return true if Qlik Sense is up, false if down.  Note this is the only method which will work without correct certificates.
  # def isSenseUp()
  #   conn = qsConn(@base_uri_qps)
  #   path="/qps/user"
  #   response = conn.get do |req|
  #     req.url path
  #     req.params['xrfkey'] = @xrf
  #   end
  #   if response.status == 200 then return true
  #     else return false
  #   end
  # end

  def get_generic_filter(path, fparam, fop, fval)
  # conn = qsConn()
  # path=path
  # response = conn.get do |req|
  #   req.url path
  #   if !fparam.nil?
  #     req.params['filter'] = fparam+" "+fop+" "+"'"+fval+"'"
  #   end
  #   req.params['xrfkey'] = @xrf
  #   end
  #     return response
  return get_generic_param(path, 'filter', fparam, fop, fval)
  end
  private :get_generic_filter

  def get_generic(path)
    # conn = qsConn()
    # path = path
    # response = conn.get do |req|
    #   req.url path
    #   req.params['xrfkey'] = @xrf
    # end
    # return response
    return get_generic_param(path, nil, nil, nil, nil)
  end
  private :get_generic

  def get_generic_param(path, paramName, param, op, val)
    conn = qsConn()
    if path[0] != '/' then
      path = '/'+path
    end
    https_url =@base_uri+path
    if !param.nil?
      if paramName == 'filter' then
        query = {paramName => param+" "+op+" "+"'"+val+"'" , 'xrfkey' => @xrf}
      else
        query = {paramName => param, 'xrfkey' => @xrf}
      end
    else
      query = {'xrfkey' => @xrf}
    end
    #puts https_url, query , @extheader
    #puts query
    r =  conn.get(https_url, query, @extheader)
    #pp r
  end
  private :get_generic_param

  def put_generic_param(path, paramName, param, op, val, body)
    conn = qsConn()
    if path[0] != '/' then
      path = '/'+path
    end
    https_url =@base_uri+path+'?xrfkey='+@xrf
    if !param.nil?
      if paramName == 'filter' then
        query = {paramName => param+" "+op+" "+"'"+val+"'" , 'xrfkey' => @xrf}
      else
        query = {paramName => param, 'xrfkey' => @xrf}
      end
    else
      query = {'xrfkey' => @xrf}
    end
    puts https_url, query , @extheader
    #puts query
    r =  conn.put(https_url, body, @extheader)
    #pp r
  end
  private :put_generic_param

  def delete_generic(https_url)
    conn = qsConn()
    puts conn.delete(https_url, nil, @extheader)
  end
  private :delete_generic

  def get_download(path, fname)
    conn = qsConn()
    if path[0] != '/' then
      path = '/'+path
    end
    https_url =@base_uri+path
    query = {'xrfkey' => @xrf}
    appFile = File.open(fname, "wb")
    conn.get(https_url, query, @extheader) do |chunk|
        appFile.write(chunk)
    end
    appFile.close
    return true
  end
  private :get_download

  def post_file(https_url, fFile, contentType)
    conn = qsConn()
    @extheader = {
      "X-Qlik-XrfKey" => @xrf,
      "Accept" => "application/json",
      "User-Agent" => 'Mozilla/2.0 (compatible; MSIE 1.0; Windows 95)',
      "X-Qlik-User" => "UserDirectory=Internal;UserID=sa_repository",
      "Connection" => "Keep-Alive",
      'Content-Type' => contentType}
    #puts https_url, query , @extheader
    File.open(fFile, "rb") do |file|
      #body = {  file,  }
        conn.post(https_url, file, @extheader)
        #https_url, query, @extheader
    end
  end
  private :post_file

  def post_generic(https_url, body, header)
    conn = qsConn()
    return conn.post(https_url, body, header)

  end
  private :post_generic

  def get_user(param = nil, val = nil)
    return  get_generic_filter("qrs/user", param, 'eq', val).body
  end

  def get_user_full(param = nil, val = nil)
    return  get_generic_filter("qrs/user/full", param, 'eq', val).body
  end

  # Connect to qlik sense as domainName\userName .  Will return 'about' info.
  #
  # NB:  If the user does not exist, they will be created.
  def connectAsUser(userName, domainName)
    @extheader = {
      "X-Qlik-XrfKey" => @xrf,
      "Accept" => "application/json",
      "User-Agent" => 'Mozilla/2.0 (compatible; MSIE 1.0; Windows 95)',
      "X-Qlik-User" => "UserDirectory="+domainName+";UserID="+userName,
      "Content-Type" => "application/json"}
    return get_generic('qrs/about').body
  end

  def get_dataconnection(param = nil, val = nil)
    return  get_generic_filter("qrs/dataconnection", param, 'eq', val).body
  end

  def get_app(param = nil, val = nil)
    return  get_generic_filter("qrs/app", param, 'eq', val).body
  end

  def get_stream(param = nil, val = nil)
    return  get_generic_filter("qrs/stream", param, 'eq', val).body
  end



  def get_about()
    return get_generic('qrs/about').body
  end

  def get_aboutDiscription()
    return get_generic('qrs/about/api/description').body
  end

  def get_custompropertydefinition()
    return get_generic('qrs/custompropertydefinition').body
  end

  def get_tag()
    return get_generic('qrs/tag').body
  end

  def get_task()
    return get_generic('qrs/task').body
  end

  def get_rule()
    return get_generic('qrs/systemrule').body
  end

  def get_userdirectory()
    return get_generic('qrs/userdirectory').body
  end

  def get_extension()
    return get_generic('qrs/extension').body
  end

  #Get a list of all entities, initialized with default values, of all public types.
  #Optionally, select if the objects that are referenced by the entities are to be initialized by default or set to null.
  def get_aboutDefault(section, listentries=false)
    if section == '' then
      path = 'qrs/about/api/default'
    else
      path = 'qrs/about/api/default/'+section
    end
    return get_generic_param(path, 'listentries', listentries, nil, nil).body
  end

  #Get an entity, initialized with default values, of a specific [type].
  #Optionally, select if the objects that are referenced by the entities are to be initialized by default or set to null.
  def get_type(type, listentries=false)
    if type == '' then
      path = 'qrs/about/api/default'
    else
      path = 'qrs/about/api/default/'+type
    end
    return get_generic_param(path, 'listentries', listentries, nil, nil).body
  end

  #Get a list of all references between entities.
  def get_relations()
    return get_generic('qrs/about/api/relations').body
  end

  #Get all enums that are used by the public part of the Qlik Sense Repository Service (QRS) API.
  def get_enums()
    return get_generic('qrs/about/api/enums').body
  end

  #Get the number of tokens that are allocated, used, or in quarantine.
  def get_accesstypeinfo()
    return get_generic('qrs/about/api/enums').body
  end


  def get_appState(id)
    return get_generic('qrs/app/'+id+'/state').body
  end

  def get_appExportId(id)
    return get_generic('qrs/app/'+id+'/export').body
  end

  def get_appExport(id, fname)
    t = get_appExportId(id)
    #pp t
    ticket = JSON.parse(t)['value']
    #return get_generic('qrs/download/app/'+id+'/'+ticket+'/'+fname).body
    return get_download('qrs/download/app/'+id+'/'+ticket+'/'+fname, fname)
  end



  def uploadfile(fName, fFile)
    conn = qsConn()
    # Note, can't pass query,so hand code url
    https_url =@base_uri+'/qrs/app/upload?name='+fName+'&xrfkey='+@xrf
    puts https_url
    post_file(https_url, fFile, 'application/vnd.qlik.sense.app')
  end

  def get_Appid(appName)
    appId = 0
    apps = JSON.parse(get_app())
    apps.each do |app|
      if app['name'] == appName then
        appId = app['id']
        #pp app
      end
    end
    return appId
  end




  def copyApp(app1, app2, xQlikUser=nil)
    if !xQlikUser.nil? then
    extheader = {
      "X-Qlik-XrfKey" => @xrf,
      "Accept" => "application/json",
      "User-Agent" => 'Mozilla/2.0 (compatible; MSIE 1.0; Windows 95)',
      "X-Qlik-User" => xQlikUser,
      "Connection" => "Keep-Alive",
      'Content-Type' => "text/plain",
      "Content-Length" => "0"
    }
    else
      extheader = {
        "X-Qlik-XrfKey" => @xrf,
        "Accept" => "application/json",
        "User-Agent" => 'Mozilla/2.0 (compatible; MSIE 1.0; Windows 95)',
        "X-Qlik-User" => "UserDirectory=Internal;UserID=sa_repository",
        "Connection" => "Keep-Alive",
        'Content-Type' => "text/plain",
        "Content-Length" => "0"
      }
    end
      id = get_Appid(app1)
      https_url =@base_uri+'/qrs/app/'+id+'/copy?name='+app2+'&xrfkey='+@xrf
      return post_generic(https_url, '', extheader)
  end

  #Upload a file to an app content library, identified by {id}, and store the file in accordance to the path specified in {externalpath} (for example, image.png).
  # {overwrite} is optional and set to false by default.
  # UNTESTED
  def uploadAppContent(libraryId, fFile,  contentType, overwrite='false')
    conn = qsConn()
    f= File.basename fFile
    puts libraryId, fFile,  contentType, overwrite, f

    https_url =@base_uri+'/qrs/appcontent/'+libraryId+'/uploadfile?externalpath='+f+'&overwrite='+overwrite+'&xrfkey='+@xrf
    puts https_url
    return post_file(https_url, fFile, contentType)
  end

  #Delete a file, stored as {externalpath}, from an app content library, identified by {id}.
  # UNTESTED
  def deleteAppContent(libraryId, fFile)
    conn = qsConn()
    https_url =@base_uri+'/qrs/appcontent/'+libraryId+'/deletecontent?externalpath='+fFile+'&xrfkey='+@xrf
    puts https_url
    delete_generic(https_url)
  end

  #Upload a file to a content library, identified by {libname}, and store the file in accordance to the path specified in {externalpath}
  #(for example, image.png). {overwrite} is optional and set to false by default.
  #A content library holds static content (for example, image and video files) that can be used in Qlik Sense.
  def uploadContent(libraryName, fFile,  contentType, overwrite='false')
    #conn = qsConn()
    f= File.basename fFile
    puts libraryName, fFile,  contentType, overwrite, f

    https_url =@base_uri+'/qrs/contentlibrary/'+libraryName+'/uploadfile?externalpath='+f+'&overwrite='+overwrite+'&xrfkey='+@xrf
    puts https_url
    post_file(https_url, fFile, contentType)
  end

  #Delete a file, stored as {externalpath}, from a content library, identified by {libname}.
  def deleteContent(libraryName, fFile)
    #conn = qsConn()
    https_url =@base_uri+'/qrs/contentlibrary/'+libraryName+'/deletecontent?externalpath='+fFile+'&xrfkey='+@xrf

    puts https_url
    delete_generic(https_url)
  end

  #Get information about the application content quota.
  def appcontentquota()
    return get_generic('qrs/appcontentquota/full').body
  end

  def setRole(userid, role)
    usersJson =JSON.parse(get_user_full('userid', userid))
    id= usersJson[0]["id"]
    path = '/qrs/user/'+id
    userJson=JSON.parse(get_generic(path).body)
    userJson["roles"] = [role]
    #userJson["name"] = "R_"+Time.new().to_s
    body = JSON.generate(userJson)
    return put_generic_param(path, nil, nil, nil, nil, body).body
  end

  def addRole(userid, role)
    usersJson =JSON.parse(get_user_full('userid', userid))
    id= usersJson[0]["id"]
    path = '/qrs/user/'+id
    userJson=JSON.parse(get_generic(path).body)
    userJson["roles"] = Array[role]+userJson["roles"]
    body = JSON.generate(userJson)
    return put_generic_param(path, nil, nil, nil, nil, body)
  end

  # App content quota: Get
  # App content quota: Update
  # App: Get hub information
  # App: Get hub list
  # App: Get state
  # App: Migrate
  # App: Publish
  # App: Reload
  # App: Replace
  # App: Upload app
  # App object: Get privileges
  # App object: Publish
  # App object: Unpublish
  # Cache: Invalidate
  # Certificate distribution: Export certificates
  # Certificate distribution: Export certificates path
  # Certificate distribution: Distribute certificate
  # Certificate distribution: Redistribute certificate
  # Certificate installation: Install certificate
  # Certificate installation: Setup ping
      # Data market: Get license
      # Data market: Add license
      # Data market: Update license
      # Data market: Add license bundle
      # Data market: Get terms acceptance
  # Engine service: Get local engine service
      # Extension: Get schemas
  # Extension: Upload extension
      # Extension: Create extension with schema
      # Extension: Delete extension by name
      # Extension: Create or update a file in an extension
      # Extension: Delete a file from an extension
  # License: Download LEF
  # License: Get
  # License: Add
  # License: Update
  # License rule audit: Get audit rules
  # License rule audit: Preview audit rules
  # License rule audit: Get audit rules matrix
  # License rule: Get user actions
  # Load balancing: Get valid engines
  # Notification: Add change subscription
  # Notification: Remove change subscription
  # Notification: Get changes since
      # Ping: Ping
  # Printing Service: Get local printing service
  # Proxy service: Get local proxy service
  # Reload task: Add reload task bundle
  # Reload task: Update reload task bundle
  # SAML: Metadata download (call 1 of 2)
  # SAML: Metadata download (call 2 of 2)
  # Scheduler service: Get local scheduler service
  # Security rule audit: Get accessible objects
  # Security rule audit: Get audit export
  def get_auditExport()
    return get_generic('qrs/systemrule/security/audit/export').body
  end
  # Security rule audit: Get audit rules
  # Security rule audit: Get audit preview
  # Security rule audit: Get audit rules matrix
  # Security rule audit: Get resource count
  # Security rule: Get accessible attributes
  # Security rule: Get attribute values
  # Security rule: Get referenced user roles
  # Security rule: Get parse tree
  # Security rule: Get user actions
  # Security rule: Get allowed resources
  # Server node: Activate server node
  # Server node configuration: Get server node creation container
  # Server node configuration: Add server node creation container
  # Server node configuration: Get local
  # Service registration: Start service registration
  # Service status: Get service state
      # Shared content: Delete content
      # Shared content: Upload file
      # Static content: Enumerate files
      # Synchronization: Create snapshot
      # Synchronization: Restore snapshot
      # Synchronization rule audit: Get audit rules
      # Synchronization rule audit: Preview audit rules
      # Synchronization rule audit: Get audit rules matrix
      # Synchronization rule: Get linked nodes
      # Synchronization rule: Get linked objects
      # System rule: Get associated rules
  # Task: Start
  # Task: Start asynchronous
  # Task: Start by name
  # Task: Start by name asynchronously
  # Task: Start many
  # Task: Stop
  # Task: Stop many
  # User directory: Get all default settings
  # User directory: Refresh user directory types
  # User directory: Sync user directories
  # User directory: Delete user directory and users
  # User: Owned resources
  # User: Synchronize user
end #class

class RCode
    attr_accessor :code
    @code = -999
end
