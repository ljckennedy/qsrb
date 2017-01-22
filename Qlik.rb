require 'securerandom'
require 'HTTPClient'
require 'json'
#require 'tempfile'
#require './qsrb/NetHttpStream'
##
#This Class provides a wrapper to the Qlik Sense APIs.
#It is a work in progress so not all APIs or endpoints are covered
class QlikSense

  def initialize( name, cert, key, root, log=nil)
    @servername=name
    @base_uri_qrs = "https://"+@servername+":4242/"
    @base_uri_qps = "https://"+@servername+"/"
    @xrf = SecureRandom.hex(16)[0..15] #'acbdefghijklmnop'
    @extheader = {
      "X-Qlik-XrfKey" => @xrf,
      "Accept" => "application/json",
      "X-Qlik-User" => "UserDirectory=Internal;UserID=sa_repository",
      "Content-Type" => "application/json"}
    certs(cert, key, root)
    #qsConn()
    @log = log
  end


  def certs(cert, key, root)
    #puts cert, key, root
    @cert = cert
    @key = key
    @root = root

  end
  private :certs

  def qsConn(base_uri)
    client = HTTPClient.new()
    client.ssl_config.set_trust_ca(@root)
    client.ssl_config.set_client_cert_file(@cert, @key)
    #client.set_auth(@base_uri, 'lkennedy\qservice', 'Password15')

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
  # conn = qsConn(@base_uri_qrs)
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
    # conn = qsConn(@base_uri_qrs)
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
    conn = qsConn(@base_uri_qrs)
    https_url =@base_uri_qrs+path
    if !param.nil?
      if param == 'filter' then
        query = {paramName => param+" "+op+" "+"'"+val+"'" , 'xrfkey' => @xrf}
      else
        query = {paramName => param, 'xrfkey' => @xrf}
      end
    else
      query = {'xrfkey' => @xrf}
    end
    #puts https_url, query , @extheader
    puts
    return conn.get(https_url, query, @extheader)
  end
  private :get_generic_param

  def get_download(path, fname)
    conn = qsConn(@base_uri_qrs)
    https_url =@base_uri_qrs+path
    query = {'xrfkey' => @xrf}
    appFile = File.open(fname, "wb")
    conn.get(https_url, query, @extheader) do |chunk|
        appFile.write(chunk)
    end
    appFile.close
    return true
  end
  private :get_download

  def get_user(param = nil, val = nil)
    return  get_generic_filter("qrs/user", param, 'eq', val).body
  end

  # Connect to qlik sense as domainName\userName .  Will return 'about' info.
  #
  # NB:  If the user does not exist, they will be created.
  def connectAsUser(userName, domainName)
    @extheader = {
      "X-Qlik-XrfKey" => @xrf,
      "Accept" => "application/json",
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
    return get_generic('qrs/extension ').body
  end
  def get_aboutDefault(section, listentries=false)
    if section == '' then
      path = 'qrs/about/api/default'
    else
      path = 'qrs/about/api/default/'+section
    end
    return get_generic_param(path, 'listentries', listentries, nil, nil).body
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

end #class

class RCode
    attr_accessor :code
    @code = -999
end
