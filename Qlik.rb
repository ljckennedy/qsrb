require 'securerandom'
require 'faraday'
require 'faraday/detailed_logger'
require 'json'

class QlikSense

  def initialize( name, cert, key, root, log=nil)
    @servername=name
    @base_uri_qrs = "https://"+@servername+":4242/"
    @base_uri_qps = "https://"+@servername+"/"
    @xrf = SecureRandom.hex(16)[0..15] #'acbdefghijklmnop'
    #headers()
    certs(cert, key, root)
    #qsConn()
    @log = log
  end

  def servername()
    @servername
  end

  def certs(cert, key, root)
    #puts cert, key, root
    cert = OpenSSL::X509::Certificate.new(File.read(cert))
    key = OpenSSL::PKey::RSA.new(File.read(key))
    #root = root
    @ssl_options = {
    :client_cert => cert,
    :client_key  => key,
    :ca_file     => root,
    :verify      => OpenSSL::SSL::VERIFY_PEER
    }
  end

  def qsConn(base_uri)
    return  Faraday.new(base_uri, ssl: @ssl_options) do |faraday|
      faraday.request  :url_encoded
      if @log == 'debug'
        faraday.response :detailed_logger
      elsif @log == 'log'
        faraday.response :logger
      end
      #faraday.basic_auth("https://"+"@servername", 'lkennedy\qservice', 'xxxxx')
      faraday.headers[:"X-Qlik-XrfKey"] = @xrf
      faraday.headers[:Accept] = "application/json"
      faraday.headers[:"X-Qlik-User"] = "UserDirectory=Internal;UserID=sa_repository"
      faraday.headers[:"Content-Type"] = "application/json"
      #faraday.adapter  Faraday.default_adapter
      faraday.use  Faraday::Adapter::HTTPClient
    end
  end

  def connectAsUser(userName, domainName)
    conn = qsConn(@base_uri_qrs)
    conn.headers[:"X-Qlik-User"] = "UserDirectory="+domainName+";UserID="+userName
    path = 'qrs/about'
    response = conn.get do |req|
      req.url path
      req.params['xrfkey'] = @xrf
    end
    return response.body
  end

  def isSenseUp()
    conn = qsConn(@base_uri_qps)
    path="/qps/user"
    response = conn.get do |req|
      req.url path
      req.params['xrfkey'] = @xrf
    end
    if response.status == 200 then return true
      else return false
    end
  end

  def get_generic_filter(path, fparam, fop, fval)
  conn = qsConn(@base_uri_qrs)
  path=path
  response = conn.get do |req|
    req.url path
    if !fparam.nil?
      req.params['filter'] = fparam+" "+fop+" "+"'"+fval+"'"
    end
    req.params['xrfkey'] = @xrf
    end
      return response
  end
  private :get_generic_filter

  def get_user(param = nil, val = nil)
    return  get_generic_filter("qrs/user", param, 'eq', val).body
  end

  def get_dataconnection(param = nil, val = nil)
    return  get_generic_filter("qrs/dataconnection", param, 'eq', val).body
  end

  def get_app(param = nil, val = nil)
    return  get_generic_filter("qrs/app", param, 'eq', val).body
  end

  def get_generic(path)
    conn = qsConn(@base_uri_qrs)
    path = path
    response = conn.get do |req|
      req.url path
      req.params['xrfkey'] = @xrf
    end
    return response
  end
  private :get_generic

  def get_about()
    # conn = qsConn(@base_uri_qrs)
    # path = 'qrs/about'
    # response = conn.get do |req|
    #   req.url path
    #   req.params['xrfkey'] = @xrf
    # end
    return get_generic('qrs/about').body
  end

  def get_aboutDiscription()
    # conn = qsConn(@base_uri_qrs)
    # path = 'qrs/about/api/description'
    # response = conn.get do |req|
    #   req.url path
    #   req.params['xrfkey'] = @xrf
    # end
    return get_generic('qrs/about/api/description').body
  end

  def get_aboutDefault(section, listentries=false)
    conn = qsConn(@base_uri_qrs)
    if section == '' then path = 'qrs/about/api/default'
    else path = 'qrs/about/api/default'+'/'+section
    end
    response = conn.get do |req|
      req.url path
      req.params['xrfkey'] = @xrf
      req.params['listentries'] = listentries
    end
    return response.body
  end


  # def get_servicestate()
  #   conn = qsConn(@base_uri_qrs)
  #   path = 'qrs/servicestate'
  #   response = conn.get do |req|
  #     req.url path
  #     req.params['xrfkey'] = @xrf
  #   end
  #   puts "\n", response.body
  #   if response.body == 0 then
  #     print ('Initializing')
  #   elsif response.body == 1
  #     print ('Certificates not installed')
  #   else
  #     print ('Running')
  #   end
  # end
  def get_appState(id)
    conn = qsConn(@base_uri_qrs)
    path = '/qrs/app/'+id+'/state'
    response = conn.get do |req|
      req.url path
      req.params['xrfkey'] = @xrf
    end
    return response.body
  end

  def get_appExportId(id)
      conn = qsConn(@base_uri_qrs)
      path = '/qrs/app/'+id+'/export'
      response = conn.get do |req|
        req.url path
        req.params['xrfkey'] = @xrf
      end
    return response.body
  end

  def get_appExport(id, fname)
    ticket = JSON.parse(get_appExportId(id))['value']
    puts ticket
    conn = qsConn(@base_uri_qrs)
    path = '/qrs/download/app/'+id+'/'+ticket+'/'+fname
    response = conn.get do |req|
      req.url path
      req.params['xrfkey'] = @xrf
    end
    return response.body
  end

end #class

class RCode
    attr_accessor :code
    @code = -999
end
