#!/usr/bin/env ruby
require 'rexml/document'
require 'onelogin/saml'

files = []
settings_map = {}
i = 0
while i < ARGV.size do
  if ARGV[i].start_with? '--'
    settings_map[ARGV[i][2..-1].to_sym] = ARGV[i + 1]
    i += 2
  else
    files << ARGV[i]
    i += 1
  end  
end

if files.empty?
  puts "usage: test.rb base64-assertion [base64-assertion...] [--idp_cert_fingerprint *|XXX...] [--xmlsec_certificate path] [--xmlsec_privatekey path]"
  exit 1
end

settings = Onelogin::Saml::Settings.new(settings_map)

files.each do |filename|
  base64 = File.read(filename)
  response = Onelogin::Saml::Response.new(base64, settings)
  puts "file: #{filename}\tvalid: #{response.is_valid?}\tstatus_code: #{response.status_code} fingerprint_from_idp: #{response.fingerprint_from_idp}"
end
