require 'spec'
require File.expand_path(File.dirname(__FILE__) + '/../lib/onelogin/saml.rb')

Spec::Runner.configure do |config|
  FIXTURE_PATH = File.expand_path(File.dirname(__FILE__) + '/fixtures')

  def fixture_path(filename)
    "#{FIXTURE_PATH}/#{filename}"
  end
end
