require 'spec'
require File.expand_path(File.dirname(__FILE__) + '/../lib/onelogin/saml.rb')

Dir[File.expand_path(File.dirname(__FILE__) + '/support/**/*.rb')].each { |f| require f }

Spec::Runner.configure do |config|
  FIXTURE_PATH = File.expand_path(File.dirname(__FILE__) + '/fixtures')

  def fixture_path(filename)
    "#{FIXTURE_PATH}/#{filename}"
  end

  config.before(:suite) do
    TestServer.start(ENV['TEST_SERVER_PORT'] || 2345)
  end

  config.after(:each) do
    TestServer.reset
  end

  config.after(:suite) do
    TestServer.stop
  end
end
