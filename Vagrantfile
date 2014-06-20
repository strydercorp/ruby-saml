# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = 'hashicorp/precise64'
  config.vm.provision :ventriloquist do |env|
    env.platforms << %w( ruby-1.9.3 )
    env.packages << %w(
      xmlsec1
      libxmlsec1
      libxmlsec1-dev
    )
  end
end
