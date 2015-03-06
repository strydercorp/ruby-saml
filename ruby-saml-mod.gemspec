# coding: utf-8

Gem::Specification.new do |s|
  s.name = %q{ruby-saml-mod}
  s.version = "0.2.4"
  s.authors = ["OneLogin LLC", "Bracken", "Zach", "Cody", "Jeremy", "Paul", "Nick"]
  s.summary = %q{Ruby library for SAML service providers}
  s.homepage = %q{http://github.com/instructure/ruby-saml}
  s.description = %q{This is an early fork from https://github.com/onelogin/ruby-saml - I plan to "rebase" these changes ontop of their current version eventually. }
  s.date = Time.now.strftime("%Y-%m-%d")

  s.files = Dir.glob("{lib,spec}/**/*")
  s.test_files = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = ["lib"]

  s.add_dependency('libxml-ruby', '>= 2.3.0')
  s.add_dependency('ffi')

  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec', '2.14.1'
end
