Gem::Specification.new do |s|
  s.name = %q{ruby-saml-mod}
  s.version = "0.1.22"

  s.authors = ["OneLogin LLC", "Bracken", "Zach", "Cody", "Jeremy", "Paul"]
  s.date = %q{2013-05-07}
  s.extra_rdoc_files = [
    "LICENSE"
  ]
  s.files = [
    "LICENSE",
    "README",
    "lib/onelogin/saml.rb",
    "lib/onelogin/saml/auth_request.rb",
    "lib/onelogin/saml/authn_contexts.rb",
    "lib/onelogin/saml/log_out_request.rb",
    "lib/onelogin/saml/logout_response.rb",
    "lib/onelogin/saml/meta_data.rb",
    "lib/onelogin/saml/name_identifiers.rb",
    "lib/onelogin/saml/response.rb",
    "lib/onelogin/saml/settings.rb",
    "lib/onelogin/saml/status_codes.rb",
    "lib/xml_sec.rb",
    "ruby-saml-mod.gemspec"
  ]
  s.add_dependency('libxml-ruby', '>= 2.3.0')
  s.add_dependency('ffi')

  s.homepage = %q{http://github.com/bracken/ruby-saml}
  s.require_paths = ["lib"]
  s.summary = %q{Ruby library for SAML service providers}
  s.description = %q{This is an early fork from https://github.com/onelogin/ruby-saml - I plan to "rebase" these changes ontop of their current version eventually. }
end
