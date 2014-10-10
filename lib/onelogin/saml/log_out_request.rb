module Onelogin::Saml
  class LogOutRequest < LogoutRequest
    def initialize(settings, session)
      super(settings, session)

      warn "Class `LogOutRequest` is deprecated. Use `LogoutRequest` instead."
    end
  end
end
