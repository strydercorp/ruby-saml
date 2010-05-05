require 'onelogin/saml'

class SamlController < ApplicationController
  skip_before_filter :verify_authenticity_token, :only => [:consume]  

  def index
  end
  
  def login
    settings = Account.get_saml_settings
    request = Onelogin::Saml::AuthRequest.create(settings)
    redirect_to(request)
  end

  def consume
    response = Onelogin::Saml::Response.new(params[:SAMLResponse])
    response.settings = Account.get_saml_settings

    logger.info "NAMEID: #{response.name_id}"

    if response.is_valid?
      session[:name_id] = response.name_id
      redirect_to :action => :complete
    else
      redirect_to :action => :fail
    end
  end
  
  def complete
  end
  
  def fail
  end
  
  def logout
    #todo: implement logout
    if session[:name_id]
      session[:name_id] = nil
      session[:name_qualifier] = nil
      session[:session_index] = nil
      redirect_to :action => :index
    else
      redirect_to :action => :index
    end
  end
  
  def metadata
    settings = Account.get_saml_settings
    render :xml => Onelogin::Saml::MetaData.create(settings)
  end

end
