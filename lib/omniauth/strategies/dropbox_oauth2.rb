require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Dropbox < OmniAuth::Strategies::OAuth2
      option :name, "dropbox"
      option :client_options, {
        :site               => 'https://api.dropbox.com',
        :authorize_url      => 'https://www.dropbox.com/1/oauth2/authorize',
        :token_url          => 'https://api.dropbox.com/1/oauth2/token'
      }

      uid { raw_info['uid'] }

      info do
        {
          :uid   => raw_info['uid'],
          :name  => raw_info['display_name'],
          :email => raw_info['email'],
          :access_token => {
            :token      => access_token.token,
            :expires_in => access_token.expires_in,
            :expires_at => access_token.expires_at,
          },
        }
      end

      extra do
        { 
          'access_token' => access_token,
          'raw_info' => raw_info,
        }
      end

      def raw_info
        @raw_info ||= MultiJson.decode(access_token.get('/1/account/info').body)
      end

      def full_host
        uri = URI.parse(super)
        # Dropbox API requires https for non-localhost callback url
        uri.scheme = 'https' unless 'localhost'.eql?(uri.host)
        uri.to_s
      end

      def callback_url
        if @authorization_code_from_signed_request
          ''
        else
          options[:callback_url] || super
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'dropbox', 'Dropbox'
